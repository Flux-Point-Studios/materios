//! Settlement requests carry at least `MinSettlementBond` of MATRA, held under
//! the `settbond` named reserve. The upgrade that enacts this runtime moves a
//! version-3 chain's outstanding anonymous bonds there, and leaves preprod's
//! spec-239 settlement state, which holds none, unchanged but for its storage
//! version.
//!
//! The reserve id is spelled out here rather than taken from the pallet, so the
//! identifier operators and indexers see is pinned independently.

use crate::*;
use frame_support::{
    assert_ok,
    traits::{BuildGenesisConfig, NamedReservableCurrency, ReservableCurrency},
};
use pallet_intent_settlement::{
    types::{SettlementEvidence, SettlementRequestRecord},
    BondedClaimAttestedAt, BondedClaimRequester, ClaimSettlementRequests, SettlementStorageVersion,
};
use parity_scale_codec::Decode;
use sp_io::{hashing::twox_128, TestExternalities};
use sp_keyring::Sr25519Keyring::{Dave, Eve, Ferdie};
use sp_runtime::BuildStorage;

const SETTLEMENT_RESERVE: [u8; 8] = *b"settbond";
const CURRENT_VERSION: u32 = 4;

/// Every key under the settlement pallet's prefix, with its value.
fn settlement_storage() -> Vec<(Vec<u8>, Vec<u8>)> {
    let prefix = twox_128(b"IntentSettlement");
    let mut entries = Vec::new();
    let mut cursor = prefix.to_vec();
    while let Some(key) = sp_io::storage::next_key(&cursor) {
        if !key.starts_with(&prefix) {
            break;
        }
        let value = sp_io::storage::get(&key).expect("a listed key holds a value");
        entries.push((key.clone(), value.to_vec()));
        cursor = key;
    }
    entries
}

fn version_key() -> Vec<u8> {
    SettlementStorageVersion::<Runtime>::hashed_key().to_vec()
}

fn settlement_events() -> Vec<pallet_intent_settlement::Event<Runtime>> {
    System::events()
        .into_iter()
        .filter_map(|record| match record.event {
            RuntimeEvent::IntentSettlement(event) => Some(event),
            _ => None,
        })
        .collect()
}

fn chain(balances: Vec<(AccountId, Balance)>) -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("system genesis builds");
    pallet_balances::GenesisConfig::<Runtime> { balances }
        .assimilate_storage(&mut storage)
        .expect("balances genesis builds");
    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

#[test]
fn the_minimum_settlement_bond_is_one_thousand_matra_as_the_attestor_bond_is() {
    assert_eq!(MATRA_DECIMALS, 6);
    assert_eq!(
        IntentSettlementMinSettlementBond::get(),
        1_000 * 10u128.pow(MATRA_DECIMALS)
    );
    chain(Vec::new()).execute_with(|| {
        let published = pallet_intent_settlement::Pallet::<Runtime>::pallet_constants_metadata()
            .into_iter()
            .find(|constant| constant.name == "MinSettlementBond")
            .expect("the pallet publishes its minimum bond")
            .value;
        assert_eq!(
            u128::decode(&mut &published[..]).expect("a u128"),
            IntentSettlementMinSettlementBond::get()
        );
        pallet_orinq_receipts::GenesisConfig::<Runtime>::default().build();
        assert_eq!(
            pallet_orinq_receipts::BondRequirement::<Runtime>::get(),
            IntentSettlementMinSettlementBond::get()
        );
    });
}

/// A chain this runtime's genesis builds starts settlement at its current
/// storage version, so an upgrade migrates nothing.
#[test]
fn an_upgrade_leaves_a_fresh_genesis_settlement_state_unchanged() {
    chain(Vec::new()).execute_with(|| {
        pallet_intent_settlement::GenesisConfig::<Runtime>::default().build();
        assert_eq!(SettlementStorageVersion::<Runtime>::get(), CURRENT_VERSION);
        let before = settlement_storage();

        Executive::execute_on_runtime_upgrade();

        assert_eq!(settlement_storage(), before);
        assert!(settlement_events().is_empty());
    });
}

/// Preprod's settlement state at a finalized spec-239 block, read from a
/// node: storage version 3, no pending or attested bond.
fn preprod_settlement_state() -> (BlockNumber, Vec<(Vec<u8>, Vec<u8>)>) {
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("preprod-settlement-2332901.json"))
            .expect("the snapshot is JSON");
    let hex = |field: &serde_json::Value| {
        sp_core::bytes::from_hex(field.as_str().expect("a hex string")).expect("valid hex")
    };
    let entries = snapshot["entries"]
        .as_array()
        .expect("snapshot entries")
        .iter()
        .map(|entry| (hex(&entry["key"]), hex(&entry["value"])))
        .collect();
    let block = snapshot["block_number"].as_u64().expect("a block number");
    (block as BlockNumber, entries)
}

#[test]
fn upgrading_preprods_settlement_state_changes_only_its_storage_version() {
    let (block, entries) = preprod_settlement_state();
    chain(Vec::new()).execute_with(|| {
        System::set_block_number(block + 1);
        for (key, value) in &entries {
            sp_io::storage::set(key, value);
        }
        let before = settlement_storage();
        assert_eq!(before, {
            let mut sorted = entries.clone();
            sorted.sort();
            sorted
        });
        assert_eq!(SettlementStorageVersion::<Runtime>::get(), 3);
        assert_eq!(ClaimSettlementRequests::<Runtime>::iter().count(), 0);
        assert_eq!(BondedClaimRequester::<Runtime>::iter().count(), 0);

        Executive::execute_on_runtime_upgrade();

        let expected: Vec<_> = before
            .into_iter()
            .map(|(key, value)| {
                if key == version_key() {
                    (key, CURRENT_VERSION.to_le_bytes().to_vec())
                } else {
                    (key, value)
                }
            })
            .collect();
        assert_eq!(settlement_storage(), expected);
        assert!(settlement_events().is_empty());
    });
}

/// The settlement pallet's pre- and post-upgrade checks pass over preprod's
/// state: it decodes, its cutovers and audit flags hold, and every
/// requester's bonds fit their settlement reserve. Every other pallet stands
/// at its in-code storage version, as genesis leaves it.
#[cfg(feature = "try-runtime")]
#[test]
fn preprods_settlement_state_passes_the_upgrade_checks() {
    use frame_support::traits::OnGenesis;
    let (block, entries) = preprod_settlement_state();
    chain(Vec::new()).execute_with(|| {
        AllPalletsWithSystem::on_genesis();
        System::set_block_number(block + 1);
        for (key, value) in &entries {
            sp_io::storage::set(key, value);
        }
        Executive::try_runtime_upgrade(frame_try_runtime::UpgradeCheckSelect::PreAndPost)
            .expect("every pre- and post-upgrade check passes");
        assert_eq!(SettlementStorageVersion::<Runtime>::get(), CURRENT_VERSION);
    });
}

fn evidence(tag: u8) -> SettlementEvidence {
    SettlementEvidence {
        cardano_tx_hash: [tag; 32],
        observed_at_depth: IntentSettlementMinFinalityDepth::get(),
        observed_slot: 1,
        beneficiary_addr_hash: [2; 28],
        amount_lovelace: 1,
        mainchain_genesis_hash: IntentSettlementMainchainGenesisHash::get(),
    }
}

/// A version-3 chain held bonds in the anonymous reserve, beside whatever
/// else the account reserved there, such as an attestor bond. The upgrade
/// moves exactly the settlement bonds, pending and attested, under the
/// settlement reserve: the account's free and reserved balances, its MOTRA
/// holding checkpoint and the issuance stay as they were, and every bond
/// later comes back out of the settlement reserve, leaving the attestor bond.
#[test]
fn upgrading_from_version_3_moves_outstanding_bonds_into_the_settlement_reserve() {
    let keeper = Dave.to_account_id();
    let unbonded = Eve.to_account_id();
    let caller = Ferdie.to_account_id();
    let attestor_bond = 1_000 * MATRA;
    let pending_bond = 2_000 * MATRA;
    let attested_bond = 1_500 * MATRA;
    let funded = 10_000 * MATRA;
    let pending = H256::repeat_byte(9);
    let attested = H256::repeat_byte(10);
    let legacy = H256::repeat_byte(11);
    chain(vec![
        (keeper.clone(), funded),
        (unbonded.clone(), funded),
        (caller.clone(), funded),
    ])
    .execute_with(|| {
        System::set_block_number(5);
        SettlementStorageVersion::<Runtime>::put(3);
        for bond in [attestor_bond, pending_bond, attested_bond] {
            assert_ok!(Balances::reserve(&keeper, bond));
        }
        let request =
            |requester: &AccountId, tag: u8, bond_amount: Balance| SettlementRequestRecord {
                requester: requester.clone(),
                evidence: evidence(tag),
                settled_direct: false,
                submitted_block: 5,
                bond_amount,
            };
        ClaimSettlementRequests::<Runtime>::insert(pending, request(&keeper, 1, pending_bond));
        ClaimSettlementRequests::<Runtime>::insert(legacy, request(&unbonded, 2, 0));
        BondedClaimAttestedAt::<Runtime>::insert(attested, 4);
        BondedClaimRequester::<Runtime>::insert(attested, (keeper.clone(), attested_bond));
        System::set_block_number(10);
        let free = Balances::free_balance(&keeper);
        let checkpoint = pallet_motra::AccrualCheckpoint::<Runtime>::get(&keeper);
        let issuance = Balances::total_issuance();
        let requests: Vec<_> = ClaimSettlementRequests::<Runtime>::iter().collect();

        Executive::execute_on_runtime_upgrade();

        assert_eq!(SettlementStorageVersion::<Runtime>::get(), CURRENT_VERSION);
        assert_eq!(
            Balances::reserved_balance_named(&SETTLEMENT_RESERVE, &keeper),
            pending_bond + attested_bond
        );
        assert_eq!(
            Balances::reserved_balance(&keeper),
            attestor_bond + pending_bond + attested_bond
        );
        assert_eq!(Balances::free_balance(&keeper), free);
        assert_eq!(
            pallet_motra::AccrualCheckpoint::<Runtime>::get(&keeper),
            checkpoint
        );
        assert_eq!(Balances::reserved_balance(&unbonded), 0);
        assert_eq!(Balances::total_issuance(), issuance);
        assert_eq!(
            ClaimSettlementRequests::<Runtime>::iter().collect::<Vec<_>>(),
            requests
        );
        assert!(settlement_events().is_empty());

        System::set_block_number(5 + IntentSettlementSettlementRequestTtl::get() + 1);
        for claim in [pending, attested] {
            assert_ok!(IntentSettlement::release_settlement_bond(
                RuntimeOrigin::signed(caller.clone()),
                claim
            ));
        }
        assert_eq!(
            Balances::reserved_balance_named(&SETTLEMENT_RESERVE, &keeper),
            0
        );
        assert_eq!(Balances::reserved_balance(&keeper), attestor_bond);
        assert_eq!(Balances::free_balance(&keeper), funded - attestor_bond);
        assert_eq!(Balances::total_issuance(), issuance);
    });
}
