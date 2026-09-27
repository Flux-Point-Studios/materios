//! The perp engine is out of the runtime, and `RemovePerpEngine` leaves no
//! trace of it in state: every keeper bond it reserved is released, its margin
//! pot is swept into the treasury, and every key under its prefix is deleted.
//!
//! Keys are built here by hand from the pallet's declared layout rather than
//! through the migration's own storage alias, so a hasher or layout mistake in
//! the migration cannot hide behind a test that shares it.

use crate::*;

use frame_support::traits::{OnRuntimeUpgrade, ReservableCurrency};
use parity_scale_codec::Encode;
use sp_io::{
    hashing::{blake2_128, twox_128},
    TestExternalities,
};
use sp_keyring::Sr25519Keyring::{Alice, Bob, Charlie, Dave};
use sp_runtime::{traits::AccountIdConversion, BuildStorage, StateVersion};

use crate::migrations::{
    db_weight as db, perp_engine_key_count, RemovePerpEngine, PERP_ENGINE_KEYS_PER_UPGRADE,
};

const FUND: Balance = 1_000_000_000_000;
const BOND: Balance = 100 * 100_000_000;
const UNRELATED_RESERVE: Balance = 2_000_000;
const POT_BALANCE: Balance = 1_979_999_997;

fn acct(k: sp_keyring::Sr25519Keyring) -> AccountId {
    k.to_account_id()
}

fn perp_pot() -> AccountId {
    PalletId(*b"perp/v0w").into_account_truncating()
}

fn treasury() -> AccountId {
    TreasuryPalletId::get().into_account_truncating()
}

fn prefix() -> [u8; 16] {
    twox_128(b"PerpEngine")
}

fn item_key(item: &[u8], suffix: &[u8]) -> Vec<u8> {
    [&prefix()[..], &twox_128(item)[..], suffix].concat()
}

fn blake2_128_concat(encoded: &[u8]) -> Vec<u8> {
    [&blake2_128(encoded)[..], encoded].concat()
}

fn market() -> Vec<u8> {
    b"ADA-PERP/USD".to_vec().encode()
}

fn keeper_bond_key(keeper: &AccountId) -> Vec<u8> {
    let suffix = [
        blake2_128_concat(&market()),
        blake2_128_concat(&keeper.encode()),
    ]
    .concat();
    item_key(b"ReservedKeeperBonds", &suffix)
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (acct(Alice), FUND),
            (acct(Bob), FUND),
            (acct(Charlie), FUND),
            (acct(Dave), FUND),
            (perp_pot(), POT_BALANCE),
            (treasury(), ExistentialDeposit::get()),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");
    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| frame_system::Pallet::<Runtime>::set_block_number(1));
    ext
}

/// Mirrors live preprod: bonded keepers (one also holding an unrelated
/// reserve), a keeper whose bond was slashed to a zero entry, open positions,
/// margin accounts and every per-market item the pallet ever wrote.
fn seed_perp_engine_state() -> usize {
    let bonded = [acct(Alice), acct(Bob), acct(Charlie)];
    for keeper in &bonded {
        Balances::reserve(keeper, BOND).expect("keeper can reserve its bond");
        sp_io::storage::set(&keeper_bond_key(keeper), &BOND.encode());
    }
    Balances::reserve(&acct(Charlie), UNRELATED_RESERVE).expect("unrelated reserve");
    let slashed = acct(Dave);
    sp_io::storage::set(&keeper_bond_key(&slashed), &0u128.encode());

    let alice = blake2_128_concat(&acct(Alice).encode());
    let bob = blake2_128_concat(&acct(Bob).encode());
    let m = blake2_128_concat(&market());
    let raw: Vec<Vec<u8>> = vec![
        item_key(b"Markets", &m),
        item_key(b"Positions", &[m.clone(), alice.clone()].concat()),
        item_key(b"Positions", &[m.clone(), bob.clone()].concat()),
        item_key(b"MarginAccounts", &alice),
        item_key(b"MarginAccounts", &bob),
        item_key(b"MarkPriceCacheMap", &m),
        item_key(b"CumulativeFundingIndex", &m),
        item_key(
            b"PremiumIndexSamples",
            &[m.clone(), blake2_128_concat(&7u32.encode())].concat(),
        ),
        item_key(b"LastSettledFundingEpoch", &m),
        item_key(b"BadDebtAccumulated", &m),
        item_key(b"BadDebtWindowStart", &m),
        [&prefix()[..], &twox_128(b":__STORAGE_VERSION__:")[..]].concat(),
    ];
    for key in &raw {
        sp_io::storage::set(key, &[1u8; 24]);
    }
    raw.len() + bonded.len() + 1
}

#[test]
fn metadata_carries_no_perp_engine() {
    for version in [14u32, 15] {
        let metadata = Runtime::metadata_at_version(version)
            .unwrap_or_else(|| panic!("metadata v{version} is served"));
        for needle in [&b"PerpEngine"[..], &b"perp_engine"[..]] {
            assert!(
                !metadata.windows(needle.len()).any(|w| w == needle),
                "metadata v{version} still mentions {}",
                core::str::from_utf8(needle).unwrap_or("?"),
            );
        }
    }
}

#[test]
fn pallet_indices_are_pinned_and_23_stays_vacant() {
    let indices: Vec<(&str, u8)> = Runtime::metadata_ir()
        .pallets
        .iter()
        .map(|p| (p.name, p.index))
        .collect();
    assert_eq!(
        indices,
        vec![
            ("System", 0),
            ("Timestamp", 1),
            ("Aura", 2),
            ("Grandpa", 3),
            ("Balances", 4),
            ("Sudo", 6),
            ("Multisig", 7),
            ("Utility", 8),
            ("Treasury", 9),
            ("Vesting", 10),
            ("OrinqReceipts", 11),
            ("Motra", 12),
            ("Sidechain", 13),
            ("SessionCommitteeManagement", 14),
            ("BlockRewards", 15),
            ("PalletSession", 16),
            ("Session", 17),
            ("NativeTokenManagement", 18),
            ("IntentSettlement", 19),
            ("TeeAttestation", 20),
            ("Billing", 21),
            ("Oracle", 22),
            ("Recovery", 24),
        ],
    );
}

fn sentinel_key() -> Vec<u8> {
    [&twox_128(b"Oracle")[..], &twox_128(b"Prices")[..], b"k"].concat()
}

/// Seeds the perp-engine state and commits it, so the migration meets the
/// keys in the backend as it would on chain and its weight counts them.
fn new_seeded_ext() -> (TestExternalities, usize) {
    let mut ext = new_test_ext();
    let seeded = ext.execute_with(|| {
        sp_io::storage::set(&sentinel_key(), b"untouched");
        seed_perp_engine_state()
    });
    ext.commit_all().expect("seed reaches the backend");
    (ext, seeded)
}

#[test]
fn removal_releases_bonds_sweeps_the_pot_and_clears_every_key() {
    let (mut ext, seeded) = new_seeded_ext();
    ext.execute_with(|| {
        assert_eq!(perp_engine_key_count() as usize, seeded);
        let issuance = Balances::total_issuance();

        let weight = RemovePerpEngine::on_runtime_upgrade();

        assert_eq!(perp_engine_key_count(), 0);
        for keeper in [acct(Alice), acct(Bob)] {
            assert_eq!(Balances::reserved_balance(&keeper), 0);
            assert_eq!(Balances::free_balance(&keeper), FUND);
        }
        assert_eq!(
            Balances::reserved_balance(&acct(Charlie)),
            UNRELATED_RESERVE
        );
        assert_eq!(
            Balances::free_balance(&acct(Charlie)),
            FUND - UNRELATED_RESERVE
        );
        assert_eq!(Balances::free_balance(&acct(Dave)), FUND);
        assert_eq!(Balances::free_balance(&perp_pot()), 0);
        assert!(!frame_system::Account::<Runtime>::contains_key(perp_pot()));
        assert_eq!(
            Balances::free_balance(&treasury()),
            ExistentialDeposit::get() + POT_BALANCE,
        );
        assert_eq!(Balances::total_issuance(), issuance);
        assert_eq!(
            sp_io::storage::get(&sentinel_key()).as_deref(),
            Some(&b"untouched"[..])
        );
        assert!(weight.all_gte(db().reads_writes(seeded as u64, seeded as u64)));
    });
}

#[test]
fn the_runtime_upgrade_path_runs_the_removal() {
    let (mut ext, _) = new_seeded_ext();
    ext.execute_with(|| {
        Executive::execute_on_runtime_upgrade();
        assert_eq!(perp_engine_key_count(), 0);
        assert_eq!(Balances::reserved_balance(&acct(Alice)), 0);
        assert_eq!(Balances::free_balance(&perp_pot()), 0);
    });
}

#[test]
fn removal_is_idempotent() {
    let (mut ext, _) = new_seeded_ext();
    ext.execute_with(|| {
        RemovePerpEngine::on_runtime_upgrade();
        let root = sp_io::storage::root(StateVersion::V1);

        let weight = RemovePerpEngine::on_runtime_upgrade();

        assert_eq!(sp_io::storage::root(StateVersion::V1), root);
        assert_eq!(weight, db().reads(1));
        assert_eq!(
            Balances::reserved_balance(&acct(Charlie)),
            UNRELATED_RESERVE
        );
    });
}

#[test]
fn removal_deletes_at_most_the_bound_per_upgrade_and_finishes_on_the_next() {
    let overflow = 5u32;
    let mut ext = new_test_ext();
    ext.execute_with(|| {
        for i in 0..PERP_ENGINE_KEYS_PER_UPGRADE + overflow {
            sp_io::storage::set(&item_key(b"MarginAccounts", &i.encode()), &[0u8; 8]);
        }
    });
    ext.commit_all().expect("seed reaches the backend");

    ext.execute_with(|| {
        RemovePerpEngine::on_runtime_upgrade();
        assert_eq!(perp_engine_key_count(), overflow);
    });
    ext.commit_all().expect("first run reaches the backend");

    ext.execute_with(|| {
        RemovePerpEngine::on_runtime_upgrade();
        assert_eq!(perp_engine_key_count(), 0);
    });
}

#[test]
fn a_run_at_the_bound_fits_in_one_block() {
    let mut ext = new_test_ext();
    ext.execute_with(|| {
        for i in 0..PERP_ENGINE_KEYS_PER_UPGRADE {
            let keeper = AccountId::from([(i % 251) as u8 + 1; 32]);
            let suffix = [
                blake2_128_concat(&i.encode().encode()),
                blake2_128_concat(&keeper.encode()),
            ]
            .concat();
            sp_io::storage::set(&item_key(b"ReservedKeeperBonds", &suffix), &0u128.encode());
            sp_io::storage::set(&item_key(b"MarginAccounts", &i.encode()), &[0u8; 8]);
        }
    });
    ext.commit_all().expect("seed reaches the backend");

    ext.execute_with(|| {
        let weight = RemovePerpEngine::on_runtime_upgrade();
        let max_block = <Runtime as frame_system::Config>::BlockWeights::get().max_block;
        assert!(
            weight.all_lte(max_block),
            "{weight:?} exceeds a block's {max_block:?}"
        );
        assert!(weight.all_gte(db().reads_writes(
            2 * u64::from(PERP_ENGINE_KEYS_PER_UPGRADE),
            2 * u64::from(PERP_ENGINE_KEYS_PER_UPGRADE),
        )));
    });
}
