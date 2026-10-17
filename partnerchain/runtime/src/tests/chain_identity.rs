//! The chain identity settlement and the oracle bind into committee-signed
//! payloads is this chain's own genesis hash, which off-chain signers read as
//! `chain_getBlockHash(0)`.

use crate::{migrations::PREPROD_GENESIS_HASH, *};
use frame_support::{assert_noop, assert_ok};
use pallet_intent_settlement::types::{Claim, SettlementEvidence, Voucher};
use sp_core::{sr25519, Pair};
use sp_runtime::{
    traits::{Hash as _, Header as _},
    BuildStorage, StateVersion,
};

const PAYMENT_HASH: [u8; 28] = [17; 28];
const CARDANO_TX: [u8; 32] = [21; 32];
const PAIR_ID: [u8; 32] = [24; 32];

fn genesis_state() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("system genesis builds")
        .into()
}

/// The hash of the genesis block a node builds from the current state.
fn genesis_hash() -> H256 {
    Header::new(
        0,
        BlakeTwo256::ordered_trie_root(Vec::new(), StateVersion::V1),
        H256::from_slice(&sp_io::storage::root(StateVersion::V1)),
        H256::zero(),
        Default::default(),
    )
    .hash()
}

fn assert_identity(expected: H256) {
    assert_eq!(IntentSettlementMateriosChainId::get(), expected);
    assert_eq!(OracleMateriosChainId::get(), expected.0);
}

#[test]
fn chain_identity_is_the_genesis_hash_from_block_one_through_pruning() {
    genesis_state().execute_with(|| {
        let genesis = genesis_hash();
        assert_ne!(genesis, PREPROD_GENESIS_HASH);
        System::initialize(&1, &genesis, &Default::default());
        assert_identity(genesis);
        System::finalize();
        // The last two finalisations reach and pass block zero's turn in the
        // BlockHash pruning window.
        for number in [2, BlockHashCount::get() + 1, BlockHashCount::get() + 2] {
            System::initialize(&number, &H256::repeat_byte(7), &Default::default());
            System::finalize();
            assert_identity(genesis);
        }
    });
}

#[test]
fn chain_identity_before_block_one_is_the_system_placeholder() {
    genesis_state().execute_with(|| {
        assert_eq!(System::block_number(), 0);
        assert_eq!(System::block_hash(0), H256::repeat_byte(69));
        assert_identity(H256::repeat_byte(69));
    });
}

/// Seats `pair` as the whole committee, at threshold one.
fn seat_committee(pair: &sr25519::Pair) -> AccountId {
    let account = AccountId::from(pair.public().0);
    pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(
        frame_support::BoundedBTreeSet::<
            AccountId,
            <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
        >::try_from(alloc::collections::BTreeSet::from([account.clone()]))
        .expect("one member fits"),
    );
    pallet_orinq_receipts::AttestationThreshold::<Runtime>::put(1);
    account
}

/// A claim with a voucher, whose settlement `requester` has requested.
fn requested_claim(requester: AccountId) -> Voucher {
    use pallet_intent_settlement::{Claims, Vouchers};
    let mut address = vec![0x01];
    address.extend_from_slice(&[PAYMENT_HASH, PAYMENT_HASH].concat());
    let voucher = Voucher {
        claim_id: H256::repeat_byte(11),
        policy_id: H256::repeat_byte(12),
        beneficiary_cardano_addr: address.try_into().expect("a base address fits"),
        amount_ada: 100_000,
        batch_fairness_proof_digest: [18; 32],
        issued_block: 1,
        expiry_slot_cardano: 1000,
        committee_sigs: Default::default(),
    };
    Claims::<Runtime>::insert(
        voucher.claim_id,
        Claim {
            intent_id: H256::repeat_byte(13),
            policy_id: voucher.policy_id,
            amount_ada: voucher.amount_ada,
            issued_block: voucher.issued_block,
            expiry_slot_cardano: voucher.expiry_slot_cardano,
            settled: false,
            settled_direct: false,
            cardano_tx_hash: [0; 32],
        },
    );
    Vouchers::<Runtime>::insert(voucher.claim_id, &voucher);
    assert_ok!(IntentSettlement::request_settle(
        RuntimeOrigin::signed(requester),
        voucher.claim_id,
        CARDANO_TX,
        false,
        SettlementEvidence {
            cardano_tx_hash: CARDANO_TX,
            observed_at_depth: 15,
            observed_slot: 500,
            beneficiary_addr_hash: PAYMENT_HASH,
            amount_lovelace: voucher.amount_ada,
            mainchain_genesis_hash: IntentSettlementMainchainGenesisHash::get(),
        },
    ));
    voucher
}

/// The STCA digest a committee member signs to attest `voucher`'s
/// settlement, bound to `chain_id`.
fn settle_digest(chain_id: [u8; 32], voucher: &Voucher) -> [u8; 32] {
    use pallet_intent_settlement::voucher_canonicalize::{
        build_type0_address_cbor, compute_voucher_digest_with_address, ChainIdentity,
        Type0AddressHashes,
    };
    let address_cbor = build_type0_address_cbor(Type0AddressHashes {
        payment_hash: &PAYMENT_HASH,
        stake_hash: &PAYMENT_HASH,
    });
    let voucher_digest = compute_voucher_digest_with_address(
        ChainIdentity {
            materios_chain_id: &chain_id,
            network_magic: IntentSettlementNetworkMagic::get(),
            aegis_policy_script_hash: &IntentSettlementAegisPolicyV1ScriptHash::get(),
            settlement_version: IntentSettlementSettlementVersion::get(),
        },
        &voucher.claim_id,
        &voucher.policy_id,
        &address_cbor,
        voucher.amount_ada,
        &voucher.batch_fairness_proof_digest,
        voucher.issued_block,
        voucher.expiry_slot_cardano,
    );
    pallet_intent_settlement::settle_claim_attested_payload(
        &chain_id,
        &voucher.claim_id,
        &voucher_digest,
        &CARDANO_TX,
        false,
        &PAYMENT_HASH,
        voucher.amount_ada,
        15,
        500,
        &IntentSettlementMainchainGenesisHash::get(),
    )
}

#[test]
fn attest_settle_verifies_over_the_live_genesis_and_refuses_the_preprod_constant() {
    genesis_state().execute_with(|| {
        let genesis = genesis_hash();
        System::initialize(&1, &genesis, &Default::default());
        let pair = sr25519::Pair::from_seed(&[19; 32]);
        let member = seat_committee(&pair);
        let voucher = requested_claim(member.clone());
        let bundle = |chain_id: [u8; 32]| {
            vec![(
                pair.public().0,
                pair.sign(&settle_digest(chain_id, &voucher)).0,
            )]
        };
        assert_noop!(
            IntentSettlement::attest_settle(
                RuntimeOrigin::signed(member.clone()),
                voucher.claim_id,
                bundle(PREPROD_GENESIS_HASH.0)
            ),
            pallet_intent_settlement::Error::<Runtime>::InvalidSignature
        );
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(member),
            voucher.claim_id,
            bundle(genesis.0)
        ));
        assert!(
            pallet_intent_settlement::Claims::<Runtime>::get(voucher.claim_id)
                .expect("the claim stays")
                .settled
        );
    });
}

#[test]
fn submit_price_verifies_over_the_live_genesis_and_refuses_the_preprod_constant() {
    genesis_state().execute_with(|| {
        let genesis = genesis_hash();
        System::initialize(&1, &genesis, &Default::default());
        let pair = sr25519::Pair::from_seed(&[23; 32]);
        pallet_oracle::Attestors::<Runtime>::insert(
            PAIR_ID,
            BoundedVec::<_, OracleMaxAttestors>::try_from(vec![pair.public().0])
                .expect("one attestor fits"),
        );
        let submit = |chain_id: [u8; 32]| {
            let payload = pallet_oracle::submit_price_payload(&chain_id, &PAIR_ID, 100, 6, 1);
            Oracle::submit_price(
                RuntimeOrigin::signed(AccountId::from(pair.public().0)),
                PAIR_ID,
                100,
                6,
                1,
                pair.public().0,
                pair.sign(&payload).0,
            )
        };
        assert_noop!(
            submit(PREPROD_GENESIS_HASH.0),
            pallet_oracle::Error::<Runtime>::InvalidSignature
        );
        assert_ok!(submit(genesis.0));
        assert!(pallet_oracle::AttestorSubmitted::<Runtime>::contains_key((
            PAIR_ID,
            1,
            pair.public().0
        )));
    });
}

/// On preprod, whose genesis is the hash the runtime used to pin, every
/// committee digest is the one signers produce today, and a bundle signed
/// over it settles.
#[test]
fn preprod_digests_are_byte_identical_to_the_pinned_constant() {
    genesis_state().execute_with(|| {
        System::initialize(&1, &PREPROD_GENESIS_HASH, &Default::default());
        assert_identity(PREPROD_GENESIS_HASH);
        let live = IntentSettlementMateriosChainId::get().0;
        let pinned = PREPROD_GENESIS_HASH.0;
        let pair = sr25519::Pair::from_seed(&[19; 32]);
        let member = seat_committee(&pair);
        let voucher = requested_claim(member.clone());
        let expire = |chain_id: &[u8; 32]| {
            pallet_intent_settlement::expire_policy_attested_payload(
                chain_id,
                &H256::repeat_byte(13),
                &voucher.policy_id,
                &CARDANO_TX,
                15,
                500,
                &IntentSettlementMainchainGenesisHash::get(),
            )
        };
        let fraud = |chain_id: &[u8; 32]| {
            pallet_intent_settlement::slash_bad_settlement_evidence_payload(
                chain_id,
                &voucher.claim_id,
                &pallet_intent_settlement::types::FraudProof::TxNotFound,
            )
        };
        let price = |chain_id: &[u8; 32]| {
            pallet_oracle::submit_price_payload(chain_id, &PAIR_ID, 100, 6, 1)
        };
        assert_eq!(
            settle_digest(live, &voucher),
            settle_digest(pinned, &voucher)
        );
        assert_eq!(expire(&live), expire(&pinned));
        assert_eq!(fraud(&live), fraud(&pinned));
        assert_eq!(price(&OracleMateriosChainId::get()), price(&pinned));
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(member),
            voucher.claim_id,
            vec![(
                pair.public().0,
                pair.sign(&settle_digest(pinned, &voucher)).0
            )]
        ));
    });
}
