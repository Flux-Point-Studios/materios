use crate as pallet_orinq_receipts;
use crate::{pallet, pallet::GrandpaPendingChange, types::ReceiptRecord};
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstBool, ConstU32, ConstU64},
};
use parity_scale_codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, H256};
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------
//
// NOTE: AccountId and BlockNumber are chosen to match the pallet's Hooks
// bounds (see lib.rs):
//   T::AccountId: From<[u8; 32]>   — satisfied by AccountId32
//   BlockNumberFor<T>: Into<u32> + From<u32>   — satisfied by u32
// Using `u64` accounts + `u64` block numbers (as the pre-Hooks-feature
// tests did) fails `IntegrityTest` now that find_block_author + validator
// rewards are part of the pallet proper.

// MockBlockU32 is the u32-BlockNumber variant of MockBlock. We need u32 here
// because the pallet's Hooks impl requires `BlockNumberFor<T>: Into<u32> + From<u32>`.
type Block = frame_system::mocking::MockBlockU32<Test>;
pub type MockAccountId = AccountId32;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Aura: pallet_aura,
        Grandpa: pallet_grandpa,
        Balances: pallet_balances,
        OrinqReceipts: pallet_orinq_receipts,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = MockAccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<u128>;
}

parameter_types! {
    pub const MinimumPeriod: u64 = 5;
    pub const ExistentialDeposit: u128 = 1;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl pallet_aura::Config for Test {
    type AuthorityId = sp_consensus_aura::sr25519::AuthorityId;
    type DisabledValidators = ();
    type MaxAuthorities = ConstU32<32>;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Test>;
}

impl pallet_grandpa::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

impl pallet_balances::Config for Test {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type Balance = u128;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
}

impl pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = crate::weights::SubstrateWeight;
    type MaxResubmits = ConstU32<64>;
    type MaxCommitteeSize = ConstU32<16>;
}

/// Construct a deterministic AccountId32 from a single byte seed (for tests).
fn acc(seed: u8) -> MockAccountId {
    AccountId32::new([seed; 32])
}

/// Build genesis storage for tests.
fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    // Seed Component-5 storage from genesis (defaults match the previous
    // const values: 10 MATRA/signer, 50K MATRA/era base, baseline 16).
    pallet_orinq_receipts::GenesisConfig::<Test> {
        attestation_reward_per_signer: 10_000_000,
        era_cap_base: 50_000_000_000,
        era_cap_baseline_attestor_count: 16,
        _phantom: Default::default(),
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        // Seed timestamp so `pallet_timestamp::Now` is populated.
        Timestamp::set_timestamp(1_000);
    });
    ext
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dummy_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn submit(
    who_seed: u8,
    receipt_id: H256,
    content_hash: H256,
) -> frame_support::dispatch::DispatchResult {
    OrinqReceipts::submit_receipt(
        RuntimeOrigin::signed(acc(who_seed)),
        receipt_id,
        content_hash,
        dummy_hash(1),       // base_root_sha256
        None,                // zk_root_poseidon
        None,                // poseidon_params_hash
        dummy_hash(2),       // base_manifest_hash
        dummy_hash(3),       // safety_manifest_hash
        dummy_hash(4),       // monitor_config_hash
        dummy_hash(5),       // attestation_evidence_hash
        dummy_hash(6),       // storage_locator_hash
        dummy_hash(7),       // schema_hash
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn submit_receipt_stores_record_and_increments_counter() {
    new_test_ext().execute_with(|| {
        let rid = H256::from([0xAA; 32]);
        let ch = H256::from([0xBB; 32]);

        assert_ok!(submit(1, rid, ch));

        // Storage populated
        let record = OrinqReceipts::receipts(rid).expect("receipt should exist");
        assert_eq!(record.submitter, acc(1));
        assert_eq!(record.content_hash, ch.0);
        assert_eq!(record.base_root_sha256, dummy_hash(1));
        assert_eq!(record.schema_hash, dummy_hash(7));

        // Counter
        assert_eq!(OrinqReceipts::receipt_count(), 1);

        // Content index
        let ids = OrinqReceipts::content_index(ch);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], rid);
    });
}

#[test]
fn submit_receipt_duplicate_fails() {
    new_test_ext().execute_with(|| {
        let rid = H256::from([0xCC; 32]);
        let ch = H256::from([0xDD; 32]);

        assert_ok!(submit(1, rid, ch));
        assert_noop!(
            submit(2, rid, ch),
            pallet::Error::<Test>::ReceiptAlreadyExists
        );
    });
}

#[test]
fn set_availability_cert_works_for_root() {
    new_test_ext().execute_with(|| {
        let rid = H256::from([0x11; 32]);
        let ch = H256::from([0x22; 32]);
        assert_ok!(submit(1, rid, ch));

        let cert = [0xFF; 32];
        assert_ok!(OrinqReceipts::set_availability_cert(
            RuntimeOrigin::root(),
            rid,
            cert,
        ));

        let record = OrinqReceipts::receipts(rid).unwrap();
        assert_eq!(record.availability_cert_hash, cert);
    });
}

#[test]
fn set_availability_cert_rejects_non_root() {
    new_test_ext().execute_with(|| {
        let rid = H256::from([0x33; 32]);
        let ch = H256::from([0x44; 32]);
        assert_ok!(submit(1, rid, ch));

        assert_noop!(
            OrinqReceipts::set_availability_cert(
                RuntimeOrigin::signed(acc(1)),
                rid,
                [0xFF; 32],
            ),
            frame_support::error::BadOrigin
        );
    });
}

#[test]
fn set_availability_cert_fails_for_missing_receipt() {
    new_test_ext().execute_with(|| {
        let rid = H256::from([0x55; 32]);
        assert_noop!(
            OrinqReceipts::set_availability_cert(RuntimeOrigin::root(), rid, [0xFF; 32]),
            pallet::Error::<Test>::ReceiptNotFound
        );
    });
}

#[test]
fn content_index_accumulates_multiple_receipts() {
    new_test_ext().execute_with(|| {
        let ch = H256::from([0xEE; 32]);

        for i in 0u8..5 {
            let rid = H256::from([i; 32]);
            assert_ok!(submit(1, rid, ch));
        }

        let ids = OrinqReceipts::content_index(ch);
        assert_eq!(ids.len(), 5);
        assert_eq!(OrinqReceipts::receipt_count(), 5);
    });
}

#[test]
fn timestamp_comes_from_pallet_timestamp() {
    new_test_ext().execute_with(|| {
        // The test ext seeds timestamp at 1_000.
        let rid = H256::from([0xFA; 32]);
        let ch = H256::from([0xFB; 32]);
        assert_ok!(submit(1, rid, ch));

        let record = OrinqReceipts::receipts(rid).unwrap();
        assert_eq!(record.created_at_millis, 1_000);

        // Advance timestamp and submit another receipt.
        Timestamp::set_timestamp(2_500);
        let rid2 = H256::from([0xFC; 32]);
        assert_ok!(submit(1, rid2, ch));

        let record2 = OrinqReceipts::receipts(rid2).unwrap();
        assert_eq!(record2.created_at_millis, 2_500);
    });
}

// ---------------------------------------------------------------------------
// rotate_authorities tests
// ---------------------------------------------------------------------------

fn make_aura_ids(count: u8) -> Vec<sp_consensus_aura::sr25519::AuthorityId> {
    use sp_core::crypto::UncheckedFrom;
    (1..=count)
        .map(|i| sp_consensus_aura::sr25519::AuthorityId::unchecked_from([i; 32]))
        .collect()
}

fn make_grandpa_ids(count: u8) -> sp_consensus_grandpa::AuthorityList {
    use sp_core::crypto::UncheckedFrom;
    (1..=count)
        .map(|i| (sp_consensus_grandpa::AuthorityId::unchecked_from([i; 32]), 1))
        .collect()
}

#[test]
fn rotate_authorities_works() {
    new_test_ext().execute_with(|| {
        let aura_ids = make_aura_ids(3);
        let grandpa_ids = make_grandpa_ids(3);

        assert_ok!(OrinqReceipts::rotate_authorities(
            RuntimeOrigin::root(),
            aura_ids.clone(),
            grandpa_ids.clone(),
            5,
        ));

        // Aura authorities updated immediately
        let stored_aura = pallet_aura::Authorities::<Test>::get();
        assert_eq!(stored_aura.len(), 3);

        // Grandpa PendingChange was written (raw storage — type alias is pub(crate))
        let pending_key = frame_support::storage::storage_prefix(b"Grandpa", b"PendingChange");
        assert!(frame_support::storage::unhashed::exists(&pending_key));

        // Stalled marker cleared (raw storage — type alias is pub(crate))
        let stalled_key = frame_support::storage::storage_prefix(b"Grandpa", b"Stalled");
        assert!(!frame_support::storage::unhashed::exists(&stalled_key));
    });
}

#[test]
fn rotate_authorities_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::rotate_authorities(
                RuntimeOrigin::signed(acc(1)),
                make_aura_ids(2),
                make_grandpa_ids(2),
                5,
            ),
            frame_support::error::BadOrigin
        );
    });
}

#[test]
fn rotate_authorities_rejects_empty_set() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::rotate_authorities(
                RuntimeOrigin::root(),
                vec![],
                vec![],
                5,
            ),
            pallet::Error::<Test>::EmptyAuthoritySet
        );
    });
}

#[test]
fn rotate_authorities_rejects_mismatched_counts() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::rotate_authorities(
                RuntimeOrigin::root(),
                make_aura_ids(3),
                make_grandpa_ids(2),
                5,
            ),
            pallet::Error::<Test>::AuthorityCountMismatch
        );
    });
}

#[test]
fn rotate_authorities_rejects_double_pending() {
    new_test_ext().execute_with(|| {
        // First rotation succeeds
        assert_ok!(OrinqReceipts::rotate_authorities(
            RuntimeOrigin::root(),
            make_aura_ids(2),
            make_grandpa_ids(2),
            5,
        ));

        // Second rotation must fail — PendingChange already exists.
        //
        // Which error fires depends on the SDK version: our pallet's own
        // `AuthorityChangeAlreadyPending` wins only if we can inspect the
        // Grandpa state before calling `schedule_change`. Newer
        // pallet-grandpa returns its own `ChangePending` from
        // `schedule_change` first. Either way the invariant holds — the
        // second rotation is rejected — so assert on the rejection, not on
        // the specific discriminant.
        let result = OrinqReceipts::rotate_authorities(
            RuntimeOrigin::root(),
            make_aura_ids(3),
            make_grandpa_ids(3),
            5,
        );
        assert!(
            result.is_err(),
            "Second rotation must fail while a change is pending; got {:?}",
            result
        );
    });
}

// ---------------------------------------------------------------------------
// Component 5 — dynamic attestation reward + era cap
//
// These tests are the TDD contract for converting the two hard-coded
// `const` values in the pallet (ATTESTATION_REWARD_PER_SIGNER,
// ATTESTATION_ERA_CAP) into governance-tunable storage with a default
// that matches the previous constants (for migration safety) and an
// auto-scaling era cap that grows with `active_attestor_count`.
// ---------------------------------------------------------------------------

#[test]
fn reward_per_signer_readable_via_storage() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            OrinqReceipts::attestation_reward_per_signer(),
            10_000_000u128,
            "default must match previous const for migration safety"
        );
    });
}

#[test]
fn reward_per_signer_settable_by_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_attestation_reward_per_signer(
            RuntimeOrigin::root(),
            5_000_000
        ));
        assert_eq!(OrinqReceipts::attestation_reward_per_signer(), 5_000_000);
    });
}

#[test]
fn reward_per_signer_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::set_attestation_reward_per_signer(
                RuntimeOrigin::signed(acc(1)),
                5_000_000
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn era_cap_base_has_default() {
    // Default baseline = 50_000_000_000 (50K MATRA in 6-decimal base units).
    new_test_ext().execute_with(|| {
        assert_eq!(OrinqReceipts::era_cap_base(), 50_000_000_000u128);
    });
}

#[test]
fn era_cap_baseline_attestor_count_has_default() {
    // Default baseline attestor count = 16 (matches MaxCommitteeSize in tests).
    new_test_ext().execute_with(|| {
        assert_eq!(OrinqReceipts::era_cap_baseline_attestor_count(), 16u32);
    });
}

#[test]
fn era_cap_auto_scales_with_attestor_count() {
    // With baseline_count = 16, doubling the committee size should double
    // the effective era cap. We can't add more than 16 (MaxCommitteeSize)
    // in the test mock, so verify linear scaling at two representative
    // sub-baseline counts (4 and 8).
    new_test_ext().execute_with(|| {
        let base_cap = OrinqReceipts::era_cap_base();
        let baseline = OrinqReceipts::era_cap_baseline_attestor_count() as u128;
        assert_eq!(baseline, 16);

        // Seed committee with 4 members.
        for i in 1u8..=4 {
            assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(acc(i))));
        }
        let cap_at_4 = OrinqReceipts::effective_era_cap();
        assert_eq!(
            cap_at_4,
            base_cap * 4 / 16,
            "effective cap at 4 attestors must be base * 4 / 16"
        );

        // Grow to 8 members.
        for i in 5u8..=8 {
            assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(acc(i))));
        }
        let cap_at_8 = OrinqReceipts::effective_era_cap();
        assert_eq!(
            cap_at_8,
            base_cap * 8 / 16,
            "effective cap at 8 attestors must be base * 8 / 16"
        );
        assert_eq!(cap_at_8, cap_at_4 * 2, "8 attestors = 2× the cap of 4");
    });
}

#[test]
fn era_cap_settable_by_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_era_cap_base(
            RuntimeOrigin::root(),
            100_000_000_000
        ));
        assert_eq!(OrinqReceipts::era_cap_base(), 100_000_000_000);
    });
}

#[test]
fn era_cap_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::set_era_cap_base(RuntimeOrigin::signed(acc(1)), 100_000_000_000),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn era_cap_baseline_settable_by_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_era_cap_baseline_attestor_count(
            RuntimeOrigin::root(),
            32
        ));
        assert_eq!(OrinqReceipts::era_cap_baseline_attestor_count(), 32);
    });
}

#[test]
fn era_cap_baseline_rejects_zero() {
    // Prevent div-by-zero in effective_era_cap().
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::set_era_cap_baseline_attestor_count(RuntimeOrigin::root(), 0),
            pallet::Error::<Test>::InvalidBaseline
        );
    });
}

#[test]
fn effective_era_cap_with_zero_attestors_is_zero() {
    // If the committee is empty, the cap should collapse to zero — we
    // shouldn't be paying rewards when nobody is attesting.
    new_test_ext().execute_with(|| {
        assert_eq!(OrinqReceipts::committee_members().len(), 0);
        assert_eq!(OrinqReceipts::effective_era_cap(), 0);
    });
}

#[test]
fn storage_values_emit_events_on_set() {
    // Each governance-tunable storage update must emit a dedicated event
    // so indexers + governance dashboards can observe the change.
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_attestation_reward_per_signer(
            RuntimeOrigin::root(),
            7_500_000
        ));
        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::AttestationRewardPerSignerUpdated { new_value: 7_500_000 }
                )
            )
        });
        assert!(matched, "AttestationRewardPerSignerUpdated event must fire");

        assert_ok!(OrinqReceipts::set_era_cap_base(
            RuntimeOrigin::root(),
            123_456_789
        ));
        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::EraCapBaseUpdated { new_value: 123_456_789 }
                )
            )
        });
        assert!(matched, "EraCapBaseUpdated event must fire");
    });
}

// ---------------------------------------------------------------------------
// GrandpaPendingChange SCALE layout tests
// ---------------------------------------------------------------------------

#[test]
fn grandpa_pending_change_scale_round_trip() {
    use sp_core::crypto::UncheckedFrom;

    let authorities: sp_consensus_grandpa::AuthorityList = vec![
        (sp_consensus_grandpa::AuthorityId::unchecked_from([1u8; 32]), 1),
        (sp_consensus_grandpa::AuthorityId::unchecked_from([2u8; 32]), 10),
    ];

    let original = GrandpaPendingChange::<u64> {
        scheduled_at: 42,
        delay: 7,
        next_authorities: authorities.clone(),
        forced: Some(42),
    };

    let encoded = original.encode();
    let decoded = GrandpaPendingChange::<u64>::decode(&mut &encoded[..])
        .expect("round-trip decode must succeed");

    assert_eq!(decoded.scheduled_at, 42);
    assert_eq!(decoded.delay, 7);
    assert_eq!(decoded.next_authorities, authorities);
    assert_eq!(decoded.forced, Some(42));
    assert_eq!(decoded, original);
}

#[test]
fn grandpa_pending_change_scale_round_trip_no_forced() {
    use sp_core::crypto::UncheckedFrom;

    let authorities: sp_consensus_grandpa::AuthorityList = vec![
        (sp_consensus_grandpa::AuthorityId::unchecked_from([0xAA; 32]), 5),
    ];

    let original = GrandpaPendingChange::<u64> {
        scheduled_at: 100,
        delay: 10,
        next_authorities: authorities.clone(),
        forced: None,
    };

    let encoded = original.encode();
    let decoded = GrandpaPendingChange::<u64>::decode(&mut &encoded[..])
        .expect("round-trip decode must succeed");

    assert_eq!(decoded, original);
    assert_eq!(decoded.forced, None);
}

#[test]
fn grandpa_pending_change_layout_compatibility() {
    // Verify exact byte layout matches pallet_grandpa's StoredPendingChange
    // (SDK: polkadot-stable2409-5, pallet-grandpa v38.0.0).
    use sp_core::crypto::UncheckedFrom;

    let auth_id = sp_consensus_grandpa::AuthorityId::unchecked_from([0x01; 32]);
    let pending = GrandpaPendingChange::<u64> {
        scheduled_at: 10,
        delay: 3,
        next_authorities: vec![(auth_id, 1)],
        forced: Some(10),
    };

    let encoded = pending.encode();

    // Build expected bytes manually:
    let mut expected = Vec::new();
    expected.extend_from_slice(&10u64.to_le_bytes()); // scheduled_at
    expected.extend_from_slice(&3u64.to_le_bytes());  // delay
    expected.push(0x04); // compact length: 1 item
    expected.extend_from_slice(&[0x01; 32]); // AuthorityId
    expected.extend_from_slice(&1u64.to_le_bytes()); // AuthorityWeight
    expected.push(0x01); // Some variant
    expected.extend_from_slice(&10u64.to_le_bytes()); // forced value

    assert_eq!(
        encoded, expected,
        "GrandpaPendingChange byte layout does not match expected pallet_grandpa layout. \
         If this fails after an SDK upgrade, inspect the new StoredPendingChange definition \
         in substrate/frame/grandpa/src/lib.rs and update GrandpaPendingChange accordingly."
    );

    let decoded = GrandpaPendingChange::<u64>::decode(&mut &expected[..])
        .expect("manually constructed bytes must decode");
    assert_eq!(decoded, pending);
}
