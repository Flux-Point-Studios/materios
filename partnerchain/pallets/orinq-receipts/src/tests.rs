use crate as pallet_orinq_receipts;
use crate::{pallet, pallet::GrandpaPendingChange, types::{ReceiptRecord, SlashReason}};
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstBool, ConstU32, ConstU64, Currency, ReservableCurrency},
    PalletId,
};
use parity_scale_codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, H256};
use sp_runtime::{
    traits::{AccountIdConversion, BlakeTwo256, IdentityLookup},
    BuildStorage, Perbill,
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

parameter_types! {
    /// Mock attestor reserve pot — matches the production runtime's
    /// `mat/attr` PalletId so test expectations mirror the real routing.
    pub const AttestorReservePotId: PalletId = PalletId(*b"mat/attr");
    /// Mock treasury pot — matches the production runtime's `mat/trsy`
    /// PalletId so Component-4 fee-split tests mirror the real routing.
    pub const TreasuryPotId: PalletId = PalletId(*b"mat/trsy");
    /// Mock treasury emission share. `pub static` (rather than `pub const`)
    /// generates a mutable `TreasuryEmissionShareValue::set(Perbill)` setter
    /// used by `era_emission_respects_configurable_treasury_share` to retune
    /// the split at test-time. Default matches the production 15%.
    pub static TreasuryEmissionShareValue: Perbill = Perbill::from_percent(15);
}

impl pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = crate::weights::SubstrateWeight;
    type MaxResubmits = ConstU32<64>;
    type MaxCommitteeSize = ConstU32<16>;
    type Currency = Balances;
    type AttestorReservePotId = AttestorReservePotId;
    type TreasuryPotId = TreasuryPotId;
    type TreasuryEmissionShare = TreasuryEmissionShareValue;
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
    // Component 4: seed the per-receipt fee, floor, and expiry deadline at
    // the documented defaults.
    pallet_orinq_receipts::GenesisConfig::<Test> {
        attestation_reward_per_signer: 10_000_000,
        era_cap_base: 50_000_000_000,
        era_cap_baseline_attestor_count: 16,
        bond_requirement: 1_000_000_000,
        receipt_submission_fee: 1_000_000,
        receipt_submission_fee_floor: 100_000,
        receipt_expiry_blocks: 14_400,
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
    // Component 4: ensure the submitter has enough MATRA to reserve the
    // per-receipt submission fee. Tests that explicitly want to exercise
    // the InsufficientFee error bypass this helper and fund manually —
    // we only auto-fund accounts at zero so a deliberately-underfunded
    // account (e.g. with 500_000 balance, below the 1M fee) isn't
    // silently topped up.
    if Balances::free_balance(&acc(who_seed)) == 0 {
        Balances::make_free_balance_be(&acc(who_seed), 10_000_000);
    }
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

        // Pre-fund the second submitter outside `assert_noop!` so its
        // auto-fund side-effect does not pollute the storage hash check.
        Balances::make_free_balance_be(&acc(2), 10_000_000);
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

        // Seed committee with 4 members. Component 8 requires a bond to
        // join, so fund + bond each account before joining.
        for i in 1u8..=4 {
            Balances::make_free_balance_be(&acc(i), 10_000_000_000);
            assert_ok!(OrinqReceipts::bond(
                RuntimeOrigin::signed(acc(i)),
                1_000_000_000
            ));
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
            Balances::make_free_balance_be(&acc(i), 10_000_000_000);
            assert_ok!(OrinqReceipts::bond(
                RuntimeOrigin::signed(acc(i)),
                1_000_000_000
            ));
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

// ---------------------------------------------------------------------------
// Component 8 — Attestor Bond + Slashing
//
// Attestors must lock a bond before joining the committee. Misbehaviour is
// punished by slashing the bond and repatriating funds to the attestor
// reserve pot (`mat/attr`) so the MATRA accumulates for future rewards
// rather than being burned. Auto-eject if the remaining bond drops below
// `BondRequirement`.
// ---------------------------------------------------------------------------

#[test]
fn bond_reserves_balance_and_records_amount() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            5_000_000_000
        ));
        assert_eq!(Balances::reserved_balance(&attestor), 5_000_000_000);
        assert_eq!(OrinqReceipts::attestor_bonds(&attestor), 5_000_000_000);
    });
}

#[test]
fn bond_rejects_insufficient_balance() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 1_000_000);
        assert_noop!(
            OrinqReceipts::bond(RuntimeOrigin::signed(attestor), 5_000_000_000),
            pallet_balances::Error::<Test>::InsufficientBalance
        );
    });
}

#[test]
fn bond_accumulates_on_repeat_calls() {
    // Calling `bond` twice should extend the existing reservation rather
    // than clobber it — attestors can top up without a withdraw/re-bond.
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            2_000_000_000
        ));
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            3_000_000_000
        ));
        assert_eq!(OrinqReceipts::attestor_bonds(&attestor), 5_000_000_000);
        assert_eq!(Balances::reserved_balance(&attestor), 5_000_000_000);
    });
}

#[test]
fn unbond_while_in_committee_fails() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            1_000_000_000
        ));
        assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(attestor.clone())));
        assert_noop!(
            OrinqReceipts::unbond(RuntimeOrigin::signed(attestor)),
            pallet::Error::<Test>::StillInCommittee
        );
    });
}

#[test]
fn unbond_returns_balance_when_not_in_committee() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            1_000_000_000
        ));
        assert_eq!(Balances::reserved_balance(&attestor), 1_000_000_000);

        assert_ok!(OrinqReceipts::unbond(RuntimeOrigin::signed(attestor.clone())));
        assert_eq!(Balances::reserved_balance(&attestor), 0);
        assert_eq!(OrinqReceipts::attestor_bonds(&attestor), 0);
        assert_eq!(Balances::free_balance(&attestor), 10_000_000_000);
    });
}

#[test]
fn unbond_without_prior_bond_fails() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_noop!(
            OrinqReceipts::unbond(RuntimeOrigin::signed(attestor)),
            pallet::Error::<Test>::NothingToUnbond
        );
    });
}

#[test]
fn join_committee_requires_bond() {
    // Default BondRequirement is 1_000_000_000 (1K MATRA at 6 decimals).
    // Without enough bond, join_committee must reject.
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_noop!(
            OrinqReceipts::join_committee(RuntimeOrigin::signed(attestor.clone())),
            pallet::Error::<Test>::InsufficientBond
        );

        // Bond below requirement still fails.
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            500_000_000
        ));
        assert_noop!(
            OrinqReceipts::join_committee(RuntimeOrigin::signed(attestor.clone())),
            pallet::Error::<Test>::InsufficientBond
        );

        // Top up to meet the requirement and retry.
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            500_000_000
        ));
        assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(attestor)));
    });
}

#[test]
fn slash_reduces_bond_and_routes_to_reserve_pot() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        let reserve_acct: MockAccountId =
            AttestorReservePotId::get().into_account_truncating();

        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        // Pre-fund the reserve pot above ED so it can receive repatriated funds.
        Balances::make_free_balance_be(&reserve_acct, 1);

        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            5_000_000_000
        ));

        let reserve_before = Balances::free_balance(&reserve_acct);
        assert_ok!(OrinqReceipts::slash_attestor(
            RuntimeOrigin::root(),
            attestor.clone(),
            1_000_000_000,
            SlashReason::InvalidSignature
        ));
        assert_eq!(OrinqReceipts::attestor_bonds(&attestor), 4_000_000_000);
        assert_eq!(Balances::reserved_balance(&attestor), 4_000_000_000);
        assert_eq!(
            Balances::free_balance(&reserve_acct),
            reserve_before + 1_000_000_000
        );
    });
}

#[test]
fn slash_auto_ejects_if_bond_drops_below_requirement() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        let reserve_acct: MockAccountId =
            AttestorReservePotId::get().into_account_truncating();

        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        Balances::make_free_balance_be(&reserve_acct, 1);

        // Bond exactly at requirement (default = 1_000_000_000) then join.
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            1_000_000_000
        ));
        assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(
            attestor.clone()
        )));
        assert!(OrinqReceipts::committee_members().contains(&attestor));

        // Slash half the bond — new bond = 500M, below the 1B requirement.
        assert_ok!(OrinqReceipts::slash_attestor(
            RuntimeOrigin::root(),
            attestor.clone(),
            500_000_000,
            SlashReason::Unavailability
        ));

        // Auto-ejected.
        assert!(!OrinqReceipts::committee_members().contains(&attestor));
    });
}

#[test]
fn slash_rejects_non_root() {
    new_test_ext().execute_with(|| {
        let attestor = acc(1);
        let caller = acc(2);
        Balances::make_free_balance_be(&attestor, 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(
            RuntimeOrigin::signed(attestor.clone()),
            5_000_000_000
        ));

        assert_noop!(
            OrinqReceipts::slash_attestor(
                RuntimeOrigin::signed(caller),
                attestor,
                1_000_000_000,
                SlashReason::Governance
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_bond_requirement_root_only() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_bond_requirement(
            RuntimeOrigin::root(),
            2_500_000_000
        ));
        assert_eq!(OrinqReceipts::bond_requirement(), 2_500_000_000);

        assert_noop!(
            OrinqReceipts::set_bond_requirement(RuntimeOrigin::signed(acc(1)), 1),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn bond_requirement_has_default() {
    new_test_ext().execute_with(|| {
        // Default = 1_000_000_000 base units (1K MATRA at 6 decimals).
        assert_eq!(OrinqReceipts::bond_requirement(), 1_000_000_000);
    });
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

// ---------------------------------------------------------------------------
// Component 4 — per-receipt submission fee + signer payout
//
// Submitter pays a flat fee on each receipt, held in escrow. When the
// attestation threshold is met, 80% is split pro-rata flat among the actual
// signers and 20% plus any rounding residue goes to the treasury pot. If the
// receipt expires before certification, the full fee refunds to the
// submitter. Both the fee amount and a minimum-floor are governance-tunable.
// ---------------------------------------------------------------------------

/// Default fee at genesis: 1 MATRA (6 decimals = 1_000_000 base units).
const DEFAULT_FEE: u128 = 1_000_000;
/// Default floor at genesis: 0.1 MATRA (100_000 base units).
const DEFAULT_FLOOR: u128 = 100_000;

fn treasury_account() -> MockAccountId {
    TreasuryPotId::get().into_account_truncating()
}

/// Submit a receipt with dummy field values — shorthand used by Component-4
/// tests, distinct from the top-of-file `submit` helper which predates
/// Component 4 so is re-used unchanged.
fn submit_c4(who_seed: u8, receipt_id: H256, content_hash: H256) -> frame_support::dispatch::DispatchResult {
    submit(who_seed, receipt_id, content_hash)
}

/// Attach Alice (seed 1) to the committee with a bond and threshold-1 setup,
/// and seed enough free balance that the receipt fee can be reserved.
fn seed_submitter_and_committee(submitter_seed: u8, committee_seeds: &[u8]) {
    // Submitter gets enough MATRA to cover the fee.
    Balances::make_free_balance_be(&acc(submitter_seed), 10_000_000_000);
    // Committee members each fund + bond + join.
    for &s in committee_seeds.iter() {
        Balances::make_free_balance_be(&acc(s), 10_000_000_000);
        assert_ok!(OrinqReceipts::bond(RuntimeOrigin::signed(acc(s)), 1_000_000_000));
        assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(acc(s))));
    }
    // Treasury pot pre-funded above ED so it can receive deposits.
    Balances::make_free_balance_be(&treasury_account(), 1);
}

#[test]
fn fee_storage_defaults_match_genesis() {
    new_test_ext().execute_with(|| {
        assert_eq!(OrinqReceipts::receipt_submission_fee(), DEFAULT_FEE);
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), DEFAULT_FLOOR);
    });
}

#[test]
fn submit_receipt_reserves_fee_from_submitter() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([7u8; 32]);
        let ch = H256::from([8u8; 32]);

        assert_ok!(submit_c4(1, rid, ch));

        // Fee reserved from submitter's free balance.
        assert_eq!(Balances::reserved_balance(&submitter), DEFAULT_FEE);
        assert_eq!(Balances::free_balance(&submitter), 10_000_000 - DEFAULT_FEE);

        // Escrow map populated.
        let escrow = pallet::ReceiptFeeEscrow::<Test>::get(rid)
            .expect("escrow must be populated on submit");
        assert_eq!(escrow.0, submitter);
        assert_eq!(escrow.1, DEFAULT_FEE);
    });
}

#[test]
fn insufficient_balance_rejects_submission() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        // Below fee (1M).
        Balances::make_free_balance_be(&submitter, 500_000);
        let rid = H256::from([7u8; 32]);
        let ch = H256::from([8u8; 32]);

        assert_noop!(
            submit_c4(1, rid, ch),
            pallet::Error::<Test>::InsufficientFee
        );
    });
}

#[test]
fn threshold_hit_splits_fee_80_20_three_signers() {
    new_test_ext().execute_with(|| {
        // 5-member committee, threshold 3; 3 signers actually attest.
        // Expected: each signer gets (1M * 80/100) / 3 = 266_666 (dust 2 -> treasury)
        //           treasury gets 200_000 + 2 = 200_002
        let submitter_seed = 10;
        let committee_seeds: Vec<u8> = (1u8..=5).collect();
        seed_submitter_and_committee(submitter_seed, &committee_seeds);

        // Set threshold to 3 (committee has 5 members).
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            committee_seeds.iter().map(|&s| acc(s)).collect(),
            3
        ));

        let rid = H256::from([0xA1; 32]);
        let ch = H256::from([0xA2; 32]);

        let submitter_free_before = Balances::free_balance(&acc(submitter_seed));
        assert_ok!(submit_c4(submitter_seed, rid, ch));
        assert_eq!(Balances::reserved_balance(&acc(submitter_seed)), DEFAULT_FEE);

        // Snapshot signer + treasury balances BEFORE certification.
        let signer_seeds = [1u8, 2, 3];
        let signer_before: Vec<u128> =
            signer_seeds.iter().map(|&s| Balances::free_balance(&acc(s))).collect();
        let treasury_before = Balances::free_balance(&treasury_account());

        // Three signers attest — threshold hits on the third.
        let cert_hash = [0xCE; 32];
        for &s in signer_seeds.iter() {
            assert_ok!(OrinqReceipts::attest_availability_cert(
                RuntimeOrigin::signed(acc(s)),
                rid,
                cert_hash
            ));
        }

        // to_signers = 1_000_000 * 80 / 100 = 800_000
        // per_signer = 800_000 / 3 = 266_666
        // residue    = 800_000 - 3*266_666 = 2
        // to_treasury (final) = 200_000 + 2 = 200_002
        let per_signer = 266_666u128;
        let to_treasury = 200_002u128;

        for (i, &s) in signer_seeds.iter().enumerate() {
            let delta = Balances::free_balance(&acc(s)) - signer_before[i];
            // Each signer also earns the attestation reward (10M base units);
            // the Component-4 payout is in addition to that. Subtract the
            // attestation reward to isolate the fee share.
            let fee_share = delta - 10_000_000;
            assert_eq!(
                fee_share, per_signer,
                "signer {} should get {} fee share, got {}",
                s, per_signer, fee_share
            );
        }

        assert_eq!(
            Balances::free_balance(&treasury_account()) - treasury_before,
            to_treasury,
            "treasury must receive 20% + rounding residue"
        );

        // Submitter's reserve drained, escrow cleared, free balance went down
        // by exactly the full fee.
        assert_eq!(Balances::reserved_balance(&acc(submitter_seed)), 0);
        assert!(pallet::ReceiptFeeEscrow::<Test>::get(rid).is_none());
        assert_eq!(
            submitter_free_before - Balances::free_balance(&acc(submitter_seed)),
            DEFAULT_FEE
        );
    });
}

#[test]
fn threshold_hit_with_seven_signers_splits_cleanly() {
    // 1M × 0.80 = 800_000; / 7 = 114_285 each; residue = 800_000 - 7*114_285 = 5.
    // Treasury = 200_000 + 5 = 200_005.
    new_test_ext().execute_with(|| {
        let submitter_seed = 10;
        let committee_seeds: Vec<u8> = (1u8..=7).collect();
        seed_submitter_and_committee(submitter_seed, &committee_seeds);
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            committee_seeds.iter().map(|&s| acc(s)).collect(),
            7
        ));

        let rid = H256::from([0xB1; 32]);
        let ch = H256::from([0xB2; 32]);
        assert_ok!(submit_c4(submitter_seed, rid, ch));

        let signer_before: Vec<u128> =
            committee_seeds.iter().map(|&s| Balances::free_balance(&acc(s))).collect();
        let treasury_before = Balances::free_balance(&treasury_account());

        let cert_hash = [0xCE; 32];
        for &s in committee_seeds.iter() {
            assert_ok!(OrinqReceipts::attest_availability_cert(
                RuntimeOrigin::signed(acc(s)),
                rid,
                cert_hash
            ));
        }

        let per_signer = 114_285u128;
        let to_treasury = 200_005u128;

        for (i, &s) in committee_seeds.iter().enumerate() {
            let delta = Balances::free_balance(&acc(s)) - signer_before[i];
            let fee_share = delta - 10_000_000;
            assert_eq!(
                fee_share, per_signer,
                "signer {} should get {} fee share, got {}",
                s, per_signer, fee_share
            );
        }

        assert_eq!(
            Balances::free_balance(&treasury_account()) - treasury_before,
            to_treasury
        );
    });
}

#[test]
fn threshold_hit_single_signer_gets_full_80_percent() {
    // Edge case: N_signers == 1 means that signer receives 800_000 in one
    // lump. Test documents the behaviour explicitly so it's not a surprise.
    new_test_ext().execute_with(|| {
        let submitter_seed = 10;
        seed_submitter_and_committee(submitter_seed, &[1]);
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            vec![acc(1)],
            1
        ));

        let rid = H256::from([0xC1; 32]);
        let ch = H256::from([0xC2; 32]);
        assert_ok!(submit_c4(submitter_seed, rid, ch));

        let signer_before = Balances::free_balance(&acc(1));
        let treasury_before = Balances::free_balance(&treasury_account());

        assert_ok!(OrinqReceipts::attest_availability_cert(
            RuntimeOrigin::signed(acc(1)),
            rid,
            [0xCE; 32]
        ));

        // Whole 80% goes to the sole signer, 20% goes to treasury.
        let signer_delta = Balances::free_balance(&acc(1)) - signer_before;
        let fee_share = signer_delta - 10_000_000; // subtract attestation reward
        assert_eq!(fee_share, 800_000);
        assert_eq!(
            Balances::free_balance(&treasury_account()) - treasury_before,
            200_000
        );
    });
}

#[test]
fn threshold_hit_emits_fee_distributed_event() {
    new_test_ext().execute_with(|| {
        let submitter_seed = 10;
        let committee_seeds: Vec<u8> = (1u8..=3).collect();
        seed_submitter_and_committee(submitter_seed, &committee_seeds);
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            committee_seeds.iter().map(|&s| acc(s)).collect(),
            3
        ));

        let rid = H256::from([0xD1; 32]);
        let ch = H256::from([0xD2; 32]);
        assert_ok!(submit_c4(submitter_seed, rid, ch));
        for &s in committee_seeds.iter() {
            assert_ok!(OrinqReceipts::attest_availability_cert(
                RuntimeOrigin::signed(acc(s)),
                rid,
                [0xCE; 32]
            ));
        }

        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptFeeDistributed { total_fee, signer_count, .. }
                ) if *total_fee == DEFAULT_FEE && *signer_count == 3
            )
        });
        assert!(matched, "ReceiptFeeDistributed event must fire");
    });
}

#[test]
fn pre_component_4_receipt_skips_fee_payout() {
    // Simulate a receipt that exists without escrow (pre-Component-4 legacy).
    // The threshold-hit path must not panic; it must simply skip the fee
    // distribution and still finalize the cert.
    new_test_ext().execute_with(|| {
        let submitter = acc(10);
        Balances::make_free_balance_be(&submitter, 10_000_000_000);
        let committee_seeds = [1u8, 2];
        for &s in committee_seeds.iter() {
            Balances::make_free_balance_be(&acc(s), 10_000_000_000);
            assert_ok!(OrinqReceipts::bond(RuntimeOrigin::signed(acc(s)), 1_000_000_000));
            assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(acc(s))));
        }
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            committee_seeds.iter().map(|&s| acc(s)).collect(),
            2
        ));

        let rid = H256::from([0xE1; 32]);
        let ch = H256::from([0xE2; 32]);
        assert_ok!(submit_c4(10, rid, ch));

        // Wipe the escrow as though the receipt was submitted before
        // Component 4 landed.
        pallet::ReceiptFeeEscrow::<Test>::remove(rid);
        // Also clear the submitter's reserve to mirror legacy state.
        let _ = Balances::unreserve(&submitter, DEFAULT_FEE);

        // Certify — must not error.
        for &s in committee_seeds.iter() {
            assert_ok!(OrinqReceipts::attest_availability_cert(
                RuntimeOrigin::signed(acc(s)),
                rid,
                [0xCE; 32]
            ));
        }

        // Receipt is certified.
        let record = OrinqReceipts::receipts(rid).unwrap();
        assert_eq!(record.availability_cert_hash, [0xCE; 32]);
    });
}

#[test]
fn expired_receipt_refunds_submitter() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([0xF1; 32]);
        let ch = H256::from([0xF2; 32]);
        assert_ok!(submit_c4(1, rid, ch));
        assert_eq!(Balances::reserved_balance(&submitter), DEFAULT_FEE);

        // Fast-forward past expiry — default is 14400 blocks (~24h).
        let expiry = OrinqReceipts::receipt_expiry_blocks();
        System::set_block_number(1 + expiry as u32 + 1);

        // Anyone can call expire_receipt_fee.
        assert_ok!(OrinqReceipts::expire_receipt_fee(
            RuntimeOrigin::signed(acc(99)),
            rid
        ));

        // Reserve drained, escrow cleared, free balance restored.
        assert_eq!(Balances::reserved_balance(&submitter), 0);
        assert!(pallet::ReceiptFeeEscrow::<Test>::get(rid).is_none());
        assert_eq!(Balances::free_balance(&submitter), 10_000_000);

        // Event fired.
        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptFeeRefunded { amount, .. }
                ) if *amount == DEFAULT_FEE
            )
        });
        assert!(matched, "ReceiptFeeRefunded event must fire");
    });
}

#[test]
fn expire_before_deadline_fails() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([0x11; 32]);
        let ch = H256::from([0x12; 32]);
        assert_ok!(submit_c4(1, rid, ch));

        // Block has not advanced past expiry.
        assert_noop!(
            OrinqReceipts::expire_receipt_fee(RuntimeOrigin::signed(acc(99)), rid),
            pallet::Error::<Test>::ReceiptNotExpired
        );
    });
}

#[test]
fn expire_after_certification_fails() {
    // Once a receipt is certified the escrow is cleared by the payout path;
    // calling expire_receipt_fee must fail with a clear error rather than
    // silently no-oping.
    new_test_ext().execute_with(|| {
        let submitter_seed = 10;
        seed_submitter_and_committee(submitter_seed, &[1]);
        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            vec![acc(1)],
            1
        ));

        let rid = H256::from([0x21; 32]);
        let ch = H256::from([0x22; 32]);
        assert_ok!(submit_c4(submitter_seed, rid, ch));
        assert_ok!(OrinqReceipts::attest_availability_cert(
            RuntimeOrigin::signed(acc(1)),
            rid,
            [0xCE; 32]
        ));

        let expiry = OrinqReceipts::receipt_expiry_blocks();
        System::set_block_number(1 + expiry as u32 + 1);
        assert_noop!(
            OrinqReceipts::expire_receipt_fee(RuntimeOrigin::signed(acc(99)), rid),
            pallet::Error::<Test>::ReceiptAlreadyCertified
        );
    });
}

#[test]
fn set_fee_works_for_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_receipt_submission_fee(
            RuntimeOrigin::root(),
            5_000_000
        ));
        assert_eq!(OrinqReceipts::receipt_submission_fee(), 5_000_000);

        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptSubmissionFeeUpdated { new_value: 5_000_000 }
                )
            )
        });
        assert!(matched, "ReceiptSubmissionFeeUpdated event must fire");
    });
}

#[test]
fn set_fee_rejects_below_floor() {
    new_test_ext().execute_with(|| {
        // Default floor is 100_000. Setting fee below the floor must fail.
        assert_noop!(
            OrinqReceipts::set_receipt_submission_fee(RuntimeOrigin::root(), 50_000),
            pallet::Error::<Test>::FeeBelowFloor
        );
    });
}

#[test]
fn set_fee_root_only() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::set_receipt_submission_fee(
                RuntimeOrigin::signed(acc(1)),
                5_000_000
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_floor_works_for_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_receipt_submission_fee_floor(
            RuntimeOrigin::root(),
            250_000
        ));
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), 250_000);
    });
}

#[test]
fn set_floor_root_only() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            OrinqReceipts::set_receipt_submission_fee_floor(
                RuntimeOrigin::signed(acc(1)),
                250_000
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn raising_floor_above_current_fee_does_not_retroactively_invalidate() {
    // Governance setters are independent — raising the floor above the
    // current fee is allowed; the fee remains in place until the next
    // set_receipt_submission_fee call reconciles it. The invariant is on
    // *fee updates*, not on *floor updates*.
    new_test_ext().execute_with(|| {
        assert_ok!(OrinqReceipts::set_receipt_submission_fee_floor(
            RuntimeOrigin::root(),
            5_000_000
        ));
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), 5_000_000);
        // The fee is still 1_000_000, which is below the new floor — allowed.
        assert_eq!(OrinqReceipts::receipt_submission_fee(), 1_000_000);

        // But the next attempt to set_receipt_submission_fee below the floor fails.
        assert_noop!(
            OrinqReceipts::set_receipt_submission_fee(RuntimeOrigin::root(), 999_999),
            pallet::Error::<Test>::FeeBelowFloor
        );
        // At-floor is allowed.
        assert_ok!(OrinqReceipts::set_receipt_submission_fee(
            RuntimeOrigin::root(),
            5_000_000
        ));
    });
}

#[test]
fn migration_idempotent() {
    new_test_ext().execute_with(|| {
        use frame_support::traits::Hooks;

        // First run — a no-op because genesis already set both values.
        let _ = <OrinqReceipts as Hooks<_>>::on_runtime_upgrade();
        let fee_after_1 = OrinqReceipts::receipt_submission_fee();
        let floor_after_1 = OrinqReceipts::receipt_submission_fee_floor();

        // Second run must not change anything.
        let _ = <OrinqReceipts as Hooks<_>>::on_runtime_upgrade();
        assert_eq!(OrinqReceipts::receipt_submission_fee(), fee_after_1);
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), floor_after_1);

        // Explicitly zero-out storage to simulate a pre-Component-4 chain,
        // then run migration — it should populate the defaults.
        pallet::ReceiptSubmissionFee::<Test>::kill();
        pallet::ReceiptSubmissionFeeFloor::<Test>::kill();
        pallet::ReceiptExpiryBlocks::<Test>::kill();
        let _ = <OrinqReceipts as Hooks<_>>::on_runtime_upgrade();
        assert_eq!(OrinqReceipts::receipt_submission_fee(), DEFAULT_FEE);
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), DEFAULT_FLOOR);

        // Re-running must still be idempotent.
        let fee_a = OrinqReceipts::receipt_submission_fee();
        let floor_a = OrinqReceipts::receipt_submission_fee_floor();
        let _ = <OrinqReceipts as Hooks<_>>::on_runtime_upgrade();
        assert_eq!(OrinqReceipts::receipt_submission_fee(), fee_a);
        assert_eq!(OrinqReceipts::receipt_submission_fee_floor(), floor_a);
    });
}

// ---------------------------------------------------------------------------
// Security-review follow-ups (pre-merge hardening)
// ---------------------------------------------------------------------------

/// C1 — `set_availability_cert` must release the fee escrow so the submitter's
/// reserved balance does not remain stuck forever. The Root override has no
/// actual signers to reward, so the cleanest invariant is "refund the
/// submitter in full and emit `ReceiptFeeRefunded`", mirroring the expire
/// path.
#[test]
fn set_availability_cert_root_refunds_escrow_if_present() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([0x10; 32]);
        let ch = H256::from([0x20; 32]);

        // Regular Component-4 submission: escrow populated, balance reserved.
        assert_ok!(submit_c4(1, rid, ch));
        assert_eq!(Balances::reserved_balance(&submitter), DEFAULT_FEE);
        assert!(pallet::ReceiptFeeEscrow::<Test>::get(rid).is_some());
        assert!(pallet::ReceiptSubmittedAt::<Test>::get(rid).is_some());

        // Root-override cert'ifies the receipt directly.
        let cert = [0xCE; 32];
        assert_ok!(OrinqReceipts::set_availability_cert(
            RuntimeOrigin::root(),
            rid,
            cert
        ));

        // The receipt is certified.
        let record = OrinqReceipts::receipts(rid).unwrap();
        assert_eq!(record.availability_cert_hash, cert);

        // Critical invariants: the reserve MUST be released and escrow
        // storage MUST be cleared, otherwise the submitter's funds are
        // stranded (expire_receipt_fee would reject with ReceiptAlreadyCertified).
        assert_eq!(
            Balances::reserved_balance(&submitter), 0,
            "root override must unreserve submitter's fee"
        );
        assert_eq!(
            Balances::free_balance(&submitter), 10_000_000,
            "submitter's free balance must be restored in full"
        );
        assert!(
            pallet::ReceiptFeeEscrow::<Test>::get(rid).is_none(),
            "escrow map must be cleared"
        );
        assert!(
            pallet::ReceiptSubmittedAt::<Test>::get(rid).is_none(),
            "submitted-at anchor must be cleared"
        );

        // Refund event mirrors the expire-refund path for auditability.
        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptFeeRefunded { amount, .. }
                ) if *amount == DEFAULT_FEE
            )
        });
        assert!(
            matched,
            "ReceiptFeeRefunded event must fire so explorers can trace the refund"
        );
    });
}

/// C1 — When no escrow is present (pre-Component-4 / legacy receipt), the
/// Root override must still succeed and MUST NOT emit a spurious refund
/// event or touch any reserve. Preserves the existing behaviour for
/// receipts that predate fee escrow.
#[test]
fn set_availability_cert_root_without_escrow_is_noop_on_refund_path() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([0x30; 32]);
        let ch = H256::from([0x31; 32]);
        assert_ok!(submit_c4(1, rid, ch));

        // Simulate a legacy receipt: wipe escrow but leave the on-chain
        // receipt record in place.
        pallet::ReceiptFeeEscrow::<Test>::remove(rid);
        pallet::ReceiptSubmittedAt::<Test>::remove(rid);
        let _ = Balances::unreserve(&submitter, DEFAULT_FEE);

        // Snapshot events-pre so we can diff just the override's effects.
        let events_before = frame_system::Pallet::<Test>::events().len();

        assert_ok!(OrinqReceipts::set_availability_cert(
            RuntimeOrigin::root(),
            rid,
            [0xCE; 32]
        ));

        // No refund event fires when there was no escrow to refund.
        let refund_after = frame_system::Pallet::<Test>::events()
            .iter()
            .skip(events_before)
            .any(|r| matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(crate::Event::ReceiptFeeRefunded { .. })
            ));
        assert!(!refund_after, "no refund event should fire when no escrow present");
    });
}

/// I1 — `submit_receipt` MUST emit a `ReceiptFeeReserved` event so auditors
/// have a direct on-chain trace of the reservation (current `ReceiptSubmitted`
/// says nothing about the fee or the escrow, which makes sampling tooling
/// brittle).
#[test]
fn submit_receipt_emits_fee_reserved_event() {
    new_test_ext().execute_with(|| {
        let submitter = acc(1);
        Balances::make_free_balance_be(&submitter, 10_000_000);
        let rid = H256::from([0x40; 32]);
        let ch = H256::from([0x41; 32]);

        assert_ok!(submit_c4(1, rid, ch));

        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptFeeReserved { receipt_id, amount, .. }
                ) if *receipt_id == rid && *amount == DEFAULT_FEE
            )
        });
        assert!(
            matched,
            "ReceiptFeeReserved event must fire on successful submit_receipt"
        );
    });
}

/// I2 — `set_receipt_expiry_blocks` must reject values below the minimum
/// (10 blocks). A compromised root key could otherwise set expiry=0 and
/// race-refund in-flight submissions whose signers are mid-attestation,
/// stealing the submitter→signer fee flow.
#[test]
fn set_receipt_expiry_blocks_rejects_below_minimum() {
    new_test_ext().execute_with(|| {
        // 0 is the worst case — must be rejected.
        assert_noop!(
            OrinqReceipts::set_receipt_expiry_blocks(RuntimeOrigin::root(), 0),
            pallet::Error::<Test>::ReceiptExpiryBlocksTooLow
        );
        // Anything below the constant must also be rejected.
        assert_noop!(
            OrinqReceipts::set_receipt_expiry_blocks(
                RuntimeOrigin::root(),
                pallet::MIN_RECEIPT_EXPIRY_BLOCKS - 1
            ),
            pallet::Error::<Test>::ReceiptExpiryBlocksTooLow
        );
        // Exactly at the minimum is allowed.
        assert_ok!(OrinqReceipts::set_receipt_expiry_blocks(
            RuntimeOrigin::root(),
            pallet::MIN_RECEIPT_EXPIRY_BLOCKS
        ));
        assert_eq!(
            OrinqReceipts::receipt_expiry_blocks(),
            pallet::MIN_RECEIPT_EXPIRY_BLOCKS
        );
        // And above-minimum still works.
        assert_ok!(OrinqReceipts::set_receipt_expiry_blocks(
            RuntimeOrigin::root(),
            100
        ));
        assert_eq!(OrinqReceipts::receipt_expiry_blocks(), 100);
    });
}

/// I3 — If the treasury pot is below ED at payout, `repatriate_reserved`
/// silently returns the amount un-moved. Without the fix, the submitter's
/// reserve would remain stuck AND the event would report a treasury_amount
/// that was never transferred. The fix must refund the remainder to the
/// submitter and emit an event whose `treasury_amount` reflects what
/// actually moved.
#[test]
fn treasury_pot_below_ed_refunds_remainder_to_submitter() {
    new_test_ext().execute_with(|| {
        // 5-member committee, threshold 3; 3 signers actually attest.
        // Per-signer = 266_666, to_treasury = 200_002 on DEFAULT_FEE.
        let submitter_seed = 10;
        let committee_seeds: Vec<u8> = (1u8..=5).collect();

        // Seed: submitter funded; committee bonded + joined; but
        // explicitly DO NOT pre-fund the treasury pot. With ED=1 and a
        // zero balance, the 200_002 repatriation will silently keep the
        // funds reserved on the submitter (the pot can't be opened below ED).
        Balances::make_free_balance_be(&acc(submitter_seed), 10_000_000_000);
        for &s in committee_seeds.iter() {
            Balances::make_free_balance_be(&acc(s), 10_000_000_000);
            assert_ok!(OrinqReceipts::bond(
                RuntimeOrigin::signed(acc(s)),
                1_000_000_000
            ));
            assert_ok!(OrinqReceipts::join_committee(RuntimeOrigin::signed(acc(s))));
        }
        // Treasury pot explicitly drained below ED.
        Balances::make_free_balance_be(&treasury_account(), 0);
        assert_eq!(Balances::free_balance(&treasury_account()), 0);

        assert_ok!(OrinqReceipts::set_committee(
            RuntimeOrigin::root(),
            committee_seeds.iter().map(|&s| acc(s)).collect(),
            3
        ));

        let rid = H256::from([0x50; 32]);
        let ch = H256::from([0x51; 32]);
        assert_ok!(submit_c4(submitter_seed, rid, ch));
        assert_eq!(
            Balances::reserved_balance(&acc(submitter_seed)),
            DEFAULT_FEE
        );

        let submitter_free_before = Balances::free_balance(&acc(submitter_seed));

        // Three signers attest — threshold hits.
        let signer_seeds = [1u8, 2, 3];
        for &s in signer_seeds.iter() {
            assert_ok!(OrinqReceipts::attest_availability_cert(
                RuntimeOrigin::signed(acc(s)),
                rid,
                [0xCE; 32]
            ));
        }

        // Invariant 1: submitter's reserve is fully drained. Without the
        // fix the treasury share would still be held.
        assert_eq!(
            Balances::reserved_balance(&acc(submitter_seed)),
            0,
            "submitter's full reserve must be released regardless of treasury state"
        );

        // Invariant 2: submitter's free balance reflects refund of the
        // treasury share (since the pot was below ED).
        let expected_refund = 200_002u128; // 20% + dust
        assert_eq!(
            Balances::free_balance(&acc(submitter_seed)),
            submitter_free_before + expected_refund,
            "submitter must be refunded the un-moved treasury share"
        );

        // Invariant 3: the event reports actual_treasury_moved (0 in this
        // case), not the requested 200_002.
        let events = frame_system::Pallet::<Test>::events();
        let matched = events.iter().any(|r| {
            matches!(
                &r.event,
                RuntimeEvent::OrinqReceipts(
                    crate::Event::ReceiptFeeDistributed { treasury_amount, .. }
                ) if *treasury_amount == 0
            )
        });
        assert!(
            matched,
            "event must report treasury_amount=0 when the pot was below ED"
        );
    });
}

// ---------------------------------------------------------------------------
// Validator emission — 85/15 validator/treasury split (2026-04-21)
// ---------------------------------------------------------------------------
//
// Under the Midnight-style fee redesign, MATRA is no longer charged on
// transactions, so the 20% fee-router treasury feed is gone. To compensate,
// 15% of each era's validator emission (the 102.74 MATRA/era pre-allocated
// reserve distribution) is redirected to the treasury PalletId (`mat/trsy`).
// The remaining 85% is distributed pro-rata by blocks authored, unchanged.
//
// Rounding residue from floor(reward * 85 / 100) and floor(reward * 15 / 100)
// goes to TREASURY (the safer sink) rather than validators.

#[cfg(test)]
mod era_emission_drip {
    use super::*;
    use frame_support::traits::Hooks;
    use sp_runtime::traits::AccountIdConversion;

    const ERA_LENGTH: u32 = 14_400;
    const REWARD_PER_ERA: u128 = 102_739_726;

    fn validator_a() -> MockAccountId {
        acc(0xA1)
    }

    fn treasury_pot() -> MockAccountId {
        let pid: PalletId = TreasuryPotId::get();
        pid.into_account_truncating()
    }

    /// Seed one validator as the sole author of an entire era, then trip
    /// the era boundary by calling on_initialize at block ERA_LENGTH+1.
    /// Returns (validator_delta, treasury_delta) in MATRA base units.
    fn run_one_era_with_single_author() -> (u128, u128) {
        // Drive BlocksAuthored directly — the production `find_block_author`
        // path requires Aura digests, which would be noise for this test.
        // We're testing the SPLIT logic, not the author-identification logic
        // (which is unchanged from pre-fix).
        pallet::BlocksAuthored::<Test>::insert(&validator_a(), ERA_LENGTH);
        pallet::EraStartBlock::<Test>::put(1u32);

        let pre_validator = Balances::free_balance(&validator_a());
        let pre_trsy = Balances::free_balance(&treasury_pot());

        // Advance System block number past the era boundary so
        // `block_num - era_start >= ERA_LENGTH` fires.
        System::set_block_number(ERA_LENGTH + 2);
        let _ = <OrinqReceipts as Hooks<_>>::on_initialize(ERA_LENGTH + 2);

        let post_validator = Balances::free_balance(&validator_a());
        let post_trsy = Balances::free_balance(&treasury_pot());
        (
            post_validator.saturating_sub(pre_validator),
            post_trsy.saturating_sub(pre_trsy),
        )
    }

    #[test]
    fn era_emission_splits_85_validator_15_treasury() {
        new_test_ext().execute_with(|| {
            // Pre-fund treasury pot at ED so sub-ED deposits don't fail the
            // account-existence check; test asserts deltas, not absolutes.
            Balances::make_free_balance_be(&treasury_pot(), 1_000);
            let pre_trsy = Balances::free_balance(&treasury_pot());

            let (validator_delta, treasury_delta) = run_one_era_with_single_author();

            // With a SINGLE author, pro-rata reduces to: validator gets the
            // full 85% share, treasury gets the 15% share, and any rounding
            // residue must end up in treasury (not lost, not to validator).
            let expected_validator = REWARD_PER_ERA.saturating_mul(85) / 100;
            let expected_treasury_min = REWARD_PER_ERA.saturating_mul(15) / 100;

            assert_eq!(
                validator_delta,
                expected_validator,
                "sole validator must receive exactly floor(reward * 85 / 100)"
            );

            // Total distributed to the two buckets must equal the full era
            // reward — no MATRA leaks to burn or nowhere.
            assert_eq!(
                validator_delta + treasury_delta,
                REWARD_PER_ERA,
                "sum of validator + treasury emissions must equal full era reward (no leak)"
            );

            // Treasury delta is at least the floor 15% share; with rounding
            // residue it can be strictly greater. The exact distribution is:
            //   validator = floor(102_739_726 * 85 / 100) = 87_328_767
            //   treasury  = 102_739_726 - 87_328_767     = 15_410_959
            // (HIGH #3 fix 2026-04-21: this comment previously said the
            // validator got 87_328_766 / treasury got 15_410_960, which was
            // off-by-one — the assertion in
            // `era_emission_rounding_residue_goes_to_treasury_not_validator`
            // is, correctly, 87_328_767 / 15_410_959.)
            //
            // The old expected pre-migration behaviour was:
            //   validator = 102_739_726 (full reward to author)
            //   treasury  = 0
            assert!(
                treasury_delta >= expected_treasury_min,
                "treasury must receive >= floor(reward * 15 / 100); got {} expected >= {}",
                treasury_delta, expected_treasury_min,
            );
            let _ = pre_trsy; // kept for debugging failure output
        });
    }

    #[test]
    fn era_emission_rounding_residue_goes_to_treasury_not_validator() {
        // Pin down the exact rounding behavior so a future refactor can't
        // silently flip the residue to the validator side.
        new_test_ext().execute_with(|| {
            Balances::make_free_balance_be(&treasury_pot(), 1_000);
            let (validator_delta, treasury_delta) = run_one_era_with_single_author();

            // 102_739_726 * 85 = 8_732_876_710; / 100 = 87_328_767 (rem 10).
            //   validator = floor(reward * 85 / 100) = 87_328_767
            //   treasury  = reward - validator        = 15_410_959 (includes residue of 10)
            //
            // Pre-fix expected: validator=102_739_726, treasury=0. Preserved
            // in this comment for reviewer traceability.
            let expected_validator: u128 = 87_328_767;
            let expected_treasury: u128 = 15_410_959;
            assert_eq!(validator_delta, expected_validator);
            assert_eq!(treasury_delta, expected_treasury);
        });
    }

    #[test]
    fn era_emission_split_matra_issuance_net_increases_by_full_reward() {
        // Validator + treasury emissions are `deposit_creating`, i.e. MATRA
        // is MINTED from the pre-allocated reserve (the 150M pool). So total
        // issuance goes UP by exactly the full era reward — no burn path.
        new_test_ext().execute_with(|| {
            Balances::make_free_balance_be(&treasury_pot(), 1_000);
            let pre_issuance = Balances::total_issuance();
            let _ = run_one_era_with_single_author();
            let post_issuance = Balances::total_issuance();
            assert_eq!(
                post_issuance - pre_issuance,
                REWARD_PER_ERA,
                "total_issuance must rise by exactly REWARD_PER_ERA after the era boundary"
            );
        });
    }

    #[test]
    fn era_emission_multi_validator_pro_rata_plus_residue_to_treasury() {
        // 3-validator scenario to verify the 85% pro-rata split still works
        // and residue from pro-rata rounding goes to treasury.
        new_test_ext().execute_with(|| {
            Balances::make_free_balance_be(&treasury_pot(), 1_000);

            let v1 = acc(0xB1);
            let v2 = acc(0xB2);
            let v3 = acc(0xB3);
            // Non-divisible-by-3 counts to exercise pro-rata rounding.
            pallet::BlocksAuthored::<Test>::insert(&v1, 5_000u32);
            pallet::BlocksAuthored::<Test>::insert(&v2, 5_000u32);
            pallet::BlocksAuthored::<Test>::insert(&v3, 4_400u32);
            pallet::EraStartBlock::<Test>::put(1u32);

            let pre_trsy = Balances::free_balance(&treasury_pot());

            System::set_block_number(ERA_LENGTH + 2);
            let _ = <OrinqReceipts as Hooks<_>>::on_initialize(ERA_LENGTH + 2);

            let got_v1 = Balances::free_balance(&v1);
            let got_v2 = Balances::free_balance(&v2);
            let got_v3 = Balances::free_balance(&v3);
            let got_trsy = Balances::free_balance(&treasury_pot());

            let validator_pool = REWARD_PER_ERA.saturating_mul(85) / 100;
            let total_blocks: u128 = 14_400;

            // Each validator gets floor(validator_pool * their_blocks / total).
            let expected_v1 = validator_pool * 5_000 / total_blocks;
            let expected_v2 = validator_pool * 5_000 / total_blocks;
            let expected_v3 = validator_pool * 4_400 / total_blocks;
            assert_eq!(got_v1, expected_v1);
            assert_eq!(got_v2, expected_v2);
            assert_eq!(got_v3, expected_v3);

            let paid_to_validators = got_v1 + got_v2 + got_v3;
            let expected_trsy_delta = REWARD_PER_ERA - paid_to_validators;

            assert_eq!(
                got_trsy - pre_trsy,
                expected_trsy_delta,
                "treasury receives 15% nominal + all pro-rata residue"
            );
            assert_eq!(
                paid_to_validators + (got_trsy - pre_trsy),
                REWARD_PER_ERA,
                "full era reward conserved across validators + treasury"
            );
        });
    }

    #[test]
    fn era_emission_respects_configurable_treasury_share() {
        // HIGH #2: `TreasuryEmissionShare` must be a real runtime-tunable
        // `Get<Perbill>` — NOT a hardcoded `Perbill::from_percent(15)` in
        // the pallet hook. Proof: override the share in the mock runtime
        // and assert the validator/treasury split tracks the new value.
        //
        // This test drives the Config-trait refactor per TDD: it sets
        // `TreasuryEmissionShare` to 20% (and then 10%) via a mutable
        // `parameter_types!` static and verifies the math follows.
        //
        // If `TreasuryEmissionShare` is hardcoded at 15% anywhere in the
        // hook, both sub-cases below will fail with validator_delta ==
        // floor(reward * 85 / 100) regardless of the configured share.
        use sp_runtime::Perbill;

        // Sub-case 1: 20% treasury share ⇒ 80% validator.
        TreasuryEmissionShareValue::set(Perbill::from_percent(20));
        new_test_ext().execute_with(|| {
            Balances::make_free_balance_be(&treasury_pot(), 1_000);
            let (validator_delta, treasury_delta) = run_one_era_with_single_author();
            let expected_validator = REWARD_PER_ERA.saturating_mul(80) / 100;
            let expected_treasury = REWARD_PER_ERA.saturating_sub(expected_validator);
            assert_eq!(
                validator_delta, expected_validator,
                "at 20% treasury share, sole validator must receive floor(reward * 80 / 100)"
            );
            assert_eq!(
                treasury_delta, expected_treasury,
                "at 20% treasury share, treasury must receive reward - validator_pool"
            );
            assert_eq!(
                validator_delta + treasury_delta, REWARD_PER_ERA,
                "split at 20% must still conserve the full era reward"
            );
        });

        // Sub-case 2: 10% treasury share ⇒ 90% validator.
        TreasuryEmissionShareValue::set(Perbill::from_percent(10));
        new_test_ext().execute_with(|| {
            Balances::make_free_balance_be(&treasury_pot(), 1_000);
            let (validator_delta, treasury_delta) = run_one_era_with_single_author();
            let expected_validator = REWARD_PER_ERA.saturating_mul(90) / 100;
            let expected_treasury = REWARD_PER_ERA.saturating_sub(expected_validator);
            assert_eq!(
                validator_delta, expected_validator,
                "at 10% treasury share, sole validator must receive floor(reward * 90 / 100)"
            );
            assert_eq!(
                treasury_delta, expected_treasury,
                "at 10% treasury share, treasury must receive reward - validator_pool"
            );
        });

        // Reset to the documented default so subsequent tests (if any run
        // after this in the same process) observe the 15/85 baseline.
        TreasuryEmissionShareValue::set(Perbill::from_percent(15));
    }
}
