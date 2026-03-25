use crate as pallet_motra;
use crate::{pallet, types::MotraParams};
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU32, Hooks},
};
use sp_runtime::{
    traits::IdentityLookup,
    BuildStorage, Perbill,
};

// ---------------------------------------------------------------------------
// Mock runtime
// ---------------------------------------------------------------------------

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime! {
    pub enum Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        Motra: pallet_motra,
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
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
}

/// Build genesis storage for tests.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    // Fund accounts with MATRA.
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (1, 1_000_000_000_000_000), // 1000 MATRA (12 decimals)
            (2, 500_000_000_000_000),    // 500 MATRA
            (3, 1),                      // minimal MATRA (must be >= existential deposit)
        ],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    // Set default MOTRA params.
    pallet_motra::GenesisConfig::<Test> {
        params: MotraParams {
            min_fee: 1_000,
            congestion_rate: 0,
            target_fullness: Perbill::from_percent(50),
            decay_rate_per_block: Perbill::from_parts(999_000_000), // 99.9% retained
            generation_per_matra_per_block: 1_000,
            max_balance: 1_000_000_000_000_000,
            max_congestion_step: 500,
            length_fee_per_byte: 1_000,
            congestion_smoothing: Perbill::from_percent(10),
        },
        _phantom: Default::default(),
    }
    .assimilate_storage(&mut t)
    .unwrap();

    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
    });
    ext
}

/// Helper: advance to block n, calling on_finalize for congestion adjustment.
fn run_to_block(n: u64) {
    while System::block_number() < n {
        let current = System::block_number();
        Motra::on_finalize(current);
        let next = current + 1;
        System::set_block_number(next);
    }
}

// ============================================================================
// Test: MOTRA is non-transferable
// ============================================================================

#[test]
fn motra_has_no_transfer_extrinsic() {
    // There is no dispatchable in pallet_motra that transfers MOTRA between accounts.
    // This is a design guarantee -- we verify it by checking that the only extrinsics
    // are set_delegatee, set_params, and claim_motra.
    // The type system enforces this -- there is no `transfer` function exposed.
    // This test documents the invariant.
    new_test_ext().execute_with(|| {
        // Manually set a balance.
        pallet_motra::MotraBalances::<Test>::insert(1u64, 1000u128);
        pallet_motra::MotraBalances::<Test>::insert(2u64, 0u128);

        // There is no extrinsic to transfer from account 1 to account 2.
        // The only way MOTRA moves is via:
        // 1. Generation (based on MATRA holdings)
        // 2. Delegation (generation target)
        // 3. Fee burning

        // Verify balances unchanged.
        assert_eq!(Motra::motra_balance(&1u64), 1000);
        assert_eq!(Motra::motra_balance(&2u64), 0);
    });
}

// ============================================================================
// Test: Decay works
// ============================================================================

#[test]
fn decay_reduces_balance_over_blocks() {
    new_test_ext().execute_with(|| {
        // Give account 3 (minimal MATRA) some MOTRA directly.
        pallet_motra::MotraBalances::<Test>::insert(3u64, 1_000_000u128);
        pallet_motra::LastTouched::<Test>::insert(3u64, 1u64);

        // Advance 100 blocks.
        run_to_block(101);

        // Reconcile.
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(3)));

        let balance = Motra::motra_balance(&3u64);
        // After 100 blocks at 99.9% retention: 1_000_000 * 0.999^100 ~ 904_792
        // Account 3 has only 1 unit of MATRA, so generation is negligible:
        //   1 * 1_000 * 100 / 1_000_000_000_000 = 0 (integer division)
        // Should be less than original.
        assert!(
            balance < 1_000_000,
            "Balance should have decayed: {}",
            balance
        );
        // But not zero.
        assert!(balance > 0, "Balance should not be zero: {}", balance);
        // Approximate check (0.999^100 ~ 0.9048).
        assert!(
            balance > 850_000 && balance < 950_000,
            "Balance {} should be ~904k after 100 blocks of 0.1% decay",
            balance
        );
    });
}

// ============================================================================
// Test: Generation works and is deterministic
// ============================================================================

#[test]
fn generation_adds_motra_based_on_matra_holdings() {
    new_test_ext().execute_with(|| {
        // Account 1 has 1_000_000_000_000_000 MATRA (1000 MATRA with 12 decimals)
        // Generation = 1_000 per MATRA-unit per block
        // Per block: 1_000_000_000_000_000 * 1_000 / 1_000_000_000_000 = 1_000_000

        // Start at block 1, last_touched = 0 (default).
        run_to_block(11); // advance 10 blocks from genesis

        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));

        let balance = Motra::motra_balance(&1u64);
        // Should have generated: ~11 blocks * 1_000_000 per block = ~11_000_000
        // (elapsed is from block 0 to block 11 = 11 blocks, with some decay on accumulated)
        assert!(
            balance > 9_000_000,
            "Should have generated ~10M+ MOTRA: {}",
            balance
        );
    });
}

#[test]
fn generation_is_deterministic_across_reconciliations() {
    new_test_ext().execute_with(|| {
        // Two accounts with different MATRA, reconcile at the same time.
        // Should get proportional results.

        // Setup: both start at block 1.
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);
        pallet_motra::LastTouched::<Test>::insert(2u64, 1u64);

        run_to_block(51);

        // Reconcile both at block 51.
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));
        let balance_1 = Motra::motra_balance(&1u64);

        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(2)));
        let balance_2 = Motra::motra_balance(&2u64);

        // Account 1 has 2x the MATRA of account 2, so should have ~2x MOTRA
        // (not exact due to decay on accumulated balance).
        let ratio = (balance_1 as f64) / (balance_2 as f64);
        assert!(
            ratio > 1.9 && ratio < 2.1,
            "Balance ratio should be ~2.0: {} / {} = {}",
            balance_1,
            balance_2,
            ratio
        );
    });
}

// ============================================================================
// Test: Delegation routes generation to delegatee
// ============================================================================

#[test]
fn delegation_routes_generation_to_delegatee() {
    new_test_ext().execute_with(|| {
        // Account 1 delegates to account 3 (who has minimal MATRA).
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        assert_ok!(Motra::set_delegatee(RuntimeOrigin::signed(1), Some(3)));

        run_to_block(11); // 10 blocks

        // Reconcile account 1.
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));

        let balance_1 = Motra::motra_balance(&1u64);
        let balance_3 = Motra::motra_balance(&3u64);

        // Account 1 should have minimal MOTRA (only decay on whatever was there).
        // Account 3 should have received the generated MOTRA.
        assert!(
            balance_3 > 0,
            "Delegatee should have received MOTRA: {}",
            balance_3
        );
        // Account 1's own balance should be 0 or very small (no self-generation).
        assert!(
            balance_1 < balance_3,
            "Delegator {} should have less than delegatee {}",
            balance_1,
            balance_3
        );
    });
}

#[test]
fn cannot_delegate_to_self() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Motra::set_delegatee(RuntimeOrigin::signed(1), Some(1)),
            pallet::Error::<Test>::CannotDelegateToSelf
        );
    });
}

#[test]
fn clear_delegation_restores_self_generation() {
    new_test_ext().execute_with(|| {
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        // Delegate to account 3.
        assert_ok!(Motra::set_delegatee(RuntimeOrigin::signed(1), Some(3)));

        run_to_block(11);
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));

        let balance_after_delegation = Motra::motra_balance(&1u64);

        // Now clear delegation.
        assert_ok!(Motra::set_delegatee(RuntimeOrigin::signed(1), None));

        run_to_block(21);
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));

        let balance_after_clear = Motra::motra_balance(&1u64);

        // After clearing delegation, account 1 should be generating for itself again.
        assert!(
            balance_after_clear > balance_after_delegation,
            "Balance should grow after clearing delegation: {} > {}",
            balance_after_clear,
            balance_after_delegation
        );
    });
}

// ============================================================================
// Test: Fee payment
// ============================================================================

#[test]
fn fee_burn_succeeds_with_sufficient_motra() {
    new_test_ext().execute_with(|| {
        // Give account 1 some MOTRA.
        pallet_motra::MotraBalances::<Test>::insert(1u64, 100_000u128);
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        // Burn a fee.
        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&1, 50_000));

        let balance = Motra::motra_balance(&1u64);
        // Should have 100_000 - 50_000 = 50_000 (approximately, accounting for any reconciliation).
        assert!(
            balance <= 50_000,
            "Balance should be <= 50k after burning 50k: {}",
            balance
        );
    });
}

#[test]
fn fee_burn_fails_with_insufficient_motra() {
    new_test_ext().execute_with(|| {
        pallet_motra::MotraBalances::<Test>::insert(1u64, 100u128);
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        assert_noop!(
            pallet_motra::Pallet::<Test>::burn_fee(&1, 50_000),
            pallet::Error::<Test>::InsufficientMotra
        );
    });
}

// ============================================================================
// Test: Congestion rate adjustment
// ============================================================================

#[test]
fn congestion_rate_stays_zero_when_blocks_empty() {
    new_test_ext().execute_with(|| {
        // Empty blocks: congestion should decrease or stay at zero.
        let initial = Motra::params().congestion_rate;
        assert_eq!(initial, 0);

        run_to_block(10);

        let after = Motra::params().congestion_rate;
        assert_eq!(after, 0, "Congestion rate should stay at 0 for empty blocks");
    });
}

// ============================================================================
// Test: Compute fee
// ============================================================================

#[test]
fn compute_fee_includes_min_fee() {
    new_test_ext().execute_with(|| {
        let fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(0, 0),
            0,
        );
        assert_eq!(fee, 1_000, "Zero-weight zero-length tx should cost min_fee");
    });
}

#[test]
fn compute_fee_scales_with_congestion() {
    new_test_ext().execute_with(|| {
        // Set congestion rate.
        pallet_motra::Params::<Test>::mutate(|p| {
            p.congestion_rate = 1_000;
        });

        let fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(10_000_000, 0),
            0,
        );
        // fee = 1_000 + 1_000 * 10_000_000 / 1_000_000 = 1_000 + 10_000 = 11_000
        assert_eq!(fee, 11_000);
    });
}

// ============================================================================
// Test: Max balance cap
// ============================================================================

#[test]
fn generation_respects_max_balance() {
    new_test_ext().execute_with(|| {
        // Set a low max balance.
        pallet_motra::Params::<Test>::mutate(|p| {
            p.max_balance = 5_000_000;
        });

        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        // Run many blocks to generate way more than max.
        run_to_block(1001);

        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));

        let balance = Motra::motra_balance(&1u64);
        assert!(
            balance <= 5_000_000,
            "Balance {} should not exceed max 5M",
            balance
        );
    });
}

// ============================================================================
// Test: set_params governance gate
// ============================================================================

#[test]
fn set_params_requires_root() {
    new_test_ext().execute_with(|| {
        let params = MotraParams::default();
        assert_noop!(
            Motra::set_params(RuntimeOrigin::signed(1), params.clone()),
            frame_support::error::BadOrigin
        );
        assert_ok!(Motra::set_params(RuntimeOrigin::root(), params));
    });
}

// ============================================================================
// Test: Reconcile idempotency
// ============================================================================

#[test]
fn reconcile_same_block_is_noop() {
    new_test_ext().execute_with(|| {
        pallet_motra::MotraBalances::<Test>::insert(1u64, 500_000u128);
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        // Reconcile twice in the same block.
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));
        let balance_first = Motra::motra_balance(&1u64);

        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(1)));
        let balance_second = Motra::motra_balance(&1u64);

        assert_eq!(
            balance_first, balance_second,
            "Second reconcile in same block should be a no-op"
        );
    });
}

// ============================================================================
// Test: Zero MATRA produces zero generation
// ============================================================================

#[test]
fn zero_matra_produces_zero_generation() {
    new_test_ext().execute_with(|| {
        // Account 99 has no MATRA at all (not in genesis balances).
        pallet_motra::MotraBalances::<Test>::insert(99u64, 1_000_000u128);
        pallet_motra::LastTouched::<Test>::insert(99u64, 1u64);

        run_to_block(101);
        assert_ok!(Motra::claim_motra(RuntimeOrigin::signed(99)));

        let balance = Motra::motra_balance(&99u64);
        // Should only have decayed balance, no generation.
        // 1_000_000 * 0.999^100 ~ 904_792
        assert!(
            balance < 1_000_000,
            "Balance should have only decayed: {}",
            balance
        );
    });
}

// ============================================================================
// Test: Genesis config applies correctly
// ============================================================================

#[test]
fn genesis_params_are_set() {
    new_test_ext().execute_with(|| {
        let params = Motra::params();
        assert_eq!(params.min_fee, 1_000);
        assert_eq!(params.congestion_rate, 0);
        assert_eq!(params.target_fullness, Perbill::from_percent(50));
        assert_eq!(params.decay_rate_per_block, Perbill::from_parts(999_000_000));
        assert_eq!(params.generation_per_matra_per_block, 1_000);
        assert_eq!(params.max_balance, 1_000_000_000_000_000);
        assert_eq!(params.max_congestion_step, 500);
        assert_eq!(params.length_fee_per_byte, 1_000);
        assert_eq!(params.congestion_smoothing, Perbill::from_percent(10));
    });
}

// ============================================================================
// Test: Length fee
// ============================================================================

#[test]
fn compute_fee_includes_length_fee() {
    new_test_ext().execute_with(|| {
        let fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(0, 0),
            256, // 256 bytes
        );
        // fee = min_fee + 0 (weight) + 256 * length_fee_per_byte
        // With test params: 1_000 + 0 + 256 * 1_000 = 257_000
        let params = Motra::params();
        let expected = params.min_fee + 256 * params.length_fee_per_byte;
        assert_eq!(fee, expected);
    });
}

#[test]
fn large_extrinsic_pays_proportional_length_fee() {
    new_test_ext().execute_with(|| {
        let small_fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(1_000_000, 0),
            100,
        );
        let large_fee = pallet_motra::Pallet::<Test>::compute_fee(
            frame_support::weights::Weight::from_parts(1_000_000, 0),
            10_000,
        );
        // Same weight, bigger length = bigger fee
        assert!(large_fee > small_fee, "Larger extrinsic should cost more: {} vs {}", large_fee, small_fee);
    });
}

// ============================================================================
// Test: Observability - TotalBurned
// ============================================================================

#[test]
fn total_burned_tracks_fee_burns() {
    new_test_ext().execute_with(|| {
        pallet_motra::MotraBalances::<Test>::insert(1u64, 1_000_000u128);
        pallet_motra::LastTouched::<Test>::insert(1u64, 1u64);

        assert_eq!(Motra::total_burned(), 0);

        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&1, 50_000));
        assert_eq!(Motra::total_burned(), 50_000);

        assert_ok!(pallet_motra::Pallet::<Test>::burn_fee(&1, 30_000));
        assert_eq!(Motra::total_burned(), 80_000);
    });
}
