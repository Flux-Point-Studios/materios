//! Unit tests for `pallet-billing`.
//!
//! These cover the Phase 2.A contract surface:
//! - topup correctly burns MATRA + credits Balances
//! - pay_request is idempotent on request_id
//! - pay_request respects max_charge
//! - pay_request is dry-run while DebitsEnabled is false (2.A measurement)
//! - withdrawal cooldown enforced
//! - re-requesting withdrawal cancels the prior + restarts the clock
//! - PerByte pricing scales with request_bytes
//! - Endpoint class length cap enforced
//!
//! Real benchmark-derived weights, multi-block scenarios, and pallet-motra
//! integration tests come in 2.B.

use crate as pallet_billing;
use crate::types::{PricingModel, WITHDRAWAL_COOLDOWN_BLOCKS};
use crate::Error;

use frame_support::{
    assert_err, assert_noop, assert_ok,
    parameter_types,
    traits::{ConstU16, ConstU32, ConstU64},
};
use frame_system as system;
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

type Block = frame_system::mocking::MockBlock<TestRuntime>;
type Balance = u128;

frame_support::construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
        Balances: pallet_balances,
        Billing: pallet_billing,
    }
);

impl system::Config for TestRuntime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type RuntimeTask = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for TestRuntime {
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ConstU32<10>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
}

parameter_types! {
    // Short retention for tests — 100 blocks. Real runtime uses 14_400.
    pub const RequestIdRetentionBlocks: u64 = 100;
}

impl pallet_billing::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type MatraCurrency = Balances;
    type GovernanceOrigin = frame_system::EnsureRoot<u64>;
    type RequestIdRetentionBlocks = RequestIdRetentionBlocks;
    // Small cap so the positive/negative tests can exercise the boundary
    // without standing up 256 dummy entries. Real runtime uses 256.
    type MaxPruneBatch = ConstU32<8>;
    type WeightInfo = ();
}

const ALICE: u64 = 1;
const BOB: u64 = 2;
const TREASURY: u64 = 999;

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<TestRuntime> {
        balances: vec![(ALICE, 10_000_000), (BOB, 10_000_000), (TREASURY, 100_000_000)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn enable_debits() {
    assert_ok!(Billing::governance_set_debits_enabled(
        RuntimeOrigin::root(),
        true
    ));
    assert!(Billing::debits_enabled());
}

// ---------------------------------------------------------------------------
// Topup
// ---------------------------------------------------------------------------

#[test]
fn topup_self_burns_matra_and_credits_billing_balance() {
    new_test_ext().execute_with(|| {
        let initial_matra = Balances::free_balance(&ALICE);
        let initial_billing = Billing::balance_of(&ALICE);
        assert_eq!(initial_billing, 0);

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));

        assert_eq!(Balances::free_balance(&ALICE), initial_matra - 100_000);
        assert_eq!(Billing::balance_of(&ALICE), 100_000);
    });
}

#[test]
fn topup_for_credits_target_not_caller() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_for(
            RuntimeOrigin::signed(ALICE),
            BOB,
            50_000
        ));
        assert_eq!(Billing::balance_of(&BOB), 50_000);
        assert_eq!(Billing::balance_of(&ALICE), 0);
        assert_eq!(Balances::free_balance(&ALICE), 10_000_000 - 50_000);
    });
}

#[test]
fn topup_fails_if_caller_has_insufficient_matra() {
    new_test_ext().execute_with(|| {
        assert_err!(
            Billing::topup_self(RuntimeOrigin::signed(ALICE), 999_999_999_999),
            Error::<TestRuntime>::TopupTransferFailed
        );
    });
}

// ---------------------------------------------------------------------------
// pay_request — dry run mode (2.A default)
// ---------------------------------------------------------------------------

#[test]
fn pay_request_is_dry_run_when_debits_disabled() {
    new_test_ext().execute_with(|| {
        // No governance call to enable debits — should remain in dry-run.
        assert!(!Billing::debits_enabled());

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        let before = Billing::balance_of(&ALICE);

        let req_id = H256::repeat_byte(0xab);
        // Even with a non-zero price set, dry-run must not debit.
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(1_000),
        ));

        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));

        // Balance unchanged.
        assert_eq!(Billing::balance_of(&ALICE), before);
        // Idempotency record was written even in dry-run.
        assert!(Billing::paid_request(ALICE, req_id).is_some());
    });
}

// ---------------------------------------------------------------------------
// pay_request — live debit mode
// ---------------------------------------------------------------------------

#[test]
fn pay_request_debits_when_enabled() {
    new_test_ext().execute_with(|| {
        enable_debits();

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(1_500),
        ));

        let req_id = H256::repeat_byte(0x01);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));

        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 1_500);
    });
}

#[test]
fn pay_request_is_idempotent_on_request_id() {
    new_test_ext().execute_with(|| {
        enable_debits();

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(2_000),
        ));

        let req_id = H256::repeat_byte(0x02);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        // Re-submit same request_id — should be a no-op success, no extra charge.
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));

        // Balance debited ONCE.
        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 2_000);
    });
}

#[test]
fn pay_request_rejects_when_charge_exceeds_max_charge() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(10_000),
        ));

        let req_id = H256::repeat_byte(0x03);
        assert_noop!(
            Billing::pay_request(
                RuntimeOrigin::signed(ALICE),
                b"receipt_submit".to_vec(),
                0,
                5_000, // max_charge below price
                req_id,
            ),
            Error::<TestRuntime>::ChargeExceedsMaxCharge
        );
        // Balance untouched.
        assert_eq!(Billing::balance_of(&ALICE), 100_000);
    });
}

#[test]
fn pay_request_rejects_when_balance_insufficient() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(500),
        ));

        let req_id = H256::repeat_byte(0x04);
        assert_noop!(
            Billing::pay_request(
                RuntimeOrigin::signed(ALICE),
                b"receipt_submit".to_vec(),
                0,
                10_000,
                req_id,
            ),
            Error::<TestRuntime>::InsufficientBalance
        );
    });
}

// ---------------------------------------------------------------------------
// PerByte pricing
// ---------------------------------------------------------------------------

#[test]
fn per_byte_pricing_scales_with_request_bytes() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 1_000_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"chunk_upload".to_vec(),
            PricingModel::PerByte { unit_price: 10 },
        ));

        let req_id = H256::repeat_byte(0x05);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"chunk_upload".to_vec(),
            1_000, // 1KB
            100_000,
            req_id,
        ));

        // 1000 bytes * 10 MATRA/byte = 10_000.
        assert_eq!(Billing::balance_of(&ALICE), 1_000_000 - 10_000 /*per_byte: balance was topped from 10M not 1M*/);
    });
}

#[test]
fn per_byte_pricing_ignores_request_bytes_for_per_call_endpoints() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 1_000_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(500),
        ));

        let req_id = H256::repeat_byte(0x06);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            999_999_999, // irrelevant for PerCall
            10_000,
            req_id,
        ));

        assert_eq!(Billing::balance_of(&ALICE), 1_000_000 - 500);
    });
}

#[test]
fn unpriced_endpoint_is_free() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 1_000));

        let req_id = H256::repeat_byte(0x07);
        // No governance_set_endpoint_price call for this class.
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"never_priced".to_vec(),
            0,
            1_000_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&ALICE), 1_000);
    });
}

// ---------------------------------------------------------------------------
// Endpoint class length cap
// ---------------------------------------------------------------------------

#[test]
fn endpoint_class_longer_than_max_is_rejected() {
    new_test_ext().execute_with(|| {
        enable_debits();
        let too_long = vec![b'x'; 65];
        let req_id = H256::repeat_byte(0x08);
        assert_noop!(
            Billing::pay_request(
                RuntimeOrigin::signed(ALICE),
                too_long,
                0,
                10_000,
                req_id,
            ),
            Error::<TestRuntime>::EndpointClassTooLong
        );
    });
}

// ---------------------------------------------------------------------------
// Withdrawal
// ---------------------------------------------------------------------------

#[test]
fn withdrawal_request_debits_immediately_and_starts_cooldown() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));

        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));

        // Balance debited immediately to prevent double-spend.
        assert_eq!(Billing::balance_of(&ALICE), 70_000);

        let pending = Billing::pending_withdrawal(&ALICE).expect("pending should exist");
        assert_eq!(pending.0, 30_000);
        // Cooldown: current block + 50.
        assert_eq!(pending.1, System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);
    });
}

#[test]
fn withdrawal_execute_before_cooldown_fails() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));

        // Same block — should fail.
        assert_noop!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::WithdrawalCooldownActive
        );

        // Advance partway — still locked.
        System::set_block_number(System::block_number() + 49);
        assert_noop!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::WithdrawalCooldownActive
        );
    });
}

#[test]
fn withdrawal_execute_after_cooldown_mints_matra_back() {
    new_test_ext().execute_with(|| {
        let initial_matra = Balances::free_balance(&ALICE);
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        let matra_after_topup = Balances::free_balance(&ALICE);
        assert_eq!(matra_after_topup, initial_matra - 100_000);

        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));

        // Advance past cooldown.
        System::set_block_number(System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);
        assert_ok!(Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)));

        // MATRA minted back.
        assert_eq!(Balances::free_balance(&ALICE), matra_after_topup + 30_000);
        // Billing balance unchanged from after request (already debited).
        assert_eq!(Billing::balance_of(&ALICE), 70_000);
        // Pending cleared.
        assert!(Billing::pending_withdrawal(&ALICE).is_none());
    });
}

#[test]
fn withdrawal_re_request_replaces_prior_and_restarts_cooldown() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));

        // First request.
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));
        assert_eq!(Billing::balance_of(&ALICE), 70_000);

        // Advance 10 blocks, then request a different amount.
        System::set_block_number(System::block_number() + 10);
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            50_000
        ));

        // Prior 30k credited back; new 50k debited; net = 100k - 50k = 50k.
        assert_eq!(Billing::balance_of(&ALICE), 50_000);

        // Cooldown restarted from current block.
        let pending = Billing::pending_withdrawal(&ALICE).expect("pending should exist");
        assert_eq!(pending.0, 50_000);
        assert_eq!(pending.1, System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);
    });
}

#[test]
fn withdrawal_execute_with_no_pending_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::NoPendingWithdrawal
        );
    });
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

#[test]
fn non_root_cannot_set_endpoint_price() {
    new_test_ext().execute_with(|| {
        assert_err!(
            Billing::governance_set_endpoint_price(
                RuntimeOrigin::signed(ALICE),
                b"receipt_submit".to_vec(),
                PricingModel::PerCall(1_000),
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn non_root_cannot_flip_debits_switch() {
    new_test_ext().execute_with(|| {
        assert_err!(
            Billing::governance_set_debits_enabled(RuntimeOrigin::signed(ALICE), true),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

// ---------------------------------------------------------------------------
// quote_price helper
// ---------------------------------------------------------------------------

#[test]
fn quote_price_returns_computed_price_without_charging() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"chunk_upload".to_vec(),
            PricingModel::PerByte { unit_price: 5 },
        ));

        let quoted = Billing::quote_price(b"chunk_upload", 200).unwrap();
        assert_eq!(quoted, 1_000);

        let unpriced = Billing::quote_price(b"unknown_endpoint", 1_000).unwrap();
        assert_eq!(unpriced, 0);
    });
}

// ---------------------------------------------------------------------------
// H1 — PaidRequests namespacing: cross-account squatting is impossible
// ---------------------------------------------------------------------------

#[test]
fn pay_request_idempotency_is_per_payer_not_global() {
    // The defect: previously, any signed account could pre-occupy a global
    // request_id slot and turn a different payer's subsequent pay_request
    // into a no-op success. With the (payer, request_id) DoubleMap, Bob
    // claiming a slot cannot prevent Alice from being independently charged.
    new_test_ext().execute_with(|| {
        enable_debits();

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(BOB), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(2_500),
        ));

        // Same request_id for both accounts — would have collided under the
        // old single-map design.
        let req_id = H256::repeat_byte(0xaa);

        // Bob front-runs Alice with this request_id.
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(BOB),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&BOB), 100_000 - 2_500);

        // Alice still gets charged independently — Bob did NOT consume her
        // idempotency slot.
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 2_500);

        // Both PaidRequests entries exist and are distinct.
        assert!(Billing::paid_request(ALICE, req_id).is_some());
        assert!(Billing::paid_request(BOB, req_id).is_some());

        // Alice resubmitting her own (payer, request_id) is still idempotent.
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        // No double-charge.
        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 2_500);
    });
}

// ---------------------------------------------------------------------------
// H2 — prune_paid_requests
// ---------------------------------------------------------------------------

#[test]
fn prune_paid_requests_removes_entries_older_than_retention() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(100),
        ));

        let req_id = H256::repeat_byte(0xbb);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert!(Billing::paid_request(ALICE, req_id).is_some());

        // Advance past the 100-block retention window (test config).
        System::set_block_number(System::block_number() + 200);

        // Anyone can call prune — use BOB to prove it's permissionless.
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, req_id)],
        ));

        // Entry gone.
        assert!(Billing::paid_request(ALICE, req_id).is_none());
    });
}

#[test]
fn prune_paid_requests_skips_entries_still_within_retention() {
    new_test_ext().execute_with(|| {
        enable_debits();
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(100),
        ));

        let req_id = H256::repeat_byte(0xbc);
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));

        // Only advance 50 blocks — still inside the 100-block retention.
        System::set_block_number(System::block_number() + 50);

        // Prune is a no-op for entries inside the window.
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, req_id)],
        ));

        // Entry still present.
        assert!(Billing::paid_request(ALICE, req_id).is_some());
    });
}

#[test]
fn prune_paid_requests_silently_skips_nonexistent_entries() {
    new_test_ext().execute_with(|| {
        // No entries written at all — pruning a made-up (payer, request_id)
        // should be a clean no-op, not an error.
        let bogus = H256::repeat_byte(0xff);
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, bogus), (BOB, bogus)],
        ));
        // Nothing to assert beyond non-error — neither key was ever there.
        assert!(Billing::paid_request(ALICE, bogus).is_none());
        assert!(Billing::paid_request(BOB, bogus).is_none());
    });
}

// ---------------------------------------------------------------------------
// M1 — execute_withdrawal mint-failure resilience
// ---------------------------------------------------------------------------
//
// We exercise the deposit-saturation path by constructing a topup that drains
// almost the entire genesis pool into the user, requesting a withdrawal that
// would push pallet-balances total issuance past u128::MAX. In practice the
// existing balances impl saturates u128 arithmetic on max-value inputs.
//
// The simplest reliable trigger that doesn't require a separate mock-Currency
// crate is: corrupt the pending entry such that the stored amount cannot be
// converted to BalanceOf<T>. Here BalanceOf<T> IS u128, so try_into never
// fails — instead we directly stage the saturation case via TotalIssuance
// pre-set + a large pending amount. The cleanest path is to override the
// pending entry post-request via storage::insert to a value whose deposit
// would exceed total-issuance headroom.

#[test]
fn execute_withdrawal_restores_pending_on_mint_failure() {
    // Reproduce the M1 hazard: deposit_creating silently returns
    // PositiveImbalance::zero() on per-account free_balance overflow
    // (see pallet-balances impl_currency.rs:434 — checked_add returns None
    // → Zero imbalance, no event, no state change). With Alice's account
    // pre-loaded near u128::MAX, any non-zero deposit will saturate, and
    // the OLD code would have silently cleared PendingWithdrawals without
    // crediting the MATRA — losing the user's funds from both ledgers.
    new_test_ext().execute_with(|| {
        // First do the legitimate setup.
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));

        let pre_pending = Billing::pending_withdrawal(&ALICE)
            .expect("pending should exist post-request");
        assert_eq!(pre_pending.0, 30_000);

        // Now force Alice's free_balance to u128::MAX — any subsequent
        // deposit_creating(non-zero) will overflow account.free and the
        // PositiveImbalance returned will be Zero.
        let _ = pallet_balances::Pallet::<TestRuntime>::force_set_balance(
            RuntimeOrigin::root(),
            ALICE,
            u128::MAX,
        );
        let pre_free = Balances::free_balance(&ALICE);
        assert_eq!(pre_free, u128::MAX);

        // Advance past cooldown.
        System::set_block_number(System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);

        // execute_withdrawal must detect the silent saturation and bail.
        assert_err!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::WithdrawalAmountOverflow
        );

        // (a) extrinsic errored — verified by assert_err above.
        // (b) PendingWithdrawals preserved — user can retry without losing escrow.
        let post_pending = Billing::pending_withdrawal(&ALICE)
            .expect("pending should still be present after mint failure");
        assert_eq!(post_pending.0, 30_000);
        // (c) free_balance unchanged — no partial credit landed.
        assert_eq!(Balances::free_balance(&ALICE), pre_free);
    });
}

// ---------------------------------------------------------------------------
// M2 — request_withdrawal(amount=0) is rejected; cancel_withdrawal exists
// ---------------------------------------------------------------------------

#[test]
fn request_withdrawal_rejects_zero_amount() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_noop!(
            Billing::request_withdrawal(RuntimeOrigin::signed(ALICE), 0),
            Error::<TestRuntime>::ZeroWithdrawal
        );
    });
}

#[test]
fn cancel_withdrawal_credits_prior_pending_back_and_does_not_start_a_new_one() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            40_000
        ));
        assert_eq!(Billing::balance_of(&ALICE), 60_000);
        assert!(Billing::pending_withdrawal(&ALICE).is_some());

        assert_ok!(Billing::cancel_withdrawal(RuntimeOrigin::signed(ALICE)));

        // Full credit back to billing balance.
        assert_eq!(Billing::balance_of(&ALICE), 100_000);
        // Nothing pending afterward.
        assert!(Billing::pending_withdrawal(&ALICE).is_none());
    });
}

#[test]
fn cancel_withdrawal_with_nothing_pending_is_a_no_op() {
    new_test_ext().execute_with(|| {
        // No pending entry exists — should not error.
        assert_ok!(Billing::cancel_withdrawal(RuntimeOrigin::signed(ALICE)));
        assert!(Billing::pending_withdrawal(&ALICE).is_none());
    });
}

// ---------------------------------------------------------------------------
// L-2 — prune_paid_requests MaxPruneBatch cap (PR #20 review, task #226)
// ---------------------------------------------------------------------------
//
// MaxPruneBatch bounds the per-call weight: the declared weight in the
// #[pallet::weight] attribute scales linearly with ids.len(), so without
// this cap a single extrinsic could declare more weight than the per-block
// normal-class budget allows and force the node to spend a full block on
// one tx (or fail with `Overweight`). The test runtime sets MaxPruneBatch
// to 8 so we can exercise both sides of the boundary cheaply.

#[test]
fn prune_paid_requests_accepts_batch_at_max_size() {
    new_test_ext().execute_with(|| {
        // Build a batch of exactly MaxPruneBatch (= 8) entries. The entries
        // don't have to actually exist on chain — `prune_paid_requests`
        // silently skips non-existent keys, so the call still succeeds.
        let ids: Vec<(u64, H256)> = (0..8u8)
            .map(|i| (ALICE, H256::repeat_byte(0xc0 | i)))
            .collect();
        assert_eq!(ids.len(), 8);

        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            ids,
        ));
    });
}

#[test]
fn prune_paid_requests_rejects_batch_over_max_size() {
    new_test_ext().execute_with(|| {
        // 9 entries — one over the cap. Must reject BEFORE iterating so
        // a malicious keeper can't burn even a partial pass of work.
        let ids: Vec<(u64, H256)> = (0..9u8)
            .map(|i| (ALICE, H256::repeat_byte(0xd0 | i)))
            .collect();
        assert_eq!(ids.len(), 9);

        assert_noop!(
            Billing::prune_paid_requests(RuntimeOrigin::signed(BOB), ids),
            Error::<TestRuntime>::PruneBatchTooLarge
        );
    });
}

#[test]
fn prune_paid_requests_accepts_empty_batch() {
    new_test_ext().execute_with(|| {
        // 0 ≤ cap, no-op success. Keepers polling with nothing to prune
        // shouldn't have to special-case the empty input.
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            Vec::new(),
        ));
    });
}
