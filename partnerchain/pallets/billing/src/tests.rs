//! Unit tests for `pallet-billing`.

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
    pub const RequestIdRetentionBlocks: u64 = 100;
}

impl pallet_billing::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type MatraCurrency = Balances;
    type GovernanceOrigin = frame_system::EnsureRoot<u64>;
    type RequestIdRetentionBlocks = RequestIdRetentionBlocks;
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
// pay_request — dry run mode
// ---------------------------------------------------------------------------

#[test]
fn pay_request_is_dry_run_when_debits_disabled() {
    new_test_ext().execute_with(|| {
        assert!(!Billing::debits_enabled());

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        let before = Billing::balance_of(&ALICE);

        let req_id = H256::repeat_byte(0xab);
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

        assert_eq!(Billing::balance_of(&ALICE), before);
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
        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));

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

        assert_eq!(Billing::balance_of(&ALICE), 1_000_000 - 10_000);
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

        assert_eq!(Billing::balance_of(&ALICE), 70_000);

        let pending = Billing::pending_withdrawal(&ALICE).expect("pending should exist");
        assert_eq!(pending.0, 30_000);
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

        assert_noop!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::WithdrawalCooldownActive
        );

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

        System::set_block_number(System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);
        assert_ok!(Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)));

        assert_eq!(Balances::free_balance(&ALICE), matra_after_topup + 30_000);
        assert_eq!(Billing::balance_of(&ALICE), 70_000);
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

        System::set_block_number(System::block_number() + 10);
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            50_000
        ));

        // Prior 30k credited back; new 50k debited; net = 100k - 50k = 50k.
        assert_eq!(Billing::balance_of(&ALICE), 50_000);

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
// PaidRequests idempotency is namespaced by payer
// ---------------------------------------------------------------------------

#[test]
fn pay_request_idempotency_is_per_payer_not_global() {
    new_test_ext().execute_with(|| {
        enable_debits();

        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(BOB), 100_000));
        assert_ok!(Billing::governance_set_endpoint_price(
            RuntimeOrigin::root(),
            b"receipt_submit".to_vec(),
            PricingModel::PerCall(2_500),
        ));

        let req_id = H256::repeat_byte(0xaa);

        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(BOB),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&BOB), 100_000 - 2_500);

        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 2_500);

        assert!(Billing::paid_request(ALICE, req_id).is_some());
        assert!(Billing::paid_request(BOB, req_id).is_some());

        assert_ok!(Billing::pay_request(
            RuntimeOrigin::signed(ALICE),
            b"receipt_submit".to_vec(),
            0,
            10_000,
            req_id,
        ));
        assert_eq!(Billing::balance_of(&ALICE), 100_000 - 2_500);
    });
}

// ---------------------------------------------------------------------------
// prune_paid_requests
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

        System::set_block_number(System::block_number() + 200);

        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, req_id)],
        ));

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

        System::set_block_number(System::block_number() + 50);

        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, req_id)],
        ));

        assert!(Billing::paid_request(ALICE, req_id).is_some());
    });
}

#[test]
fn prune_paid_requests_silently_skips_nonexistent_entries() {
    new_test_ext().execute_with(|| {
        let bogus = H256::repeat_byte(0xff);
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            vec![(ALICE, bogus), (BOB, bogus)],
        ));
        assert!(Billing::paid_request(ALICE, bogus).is_none());
        assert!(Billing::paid_request(BOB, bogus).is_none());
    });
}

// ---------------------------------------------------------------------------
// execute_withdrawal mint-failure resilience
// ---------------------------------------------------------------------------

#[test]
fn execute_withdrawal_restores_pending_on_mint_failure() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::topup_self(RuntimeOrigin::signed(ALICE), 100_000));
        assert_ok!(Billing::request_withdrawal(
            RuntimeOrigin::signed(ALICE),
            30_000
        ));

        let pre_pending = Billing::pending_withdrawal(&ALICE)
            .expect("pending should exist post-request");
        assert_eq!(pre_pending.0, 30_000);

        // Force free_balance to u128::MAX so deposit_creating saturates and
        // returns a zero PositiveImbalance.
        let _ = pallet_balances::Pallet::<TestRuntime>::force_set_balance(
            RuntimeOrigin::root(),
            ALICE,
            u128::MAX,
        );
        let pre_free = Balances::free_balance(&ALICE);
        assert_eq!(pre_free, u128::MAX);

        System::set_block_number(System::block_number() + WITHDRAWAL_COOLDOWN_BLOCKS as u64);

        assert_err!(
            Billing::execute_withdrawal(RuntimeOrigin::signed(ALICE)),
            Error::<TestRuntime>::WithdrawalAmountOverflow
        );

        let post_pending = Billing::pending_withdrawal(&ALICE)
            .expect("pending should still be present after mint failure");
        assert_eq!(post_pending.0, 30_000);
        assert_eq!(Balances::free_balance(&ALICE), pre_free);
    });
}

// ---------------------------------------------------------------------------
// request_withdrawal zero-amount + cancel_withdrawal
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

        assert_eq!(Billing::balance_of(&ALICE), 100_000);
        assert!(Billing::pending_withdrawal(&ALICE).is_none());
    });
}

#[test]
fn cancel_withdrawal_with_nothing_pending_is_a_no_op() {
    new_test_ext().execute_with(|| {
        assert_ok!(Billing::cancel_withdrawal(RuntimeOrigin::signed(ALICE)));
        assert!(Billing::pending_withdrawal(&ALICE).is_none());
    });
}

// ---------------------------------------------------------------------------
// prune_paid_requests MaxPruneBatch cap
// ---------------------------------------------------------------------------

#[test]
fn prune_paid_requests_accepts_batch_at_max_size() {
    new_test_ext().execute_with(|| {
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
        assert_ok!(Billing::prune_paid_requests(
            RuntimeOrigin::signed(BOB),
            Vec::new(),
        ));
    });
}
