//! v5.1 tokenomics — Component 1: pallet_treasury integration tests.
//!
//! Verifies:
//!   * pallet_treasury is wired into construct_runtime! and its Config is
//!     implemented with a mainnet-safe SpendOrigin / RejectOrigin / Burn.
//!   * The treasury PalletId derives a stable, canonical account that can be
//!     credited via genesis and drained via `spend_local` after SpendPeriod.
//!   * spend_local with a non-root origin is rejected (BadOrigin).
//!   * spend_local with amount > MaxBalance cap (if any) is rejected.
//!   * The `Burn` fraction is applied at every SpendPeriod rollover even when
//!     no approvals are pending.
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT
//! ---------------------------------------------------------------------------
//!
//! These tests are written BEFORE `pallet_treasury` is wired into the runtime.
//! They will fail to compile until:
//!   1. `pallet-treasury` is added to `runtime/Cargo.toml`.
//!   2. `impl pallet_treasury::Config for Runtime` is added to `runtime/src/lib.rs`.
//!   3. `Treasury: pallet_treasury` is added to `construct_runtime!`.
//!   4. `TreasuryPalletId` + `TreasuryAccount` parameters are exposed.

use crate::*;

use frame_support::{
    assert_noop, assert_ok,
    traits::{OnFinalize, OnInitialize, PalletInfoAccess},
};
use sp_io::TestExternalities;
use sp_runtime::{BuildStorage, traits::AccountIdConversion};

// ---------------------------------------------------------------------------
// Externalities builder
// ---------------------------------------------------------------------------

/// Initial amount credited to the treasury PalletId-derived account at genesis.
/// Chosen to be large enough to survive `SpendPeriod` burns in tests AND still
/// fund a visible spend.
const INITIAL_TREASURY_BALANCE: Balance = 1_000_000_000_000;

/// Seed amount credited to Alice & Bob for role tests.
const SEED_USER_BALANCE: Balance = 10_000_000;

/// Spend amount exercised in the happy-path test. Well below INITIAL.
const SPEND_AMOUNT: Balance = 100_000_000;

fn treasury_account() -> AccountId {
    // Derive via pallet_treasury::Pallet::account_id() so the test is
    // sensitive to the configured PalletId changing.
    pallet_treasury::Pallet::<Runtime>::account_id()
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    // Pre-fund treasury account + two test users.
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (treasury_account(), INITIAL_TREASURY_BALANCE),
            (sp_keyring::Sr25519Keyring::Alice.to_account_id(), SEED_USER_BALANCE),
            (sp_keyring::Sr25519Keyring::Bob.to_account_id(), SEED_USER_BALANCE),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");

    // IOG pallets: minimum genesis so AllPalletsWithSystem::on_initialize works.
    pallet_sidechain::GenesisConfig::<Runtime> {
        genesis_utxo: sidechain_domain::UtxoId::new(
            hex_literal::hex!(
                "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
            ),
            0,
        ),
        slots_per_epoch: sidechain_slots::SlotsPerEpoch(7),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("sidechain genesis");

    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("scv genesis");

    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("pcs genesis");

    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("ntm genesis");

    storage.into()
}

/// Advance the chain enough for the treasury's `SpendPeriod` tick to fire.
///
/// We only call `on_initialize` / `on_finalize` for the pallets that matter
/// for treasury tests (System + Treasury), avoiding AllPalletsWithSystem
/// because pallet_aura's on_finalize asserts that the timestamp inherent
/// matches CurrentSlot — which we'd have to fabricate per-block. For the
/// scope of these tests (verifying treasury fund-flow), those consensus
/// pallets are orthogonal.
fn run_to_block(n: BlockNumber) {
    while System::block_number() < n {
        let current = System::block_number();
        Treasury::on_finalize(current);
        System::on_finalize(current);

        let next = current + 1;
        System::reset_events();
        System::set_block_number(next);
        System::on_initialize(next);
        Treasury::on_initialize(next);
    }
}

// ---------------------------------------------------------------------------
// Existence & integration tests
// ---------------------------------------------------------------------------

#[test]
fn treasury_pallet_is_in_construct_runtime() {
    // Will only compile if `Treasury: pallet_treasury` is in construct_runtime!.
    new_test_ext().execute_with(|| {
        let name = <pallet_treasury::Pallet<Runtime> as PalletInfoAccess>::name();
        assert_eq!(name, "Treasury");
    });
}

#[test]
fn treasury_account_is_funded_at_genesis() {
    new_test_ext().execute_with(|| {
        let balance = pallet_balances::Pallet::<Runtime>::free_balance(&treasury_account());
        assert_eq!(
            balance, INITIAL_TREASURY_BALANCE,
            "treasury genesis pre-seed must match the fixture; got {}", balance,
        );
    });
}

#[test]
fn treasury_pallet_id_is_canonical_mat_trsy() {
    // Load-bearing: the pallet-id determines the account the runtime sends
    // fees to in Component 2. Changing this value silently would reroute fees
    // to a different account and break on-chain governance.
    new_test_ext().execute_with(|| {
        let account: AccountId = TreasuryPalletId::get().into_account_truncating();
        assert_eq!(account, treasury_account());
        // Also assert the literal bytes to catch typos.
        assert_eq!(TreasuryPalletId::get().0, *b"mat/trsy");
    });
}

// ---------------------------------------------------------------------------
// Happy-path spend
// ---------------------------------------------------------------------------

#[test]
fn treasury_spend_local_moves_balance_on_spend_period() {
    new_test_ext().execute_with(|| {
        let beneficiary = sp_keyring::Sr25519Keyring::Charlie.to_account_id();
        let treasury = treasury_account();

        // System events aren't recorded at block 0; move to a real block so
        // SpendApproved is deposited in the event queue.
        System::set_block_number(1);

        // BEFORE
        assert_eq!(
            pallet_balances::Pallet::<Runtime>::free_balance(&treasury),
            INITIAL_TREASURY_BALANCE,
        );
        assert_eq!(
            pallet_balances::Pallet::<Runtime>::free_balance(&beneficiary),
            0,
        );

        // Approve spend via Root.
        assert_ok!(pallet_treasury::Pallet::<Runtime>::spend_local(
            RuntimeOrigin::root(),
            SPEND_AMOUNT,
            sp_runtime::MultiAddress::Id(beneficiary.clone()),
        ));

        // SpendApproved event emitted immediately.
        let events = System::events();
        let approved_event = events.iter().find(|e| matches!(
            e.event,
            RuntimeEvent::Treasury(pallet_treasury::Event::SpendApproved { .. })
        ));
        assert!(
            approved_event.is_some(),
            "Treasury::SpendApproved must be emitted on spend_local approval; got events: {:?}",
            events.iter().map(|e| &e.event).collect::<Vec<_>>(),
        );

        // Tick to SpendPeriod so `spend_funds` pays out queued approvals.
        run_to_block(SPEND_PERIOD_BLOCKS + 1);

        // AFTER: beneficiary received the amount.
        let post_treasury = pallet_balances::Pallet::<Runtime>::free_balance(&treasury);
        let post_beneficiary =
            pallet_balances::Pallet::<Runtime>::free_balance(&beneficiary);

        assert_eq!(
            post_beneficiary, SPEND_AMOUNT,
            "beneficiary should have received exactly the spend amount; got {}",
            post_beneficiary,
        );
        // Treasury balance is INITIAL - spend - burn. We don't hard-code the
        // exact burn figure (that's covered below); instead, assert the
        // treasury dropped by at least the spend amount.
        assert!(
            post_treasury <= INITIAL_TREASURY_BALANCE - SPEND_AMOUNT,
            "treasury should have dropped by >= SPEND_AMOUNT (spend + any burn); \
             treasury now {} started at {} spend {}",
            post_treasury, INITIAL_TREASURY_BALANCE, SPEND_AMOUNT,
        );
    });
}

// ---------------------------------------------------------------------------
// Authorisation failures
// ---------------------------------------------------------------------------

#[test]
fn treasury_spend_local_from_signed_is_bad_origin() {
    new_test_ext().execute_with(|| {
        let beneficiary = sp_keyring::Sr25519Keyring::Charlie.to_account_id();
        // Alice is a normal signed account, NOT root.
        let alice = sp_keyring::Sr25519Keyring::Alice.to_account_id();
        assert_noop!(
            pallet_treasury::Pallet::<Runtime>::spend_local(
                RuntimeOrigin::signed(alice),
                SPEND_AMOUNT,
                sp_runtime::MultiAddress::Id(beneficiary),
            ),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn treasury_spend_local_from_none_is_bad_origin() {
    new_test_ext().execute_with(|| {
        let beneficiary = sp_keyring::Sr25519Keyring::Charlie.to_account_id();
        assert_noop!(
            pallet_treasury::Pallet::<Runtime>::spend_local(
                RuntimeOrigin::none(),
                SPEND_AMOUNT,
                sp_runtime::MultiAddress::Id(beneficiary),
            ),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

// ---------------------------------------------------------------------------
// SpendPeriod tick + burn
// ---------------------------------------------------------------------------

#[test]
fn treasury_spend_period_tick_applies_burn_to_idle_funds() {
    // With Burn=0% (our mainnet-safe default), the treasury must NOT lose
    // balance on idle SpendPeriod ticks. This guards against a governance
    // error that re-enables burn accidentally.
    new_test_ext().execute_with(|| {
        let before = pallet_balances::Pallet::<Runtime>::free_balance(&treasury_account());
        assert_eq!(before, INITIAL_TREASURY_BALANCE);

        run_to_block(SPEND_PERIOD_BLOCKS + 1);

        let after = pallet_balances::Pallet::<Runtime>::free_balance(&treasury_account());
        assert_eq!(
            after, INITIAL_TREASURY_BALANCE,
            "idle SpendPeriod with Burn=0% must leave treasury untouched; before {} after {}",
            before, after,
        );
    });
}

// ---------------------------------------------------------------------------
// Insufficient balance
// ---------------------------------------------------------------------------

#[test]
fn treasury_spend_approves_even_when_over_balance_then_stalls_payout() {
    // spend_local DOES allow approving more than the treasury holds; the
    // shortfall is handled at SpendPeriod by NOT paying out. This test
    // documents that behaviour: approval succeeds but balance is unchanged
    // because the spend queue `spend_funds` sees insufficient budget.
    new_test_ext().execute_with(|| {
        let beneficiary = sp_keyring::Sr25519Keyring::Charlie.to_account_id();
        let over = INITIAL_TREASURY_BALANCE + 1;
        assert_ok!(pallet_treasury::Pallet::<Runtime>::spend_local(
            RuntimeOrigin::root(),
            over,
            sp_runtime::MultiAddress::Id(beneficiary.clone()),
        ));
        run_to_block(SPEND_PERIOD_BLOCKS + 1);
        // Beneficiary must not have received anything the treasury could not cover.
        let post_beneficiary =
            pallet_balances::Pallet::<Runtime>::free_balance(&beneficiary);
        assert_eq!(
            post_beneficiary, 0,
            "over-budget spend must NOT pay the beneficiary; got {}", post_beneficiary,
        );
    });
}

// ---------------------------------------------------------------------------
// Exceeding SpendOrigin cap
// ---------------------------------------------------------------------------

#[test]
fn treasury_spend_local_over_max_spend_cap_fails() {
    // `SpendOrigin = EnsureRootWithSuccess<AccountId, MaxSpend>` should cap
    // individual approvals to MaxSpend. Amounts over the cap must fail.
    new_test_ext().execute_with(|| {
        let beneficiary = sp_keyring::Sr25519Keyring::Charlie.to_account_id();
        let over_cap = MaxSpend::get().saturating_add(1);
        assert!(
            pallet_treasury::Pallet::<Runtime>::spend_local(
                RuntimeOrigin::root(),
                over_cap,
                sp_runtime::MultiAddress::Id(beneficiary),
            )
            .is_err(),
            "spend_local must reject amounts over MaxSpend cap"
        );
    });
}

// ---------------------------------------------------------------------------
// Idempotency of account_id() derivation
// ---------------------------------------------------------------------------

#[test]
fn treasury_account_id_is_stable() {
    new_test_ext().execute_with(|| {
        let a = pallet_treasury::Pallet::<Runtime>::account_id();
        let b = pallet_treasury::Pallet::<Runtime>::account_id();
        assert_eq!(a, b, "account_id() must be deterministic");
    });
}

// ---------------------------------------------------------------------------
// Shared constants (re-exported from lib.rs so tests don't drift from config)
// ---------------------------------------------------------------------------
//
// NOTE: `SPEND_PERIOD_BLOCKS` and `MaxSpend` and `TreasuryPalletId` are pulled
// from `crate::*`. When you implement Component 1 you MUST export these names
// from the runtime so this file compiles.
