//! v5.1 tokenomics — Component 3: pallet_vesting integration tests.
//!
//! Enables cliff+linear vesting for the Strategic/Investor bucket. Investors
//! receive their tokens via `force_vested_transfer` (Root origin) with a
//! schedule that combines a cliff (starting_block) and a linear unlock
//! (per_block * blocks).
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT
//! ---------------------------------------------------------------------------
//!
//! These tests FAIL until:
//!   1. `pallet-vesting` is added to `runtime/Cargo.toml`.
//!   2. `impl pallet_vesting::Config for Runtime` is added to `runtime/src/lib.rs`.
//!   3. `Vesting: pallet_vesting` is added to `construct_runtime!`.

use crate::*;

use frame_support::{
    assert_noop, assert_ok,
    traits::{PalletInfoAccess, VestingSchedule},
};
use sp_io::TestExternalities;
use sp_runtime::{BuildStorage, MultiAddress};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// 1 MATRA at 6 decimals.
const MATRA: Balance = 1_000_000;

/// Granter holds the Strategic bucket and funds vested transfers.
fn granter() -> AccountId {
    sp_keyring::Sr25519Keyring::Alice.to_account_id()
}

fn grantee() -> AccountId {
    sp_keyring::Sr25519Keyring::Ferdie.to_account_id()
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    // Granter holds 10 MATRA * 1e6 = 10_000_000, the Strategic bucket for
    // these tests. Needs to be > MinVestedTransfer.
    // Grantee starts at ExistentialDeposit so later transfers can add locks;
    // pallet_balances panics if a positive-balance account drops below ED.
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (granter(), 10_000_000 * MATRA),
            (grantee(), ExistentialDeposit::get()),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

    // Minimal IOG genesis for AllPalletsWithSystem initialization.
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

    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| {
        System::set_block_number(1);
    });
    ext
}

// ---------------------------------------------------------------------------
// Existence
// ---------------------------------------------------------------------------

#[test]
fn vesting_pallet_is_in_construct_runtime() {
    new_test_ext().execute_with(|| {
        let name = <pallet_vesting::Pallet<Runtime> as PalletInfoAccess>::name();
        assert_eq!(name, "Vesting");
    });
}

// ---------------------------------------------------------------------------
// Basic schedule: cliff + linear
// ---------------------------------------------------------------------------

/// A schedule locking 1,000,000 units with starting_block = 100 and
/// per_block = 1 unlocks at `starting_block` + 1_000_000 blocks = 1_000_100.
///
/// Before block 100, NONE of it is usable.
/// At block 100, zero blocks elapsed since start => 0 unlocked.
/// At block 100 + N, N units unlocked.
/// At block 1_000_100, all 1,000,000 unlocked.
#[test]
fn vesting_locked_amount_is_full_before_cliff() {
    new_test_ext().execute_with(|| {
        let locked = 1_000_000u128;
        let per_block = 1u128;
        let start: BlockNumber = 100;
        let schedule =
            pallet_vesting::VestingInfo::new(locked, per_block, start);
        assert_ok!(pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
            RuntimeOrigin::root(),
            MultiAddress::Id(granter()),
            MultiAddress::Id(grantee()),
            schedule,
        ));

        // Pre-cliff block.
        System::set_block_number(50);
        let locked_now = <pallet_vesting::Pallet<Runtime> as VestingSchedule<AccountId>>::vesting_balance(
            &grantee(),
        );
        assert_eq!(locked_now, Some(locked));
    });
}

#[test]
fn vesting_locked_amount_decreases_linearly_after_cliff() {
    new_test_ext().execute_with(|| {
        let locked: Balance = 1_000_000;
        let per_block: Balance = 1;
        let start: BlockNumber = 100;
        let schedule =
            pallet_vesting::VestingInfo::new(locked, per_block, start);
        assert_ok!(pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
            RuntimeOrigin::root(),
            MultiAddress::Id(granter()),
            MultiAddress::Id(grantee()),
            schedule,
        ));

        // 250 blocks past cliff: 250 units unlocked, 999_750 still locked.
        System::set_block_number(start + 250);
        let locked_now = <pallet_vesting::Pallet<Runtime> as VestingSchedule<AccountId>>::vesting_balance(
            &grantee(),
        );
        assert_eq!(
            locked_now, Some(locked - 250),
            "expected 999_750 locked after 250 blocks past cliff"
        );

        // At the end of the schedule, 0 should remain locked.
        System::set_block_number(start + locked as BlockNumber);
        let locked_at_end = <pallet_vesting::Pallet<Runtime> as VestingSchedule<AccountId>>::vesting_balance(
            &grantee(),
        );
        assert_eq!(locked_at_end, Some(0), "schedule must fully unlock at end block");
    });
}

// ---------------------------------------------------------------------------
// Origin enforcement
// ---------------------------------------------------------------------------

#[test]
fn force_vested_transfer_requires_root() {
    new_test_ext().execute_with(|| {
        let schedule = pallet_vesting::VestingInfo::new(100 * MATRA, 1, 10);
        // Alice is signed, not root.
        assert_noop!(
            pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
                RuntimeOrigin::signed(granter()),
                MultiAddress::Id(granter()),
                MultiAddress::Id(grantee()),
                schedule,
            ),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn vested_transfer_signed_works() {
    // Signed `vested_transfer` (NOT force_) lets investors move vested tokens
    // themselves; this exercises a non-root path.
    new_test_ext().execute_with(|| {
        let schedule = pallet_vesting::VestingInfo::new(100 * MATRA, 1, 10);
        assert_ok!(pallet_vesting::Pallet::<Runtime>::vested_transfer(
            RuntimeOrigin::signed(granter()),
            MultiAddress::Id(grantee()),
            schedule,
        ));
        let locked_now = <pallet_vesting::Pallet<Runtime> as VestingSchedule<AccountId>>::vesting_balance(
            &grantee(),
        );
        assert_eq!(locked_now, Some(100 * MATRA));
    });
}

// ---------------------------------------------------------------------------
// Compound schedules
// ---------------------------------------------------------------------------

#[test]
fn two_schedules_for_same_account_accumulate() {
    new_test_ext().execute_with(|| {
        let s1 = pallet_vesting::VestingInfo::new(500 * MATRA, 1, 100);
        let s2 = pallet_vesting::VestingInfo::new(300 * MATRA, 1, 200);
        assert_ok!(pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
            RuntimeOrigin::root(),
            MultiAddress::Id(granter()),
            MultiAddress::Id(grantee()),
            s1,
        ));
        assert_ok!(pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
            RuntimeOrigin::root(),
            MultiAddress::Id(granter()),
            MultiAddress::Id(grantee()),
            s2,
        ));

        // Before either cliff, everything locked.
        System::set_block_number(50);
        let locked_now = <pallet_vesting::Pallet<Runtime> as VestingSchedule<AccountId>>::vesting_balance(
            &grantee(),
        );
        assert_eq!(locked_now, Some(800 * MATRA));
    });
}

// ---------------------------------------------------------------------------
// MinVestedTransfer enforcement
// ---------------------------------------------------------------------------

#[test]
fn vested_transfer_below_min_is_rejected() {
    new_test_ext().execute_with(|| {
        // 1 base unit is well below any reasonable MinVestedTransfer.
        let schedule = pallet_vesting::VestingInfo::new(1u128, 1u128, 10);
        let result = pallet_vesting::Pallet::<Runtime>::vested_transfer(
            RuntimeOrigin::signed(granter()),
            MultiAddress::Id(grantee()),
            schedule,
        );
        assert!(
            result.is_err(),
            "vested_transfer below MinVestedTransfer must fail"
        );
    });
}

// ---------------------------------------------------------------------------
// Balance transfer constraints
// ---------------------------------------------------------------------------

#[test]
fn grantee_cannot_transfer_locked_portion_mid_schedule() {
    new_test_ext().execute_with(|| {
        let locked: Balance = 1_000_000;
        let per_block: Balance = 1;
        let start: BlockNumber = 100;
        let schedule =
            pallet_vesting::VestingInfo::new(locked, per_block, start);
        assert_ok!(pallet_vesting::Pallet::<Runtime>::force_vested_transfer(
            RuntimeOrigin::root(),
            MultiAddress::Id(granter()),
            MultiAddress::Id(grantee()),
            schedule,
        ));

        // Mid-schedule: 500 blocks past cliff => 500 unlocked, 999_500 locked.
        System::set_block_number(start + 500);

        // Must call `vest` to update the locks up to current block.
        assert_ok!(pallet_vesting::Pallet::<Runtime>::vest(
            RuntimeOrigin::signed(grantee()),
        ));

        // Grantee's transferable balance:
        //   seed (ED=500) + unlocked_via_schedule (500) = 1000 transferable
        //   (seed doesn't come from the schedule, so it's always spendable)
        // Transferring 2000 exceeds both the seed and the 500 unlocked units,
        // hitting the lock on the remaining 999_500.
        let bob = sp_keyring::Sr25519Keyring::Bob.to_account_id();
        let result = pallet_balances::Pallet::<Runtime>::transfer_allow_death(
            RuntimeOrigin::signed(grantee()),
            MultiAddress::Id(bob),
            2_000,
        );
        assert!(
            result.is_err(),
            "transferring more than the seed + unlocked portion must fail \
             while the schedule lock is active; got {:?}", result,
        );

        // Conversely: transferring within the seed+unlocked window must
        // succeed. The target must already exist (or receive >= ED to be
        // created); Bob was seeded implicitly via `assert_noop!` earlier runs
        // — use a pre-funded account so we don't trip the ED guard.
        // We send to `granter()` (already > ED) so the transfer is the
        // pure-locking test, not an account-creation test.
        assert_ok!(pallet_balances::Pallet::<Runtime>::transfer_allow_death(
            RuntimeOrigin::signed(grantee()),
            MultiAddress::Id(granter()),
            100,
        ));
    });
}
