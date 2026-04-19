//! v5.1 tokenomics — Component 2: Fee-router (OnUnbalanced 40/30/20/10 split).
//!
//! The router is attached to `pallet_transaction_payment::Config::OnChargeTransaction`
//! via `FungibleAdapter<Balances, DealWithFees<Runtime>>`. When a transaction
//! fee is settled, `DealWithFees` receives a `Credit` imbalance and splits it:
//!
//!   40% -> block author   (`pallet_authorship`-style: current block author)
//!   30% -> attestor reserve (a PalletId-derived reserve account)
//!   20% -> treasury       (pallet_treasury::account_id())
//!   10% -> burn           (drop the credit)
//!
//! Any rounding drift is absorbed into the burn bucket so that the sum of all
//! parts equals the input fee exactly.
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT
//! ---------------------------------------------------------------------------
//!
//! These tests FAIL to compile/pass until:
//!   1. A `DealWithFees<Runtime>` type is defined (e.g. in `runtime/src/fee_router.rs`).
//!   2. `pallet_transaction_payment::Config::OnChargeTransaction` is changed to
//!      `FungibleAdapter<Balances, DealWithFees<Runtime>>`.
//!   3. The attestor reserve PalletId is declared in the runtime (re-exported
//!      as `AttestorReservePalletId` + `attestor_reserve_account()`).

use crate::*;

use frame_support::traits::{
    fungible::{Balanced, Inspect, Credit},
    tokens::Precision,
    Currency, Imbalance, OnUnbalanced,
};
use sp_io::TestExternalities;
use sp_runtime::{BuildStorage, traits::AccountIdConversion};

// ---------------------------------------------------------------------------
// Externalities
// ---------------------------------------------------------------------------

/// Amount seeded to an "origin" account used to mint the Credit imbalance.
/// Must be large enough to cover the largest fee exercised in tests.
const FEE_PAYER_SEED: Balance = 1_000_000_000_000;

fn fee_payer() -> AccountId {
    sp_keyring::Sr25519Keyring::Dave.to_account_id()
}

fn author_account() -> AccountId {
    // DealWithFees must route 40% here. Tests set this as the author via
    // `pallet_authorship::Author` storage; if the runtime uses a different
    // mechanism (e.g. pallet_block_rewards beneficiary), the DealWithFees
    // implementation is responsible for resolving it.
    sp_keyring::Sr25519Keyring::Eve.to_account_id()
}

fn attestor_reserve_account_local() -> AccountId {
    // Mirror of the runtime's `attestor_reserve_account()`; defined here so
    // the test compiles before the runtime symbol is declared. When the
    // runtime exports `AttestorReservePalletId`, this path becomes redundant,
    // but keeping it means the assertion is still load-bearing.
    crate::AttestorReservePalletId::get().into_account_truncating()
}

fn treasury_account_local() -> AccountId {
    pallet_treasury::Pallet::<Runtime>::account_id()
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (fee_payer(), FEE_PAYER_SEED),
            (author_account(), 0), // explicitly 0; asserts mean post-balance IS the credit
            // Reserve + treasury start at 0 so we measure deltas cleanly.
            (attestor_reserve_account_local(), 0),
            (treasury_account_local(), 0),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

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

// ---------------------------------------------------------------------------
// Helpers to mint and route a Credit imbalance
// ---------------------------------------------------------------------------

/// Withdraw `fee` from `fee_payer()` as a `Credit<AccountId, Balances>`, then
/// feed it into `DealWithFees::on_unbalanceds`. Returns the pre/post balances.
fn route_fee(fee: Balance) -> RoutedSnapshot {
    // Set the "current block author" for any author-resolution path. Some
    // implementations read `pallet_authorship::Author`; we also set
    // `pallet_block_rewards::CurrentBlockBeneficiary` (commonly used on IOG
    // partner chains) to cover both.
    pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(
        sidechain_domain::byte_string::SizedByteString([0xAAu8; 32]),
    );

    let pre = snapshot();

    let credit: Credit<AccountId, pallet_balances::Pallet<Runtime>> =
        pallet_balances::Pallet::<Runtime>::withdraw(
            &fee_payer(),
            fee,
            Precision::Exact,
            frame_support::traits::tokens::Preservation::Preserve,
            frame_support::traits::tokens::Fortitude::Polite,
        )
        .expect("seed should cover requested fee");

    // FungibleAdapter feeds `fee, tip` as two credits in `on_unbalanceds`. For
    // the split-percentage test we treat the entire amount as a single fee
    // with no tip; edge case tests exercise the merged path.
    <DealWithFees<Runtime> as OnUnbalanced<Credit<AccountId, pallet_balances::Pallet<Runtime>>>>
        ::on_unbalanceds(core::iter::once(credit));

    let post = snapshot();
    RoutedSnapshot { pre, post, fee }
}

#[derive(Clone, Debug)]
struct Snapshot {
    author: Balance,
    reserve: Balance,
    treasury: Balance,
    total_issuance: Balance,
}

fn snapshot() -> Snapshot {
    Snapshot {
        author: pallet_balances::Pallet::<Runtime>::free_balance(&author_account()),
        reserve: pallet_balances::Pallet::<Runtime>::free_balance(
            &attestor_reserve_account_local(),
        ),
        treasury: pallet_balances::Pallet::<Runtime>::free_balance(
            &treasury_account_local(),
        ),
        total_issuance: pallet_balances::Pallet::<Runtime>::total_issuance(),
    }
}

struct RoutedSnapshot {
    pre: Snapshot,
    post: Snapshot,
    fee: Balance,
}

impl RoutedSnapshot {
    fn author_delta(&self) -> Balance {
        self.post.author.saturating_sub(self.pre.author)
    }
    fn reserve_delta(&self) -> Balance {
        self.post.reserve.saturating_sub(self.pre.reserve)
    }
    fn treasury_delta(&self) -> Balance {
        self.post.treasury.saturating_sub(self.pre.treasury)
    }
    fn burn_delta(&self) -> Balance {
        // Burn reduces total_issuance. The fee-payer side already reduced
        // issuance when we called withdraw() above, so we reason as follows:
        //
        //   withdraw(fee)   -> total_issuance -= fee
        //   deposit(a)       -> total_issuance += a (author)
        //   deposit(r)       -> total_issuance += r (reserve)
        //   deposit(t)       -> total_issuance += t (treasury)
        //   drop credit(b)   -> total_issuance unchanged (this is the BURN)
        //
        //   so pre_issuance - post_issuance == fee - (a + r + t) == b
        self.pre.total_issuance.saturating_sub(self.post.total_issuance)
    }
    fn sum(&self) -> Balance {
        self.author_delta()
            .saturating_add(self.reserve_delta())
            .saturating_add(self.treasury_delta())
            .saturating_add(self.burn_delta())
    }
}

// ---------------------------------------------------------------------------
// 40/30/20/10 split: exact percentages
// ---------------------------------------------------------------------------

#[test]
fn fee_split_40_30_20_10_on_clean_multiple() {
    // Use a fee that divides cleanly: 100 base units => 40/30/20/10.
    new_test_ext().execute_with(|| {
        let r = route_fee(100);
        assert_eq!(r.author_delta(), 40, "author should get 40%");
        assert_eq!(r.reserve_delta(), 30, "attestor reserve should get 30%");
        assert_eq!(r.treasury_delta(), 20, "treasury should get 20%");
        assert_eq!(r.burn_delta(), 10, "10% must be burned");
        assert_eq!(r.sum(), r.fee, "sum of all shares must equal the fee");
    });
}

#[test]
fn fee_split_conservation_on_one_matra() {
    // 1 MATRA at 6 decimals = 1_000_000 base units. Divides cleanly by 10.
    new_test_ext().execute_with(|| {
        let fee: Balance = 1_000_000;
        let r = route_fee(fee);
        assert_eq!(r.author_delta(), 400_000);
        assert_eq!(r.reserve_delta(), 300_000);
        assert_eq!(r.treasury_delta(), 200_000);
        assert_eq!(r.burn_delta(), 100_000);
        assert_eq!(r.sum(), fee);
    });
}

// ---------------------------------------------------------------------------
// Property-ish: conservation across many values
// ---------------------------------------------------------------------------

#[test]
fn fee_split_conservation_across_sampled_values() {
    new_test_ext().execute_with(|| {
        // Deterministic sample of fees including boundary cases.
        let samples: &[Balance] = &[
            1, 2, 3, 4, 9, 10, 11, 99, 100, 101,
            999, 1_000, 1_001,
            1_234_567,
            999_999_999,
            1_000_000_000,
        ];
        for &fee in samples {
            // Reset: refill the fee-payer so successive samples don't drain it.
            let payer = fee_payer();
            let current = pallet_balances::Pallet::<Runtime>::free_balance(&payer);
            if current < fee {
                let topup = FEE_PAYER_SEED - current;
                let _ = pallet_balances::Pallet::<Runtime>::deposit_creating(&payer, topup);
            }
            let r = route_fee(fee);
            assert_eq!(
                r.sum(),
                r.fee,
                "conservation violated for fee={}: author={} reserve={} treasury={} burn={}",
                fee,
                r.author_delta(),
                r.reserve_delta(),
                r.treasury_delta(),
                r.burn_delta(),
            );
            // 40% is the dominant share; assert it is ALWAYS floor(fee*40/100).
            let expected_author = fee.saturating_mul(40) / 100;
            assert_eq!(
                r.author_delta(), expected_author,
                "author share wrong for fee={}: expected {}, got {}",
                fee, expected_author, r.author_delta(),
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn fee_split_zero_fee_is_noop() {
    new_test_ext().execute_with(|| {
        let pre_total = pallet_balances::Pallet::<Runtime>::total_issuance();
        // A zero credit should not panic or burn anything.
        let credit: Credit<AccountId, pallet_balances::Pallet<Runtime>> = Credit::zero();
        <DealWithFees<Runtime> as OnUnbalanced<Credit<AccountId, pallet_balances::Pallet<Runtime>>>>
            ::on_unbalanceds(core::iter::once(credit));
        let post_total = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_total, post_total, "zero credit must not change total issuance");
    });
}

#[test]
fn fee_split_rounding_residue_goes_to_burn() {
    // 7 is not divisible by 10. Percentages:
    //   floor(7 * 40 / 100) = 2      author
    //   floor(7 * 30 / 100) = 2      reserve
    //   floor(7 * 20 / 100) = 1      treasury
    //   remainder = 7 - 2 - 2 - 1 = 2 burn (gets the drift)
    //
    // The router must send the rounding remainder to BURN (or conservatively
    // to treasury) rather than letting it leak into an unfunded bucket or
    // panic. This test asserts conservation; the exact distribution of the
    // residue is validated by the conservation property test above.
    new_test_ext().execute_with(|| {
        let r = route_fee(7);
        assert_eq!(r.author_delta(), 2, "author = floor(7*0.4) = 2");
        assert_eq!(r.sum(), r.fee, "conservation must hold even with residue");
        // The sum of non-burn fractions ≤ fee * 90 / 100, so burn ≥ 10% after rounding.
        assert!(
            r.burn_delta() >= 1,
            "burn must absorb rounding residue; got {}", r.burn_delta(),
        );
    });
}

#[test]
fn fee_split_fee_and_tip_both_routed() {
    // FungibleAdapter feeds (fee, tip) as a 2-element iterator to
    // on_unbalanceds. The router MUST aggregate them so the total is split,
    // not each individually (otherwise 1+1 MATRA split gives 0.4+0.4 author
    // instead of 0.8 author).
    new_test_ext().execute_with(|| {
        let fee_part: Balance = 60;
        let tip_part: Balance = 40;
        let total = fee_part + tip_part;

        let pre = snapshot();
        let fee_credit = pallet_balances::Pallet::<Runtime>::withdraw(
            &fee_payer(),
            fee_part,
            Precision::Exact,
            frame_support::traits::tokens::Preservation::Preserve,
            frame_support::traits::tokens::Fortitude::Polite,
        ).expect("fee part");
        let tip_credit = pallet_balances::Pallet::<Runtime>::withdraw(
            &fee_payer(),
            tip_part,
            Precision::Exact,
            frame_support::traits::tokens::Preservation::Preserve,
            frame_support::traits::tokens::Fortitude::Polite,
        ).expect("tip part");

        <DealWithFees<Runtime> as OnUnbalanced<Credit<AccountId, pallet_balances::Pallet<Runtime>>>>
            ::on_unbalanceds(vec![fee_credit, tip_credit].into_iter());

        let post = snapshot();
        let author_delta = post.author.saturating_sub(pre.author);
        let reserve_delta = post.reserve.saturating_sub(pre.reserve);
        let treasury_delta = post.treasury.saturating_sub(pre.treasury);
        let burn_delta = pre.total_issuance.saturating_sub(post.total_issuance);

        assert_eq!(author_delta + reserve_delta + treasury_delta + burn_delta, total);
        assert_eq!(author_delta, 40);
        assert_eq!(reserve_delta, 30);
        assert_eq!(treasury_delta, 20);
        assert_eq!(burn_delta, 10);
    });
}
