//! No-op `OnChargeTransaction` adapter — MATRA is never charged on tx.
//!
//! Substitutes the old `FungibleAdapter<Balances, DealWithFees<Runtime>>` that
//! charged MATRA and routed fees 40/30/20/10. Under the v5.1 Midnight-style
//! fee redesign (2026-04-21), transaction fees are paid in MOTRA (via the
//! `pallet_motra::fee::ChargeMotra` SignedExtension), and MATRA is reserved
//! for value transfers only. This adapter:
//!
//!   * `withdraw_fee` returns `Ok(None)` — ZERO side-effects on Balances.
//!   * `correct_and_deposit_fee` returns `Ok(())` — nothing to refund.
//!
//! `TransactionPayment`'s RPC surface (`query_info`, `query_fee_details`,
//! `weight_to_fee`, `length_to_fee`) keeps working — those methods don't
//! call into `OnChargeTransaction`, they compute nominal figures off
//! `WeightToFee` + `LengthToFee` + `NextFeeMultiplier`. Wallets that call
//! those APIs still get a quote; that quote is now informational only.
//!
//! Fee conservation invariant: because `withdraw_fee` does not touch
//! Balances, `total_issuance` is provably conserved across any tx sequence.
//! Exercised by `runtime::tests::motra_only_fees::matra_total_issuance_
//! conserved_under_random_fee_pattern`.

use core::marker::PhantomData;

use frame_support::traits::fungible::{Balanced, Inspect};
use pallet_transaction_payment::OnChargeTransaction;
use sp_runtime::{
    traits::DispatchInfoOf, transaction_validity::TransactionValidityError,
};

/// No-op `OnChargeTransaction` parametrised over the same fungible as the
/// old `FungibleAdapter<F, _>` so we stay swap-compatible at the type-arg
/// site — handy if governance ever wants to re-enable a partial fee.
pub struct NoOpCharge<F>(PhantomData<F>);

impl<T, F> OnChargeTransaction<T> for NoOpCharge<F>
where
    T: pallet_transaction_payment::Config,
    F: Balanced<T::AccountId>,
{
    /// `Balance` is the fungible's balance type (same as the old adapter),
    /// so RPC / weight conversions keep their numeric domain.
    type Balance = <F as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

    /// `LiquidityInfo = ()` — there's nothing to carry through to the
    /// refund hook because we never withdrew anything. Cheaper than the old
    /// `Option<Credit<..>>` (no allocation, no drop-glue).
    type LiquidityInfo = ();

    fn withdraw_fee(
        _who: &<T as frame_system::Config>::AccountId,
        _call: &<T as frame_system::Config>::RuntimeCall,
        _dispatch_info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
        _fee: Self::Balance,
        _tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
        // Withdraw nothing. Critically: we do NOT check whether `fee` is zero
        // before returning Ok — even a "requested fee" of 1_000 MATRA takes
        // zero MATRA from the payer.
        Ok(())
    }

    fn correct_and_deposit_fee(
        _who: &<T as frame_system::Config>::AccountId,
        _dispatch_info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
        _post_info: &sp_runtime::traits::PostDispatchInfoOf<
            <T as frame_system::Config>::RuntimeCall,
        >,
        _corrected_fee: Self::Balance,
        _tip: Self::Balance,
        _already_withdrawn: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
        Ok(())
    }
}
