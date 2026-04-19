//! v5.1 tokenomics — Fee router (OnUnbalanced 40/30/20/10).
//!
//! Replaces the default author-only fee handler with a four-way split:
//!
//!   40% -> author pot (PalletId "mat/auth"; pallet_block_rewards pays out
//!         to SPOs on epoch rotation)
//!   30% -> attestor reserve (PalletId "mat/attr"; drained by the attestor
//!         slashing/reward pallet — Component 8 — once it lands)
//!   20% -> treasury (pallet_treasury::account_id())
//!   10% -> burn (dropped Credit -> total_issuance decreases)
//!
//! Rounding: the three non-burn shares are computed with saturating integer
//! division, then the remainder of the original credit IS the burn. This
//! guarantees `author + reserve + treasury + burn == fee` for every input.
//!
//! IMPORTANT: the default `on_unbalanceds` implementation on `OnUnbalanced`
//! merges the two incoming credits (fee + tip) into a single imbalance before
//! calling `on_unbalanced`, so we implement the split in `on_nonzero_unbalanced`
//! and the fee/tip aggregation happens for free.

use core::marker::PhantomData;

use frame_support::traits::{
    fungible::{Balanced, Credit, Inspect},
    tokens::imbalance::Imbalance,
    OnUnbalanced,
};

use crate::{AccountId, Balances};

/// The fee-router type plugged into `FungibleAdapter` for
/// `pallet_transaction_payment::Config::OnChargeTransaction`.
pub struct DealWithFees<R>(PhantomData<R>);

impl<R> OnUnbalanced<Credit<AccountId, Balances>> for DealWithFees<R>
where
    R: pallet_balances::Config
        + frame_system::Config<AccountId = AccountId>
        + pallet_treasury::Config,
{
    /// A non-zero fee imbalance has arrived. Split 40/30/20/10.
    fn on_nonzero_unbalanced(total: Credit<AccountId, Balances>) {
        // Guard: caller shouldn't send zero here (the trait default handles
        // that via `on_unbalanced` + `try_drop`), but be defensive.
        if <Credit<AccountId, Balances> as Imbalance<
            <Balances as Inspect<AccountId>>::Balance,
        >>::peek(&total)
            == 0
        {
            return;
        }

        // 40% author off the top; 60% remainder.
        let (author_share, rest) = total.ration(40, 60);
        // Of the 60%, split 30:30 (attestor-reserve vs treasury+burn).
        let (reserve_share, tail) = rest.ration(30, 30);
        // Of the 30%, split 20:10 (treasury vs burn).
        let (treasury_share, burn_share) = tail.ration(20, 10);

        // Route each share. Failed deposits (e.g. account-existence checks)
        // are absorbed into the burn bucket so no value leaks.
        let burn_share = deposit_or_burn(&author_pot_account(), author_share, burn_share);
        let burn_share =
            deposit_or_burn(&crate::attestor_reserve_account(), reserve_share, burn_share);
        let burn_share =
            deposit_or_burn(&crate::treasury_account(), treasury_share, burn_share);

        // Drop the burn share: Credit is a *negative* imbalance — dropping
        // reduces total_issuance, which is exactly the burn semantics we want.
        drop(burn_share);
    }
}

/// Try to resolve `share` into `dest`. On failure, merge it into `fallback`.
///
/// Returns the (possibly augmented) fallback credit for the caller to route
/// further or drop.
fn deposit_or_burn(
    dest: &AccountId,
    share: Credit<AccountId, Balances>,
    fallback: Credit<AccountId, Balances>,
) -> Credit<AccountId, Balances> {
    match <Balances as Balanced<AccountId>>::resolve(dest, share) {
        Ok(()) => fallback,
        // `resolve` returns the credit back on failure (e.g. ED check).
        // `Imbalance::merge` on same-currency credits cannot fail.
        Err(returned) => fallback.merge(returned),
    }
}

/// Canonical author-pot account derived from the "mat/auth" PalletId.
///
/// The 40% author share is credited to this deterministic account regardless
/// of whether the current block has an identifiable author — this keeps the
/// router pure (no reads from consensus state) while still routing the share
/// to a place governance / the block-rewards pallet can drain.
pub fn author_pot_account() -> AccountId {
    use sp_runtime::traits::AccountIdConversion;
    frame_support::PalletId(*b"mat/auth").into_account_truncating()
}
