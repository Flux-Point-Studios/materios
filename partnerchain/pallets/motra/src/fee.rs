//! MOTRA fee payment as a custom SignedExtension.
//!
//! Computes fee = min_fee + congestion_rate * weight, then burns it from the
//! payer's MOTRA balance.

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{
        InvalidTransaction, TransactionPriority, TransactionValidity, TransactionValidityError,
        ValidTransaction,
    },
};

use frame_support::{dispatch::PostDispatchInfo, traits::ContainsPair};

use crate::pallet::Config;

/// Pay transaction fees in MOTRA.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct ChargeMotra<T: Config + Send + Sync>(core::marker::PhantomData<T>);

impl<T: Config + Send + Sync> ChargeMotra<T> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<T: Config + Send + Sync> core::fmt::Debug for ChargeMotra<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChargeMotra")
    }
}

#[allow(deprecated)]
impl<T> SignedExtension for ChargeMotra<T>
where
    T: Config + Send + Sync,
    <T as frame_system::Config>::RuntimeCall:
        Dispatchable<Info = frame_support::dispatch::DispatchInfo, PostInfo = PostDispatchInfo>,
{
    const IDENTIFIER: &'static str = "ChargeMotra";
    type AccountId = T::AccountId;
    type Call = <T as frame_system::Config>::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = (T::AccountId, u128, u128);

    fn additional_signed(&self) -> Result<(), TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> TransactionValidity {
        let _ = crate::Pallet::<T>::reconcile(who).map_err(|_| InvalidTransaction::Payment)?;

        let fee = crate::Pallet::<T>::compute_fee(info.weight, len);
        let balance = crate::pallet::MotraBalances::<T>::get(who);

        if balance < fee {
            crate::pallet::InsufficientMotraFailures::<T>::mutate(|c| *c = c.saturating_add(1));
            return Err(InvalidTransaction::Payment.into());
        }

        // The guardian's veto is taken ahead of everything: its priority is
        // the ceiling, and fee-paying transactions are capped one below it, so
        // no fee, however large, can outbid it.
        if T::TakenFirst::contains(who, call) {
            let mut tag = who.encode();
            tag.extend_from_slice(b"MotraTakenFirst");
            return Ok(ValidTransaction {
                priority: TransactionPriority::MAX,
                // One tag per signer: the pool keeps a signer to one
                // taken-first transaction, so this priority cannot fill blocks.
                provides: alloc::vec![tag],
                ..Default::default()
            });
        }

        let priority = fee.min(u128::from(TransactionPriority::MAX - 1)) as u64;
        Ok(ValidTransaction {
            priority,
            ..Default::default()
        })
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        let fee = crate::Pallet::<T>::compute_fee(info.weight, len);

        crate::Pallet::<T>::burn_fee(who, fee)
            .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

        Ok((who.clone(), fee, crate::Params::<T>::get().congestion_rate))
    }

    fn post_dispatch(
        pre: Option<Self::Pre>,
        info: &DispatchInfoOf<Self::Call>,
        post_info: &sp_runtime::traits::PostDispatchInfoOf<Self::Call>,
        _len: usize,
        _result: &sp_runtime::DispatchResult,
    ) -> Result<(), TransactionValidityError> {
        if let Some((who, paid, rate)) = pre {
            let declared = rate.saturating_mul(u128::from(info.weight.ref_time())) / 1_000_000;
            let actual = rate
                .saturating_mul(u128::from(post_info.calc_actual_weight(info).ref_time()))
                / 1_000_000;
            let refund = declared.saturating_sub(actual).min(paid);
            if refund > 0 {
                let credited = crate::MotraBalances::<T>::mutate(&who, |balance| {
                    let credited = refund.min(u128::MAX - *balance);
                    *balance += credited;
                    credited
                });
                crate::TotalBurned::<T>::mutate(|total| *total = total.saturating_sub(credited));
                crate::Pallet::<T>::deposit_event(crate::Event::FeeRefunded {
                    who,
                    amount: credited,
                });
            }
        }
        Ok(())
    }
}
