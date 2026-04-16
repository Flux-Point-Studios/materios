//! MOTRA fee payment -- custom SignedExtension.
//!
//! Computes fee = min_fee + congestion_rate * weight, then burns from payer's MOTRA balance.

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{
        InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
    },
};

use frame_support::dispatch::PostDispatchInfo;

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

#[allow(deprecated)] // SignedExtension is deprecated in favour of TransactionExtension
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
    type Pre = (T::AccountId, u128); // (who, fee_amount)

    fn additional_signed(&self) -> Result<(), TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> TransactionValidity {
        // Reconcile balance (apply decay + generation).
        let _ =
            crate::Pallet::<T>::reconcile(who).map_err(|_| InvalidTransaction::Payment)?;

        let fee = crate::Pallet::<T>::compute_fee(info.weight, len);
        let balance = crate::pallet::MotraBalances::<T>::get(who);

        if balance < fee {
            crate::pallet::InsufficientMotraFailures::<T>::mutate(|c| *c = c.saturating_add(1));
            return Err(InvalidTransaction::Payment.into());
        }

        let priority = fee.min(u64::MAX as u128) as u64;
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

        // Burn MOTRA.
        crate::Pallet::<T>::burn_fee(who, fee)
            .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

        Ok((who.clone(), fee))
    }

    fn post_dispatch(
        _pre: Option<Self::Pre>,
        _info: &DispatchInfoOf<Self::Call>,
        _post_info: &sp_runtime::traits::PostDispatchInfoOf<Self::Call>,
        _len: usize,
        _result: &sp_runtime::DispatchResult,
    ) -> Result<(), TransactionValidityError> {
        // No refund for MVP -- fee is fully burned regardless of actual weight used.
        // Future: could refund unused portion.
        Ok(())
    }
}
