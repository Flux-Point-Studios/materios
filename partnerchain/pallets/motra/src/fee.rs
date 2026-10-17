//! MOTRA fee payment as a custom SignedExtension.
//!
//! Prices the complete signed weight and burns the fee from the payer's MOTRA.

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{
        InvalidTransaction, TransactionPriority, TransactionValidity, TransactionValidityError,
        ValidTransaction,
    },
};

use crate::weights::WeightInfo;
use frame_support::{
    dispatch::PostDispatchInfo,
    traits::{ContainsPair, Get},
    weights::Weight,
};

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
    type Pre = Option<(T::AccountId, u128, u128, u128)>;

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
        if let Some(validity) = T::validate_attestation(who, call) {
            return validity;
        }
        let _ = crate::Pallet::<T>::reconcile(who).map_err(|_| InvalidTransaction::Payment)?;

        let fee = crate::Pallet::<T>::compute_fee(info.weight, len);
        let balance = crate::pallet::MotraBalances::<T>::get(who);

        if balance < fee {
            crate::pallet::InsufficientMotraFailures::<T>::mutate(|c| *c = c.saturating_add(1));
            return Err(InvalidTransaction::Payment.into());
        }

        // The guardian's veto is taken ahead of everything: its priority is
        // the ceiling, and fee-paying transactions are capped below it, so
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

        // Only the non-refundable signed base earns paid priority. Length and
        // declared call weight cannot buy priority that survives a refund.
        let priority = crate::Pallet::<T>::compute_fee(Weight::zero(), 0)
            .min(u128::from(TransactionPriority::MAX - 2)) as u64;
        Ok(ValidTransaction {
            priority,
            ..Default::default()
        })
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        if let Some(validity) = T::validate_attestation(who, call) {
            validity?;
            return Ok(None);
        }
        let fee = crate::Pallet::<T>::compute_fee(info.weight, len);

        crate::Pallet::<T>::burn_fee(who, fee)
            .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

        Ok(Some((
            who.clone(),
            fee,
            crate::Params::<T>::get().congestion_rate,
            crate::Pallet::<T>::compute_fee(Weight::zero(), len),
        )))
    }

    fn post_dispatch(
        pre: Option<Self::Pre>,
        info: &DispatchInfoOf<Self::Call>,
        post_info: &sp_runtime::traits::PostDispatchInfoOf<Self::Call>,
        _len: usize,
        _result: &sp_runtime::DispatchResult,
    ) -> Result<(), TransactionValidityError> {
        if matches!(pre, Some(None)) {
            // Duty validation is included in the attestation weight. No MOTRA
            // reconciliation, burn or refund ran, so release its base budget.
            let unused = <T as Config>::WeightInfo::fee_path()
                .min(T::BlockWeights::get().get(info.class).base_extrinsic);
            frame_system::BlockWeight::<T>::mutate(|weight| weight.reduce(unused, info.class));
        }
        if let Some(Some((who, paid, rate, non_refundable))) = pre {
            let base = T::BlockWeights::get()
                .get(frame_support::dispatch::DispatchClass::Normal)
                .base_extrinsic;
            let declared = crate::Pallet::<T>::weight_fee(base.saturating_add(info.weight), rate);
            let actual = crate::Pallet::<T>::weight_fee(
                base.saturating_add(post_info.calc_actual_weight(info)),
                rate,
            );
            let refund = declared
                .saturating_sub(actual)
                .min(paid.saturating_sub(non_refundable));
            if refund > 0 {
                let cap = crate::Params::<T>::get().max_balance;
                let credited = crate::MotraBalances::<T>::mutate(&who, |balance| {
                    let credited = refund.min(cap.saturating_sub(*balance));
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
