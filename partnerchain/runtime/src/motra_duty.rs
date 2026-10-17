use crate::{AccountId, OrinqReceipts, Runtime, RuntimeCall};
use alloc::{collections::BTreeSet, vec::Vec};
use frame_support::traits::IsSubType;
use parity_scale_codec::Encode;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionValidity, ValidTransaction,
};

// Guardian vetoes retain MAX. Paid calls are capped at MAX-2; receipt-backed
// validator duties have one fixed priority regardless of batch size or R.
const DUTY_PRIORITY: TransactionPriority = TransactionPriority::MAX - 1;

pub fn validate(who: &AccountId, call: &RuntimeCall) -> Option<TransactionValidity> {
    let attestation = |call: &RuntimeCall| match <RuntimeCall as IsSubType<
        pallet_orinq_receipts::Call<Runtime>,
    >>::is_sub_type(call)
    {
        Some(pallet_orinq_receipts::Call::attest_availability_cert {
            receipt_id,
            claimed_hash,
        }) => Some((*receipt_id, *claimed_hash)),
        _ => None,
    };
    let duties: Vec<_> = if let Some(duty) = attestation(call) {
        alloc::vec![duty]
    } else {
        match <RuntimeCall as IsSubType<pallet_utility::Call<Runtime>>>::is_sub_type(call) {
            Some(
                pallet_utility::Call::batch { calls } | pallet_utility::Call::batch_all { calls },
            ) if !calls.is_empty() => calls.iter().map(attestation).collect::<Option<Vec<_>>>()?,
            _ => return None,
        }
    };
    let mut seen = BTreeSet::new();
    let mut provides = Vec::with_capacity(duties.len());
    for (receipt_id, hash) in duties {
        if !seen.insert(receipt_id)
            || OrinqReceipts::validate_attestation(who, receipt_id, hash).is_err()
        {
            return Some(Err(InvalidTransaction::Call.into()));
        }
        provides.push((b"MotraAttestation", who, receipt_id).encode());
    }
    Some(Ok(ValidTransaction {
        priority: DUTY_PRIORITY,
        provides,
        ..Default::default()
    }))
}
