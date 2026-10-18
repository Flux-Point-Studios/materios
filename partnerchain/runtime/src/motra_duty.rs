use crate::{AccountId, ExtrinsicBaseWeight, OrinqReceipts, Runtime, RuntimeCall};
use alloc::{collections::BTreeSet, vec::Vec};
use core::slice;
use frame_support::{
    traits::{Get, IsSubType},
    weights::Weight,
};
use pallet_orinq_receipts::{types::Attestation, weights::WeightInfo};
use parity_scale_codec::Encode;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionValidity, ValidTransaction,
};

// Guardian vetoes retain MAX. Paid calls are capped at MAX-2; receipt-backed
// validator duties have one fixed priority regardless of batch size or R.
const DUTY_PRIORITY: TransactionPriority = TransactionPriority::MAX - 1;

/// A batch may carry stale attests, which dispatch as benign no-ops, only up
/// to the number of new ones, so free weight stays bounded by new duties.
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
    let mut stale = 0usize;
    for (receipt_id, hash) in duties {
        if !seen.insert(receipt_id) {
            return Some(Err(InvalidTransaction::Call.into()));
        }
        match OrinqReceipts::validate_attestation(who, receipt_id, hash) {
            Ok(Attestation::New) => provides.push((b"MotraAttestation", who, receipt_id).encode()),
            Ok(Attestation::Stale) => stale += 1,
            Err(_) => return Some(Err(InvalidTransaction::Call.into())),
        }
    }
    if provides.is_empty() || stale > provides.len() {
        return Some(Err(InvalidTransaction::Call.into()));
    }
    Some(Ok(ValidTransaction {
        priority: DUTY_PRIORITY,
        provides,
        ..Default::default()
    }))
}

/// The feeless certification work the receipts `call` submits commit the
/// committee to, priced with the submission.
pub fn deferred_weight(call: &RuntimeCall) -> Weight {
    match submissions(call) {
        0 => Weight::zero(),
        receipts => certification_weight().saturating_mul(receipts.into()),
    }
}

/// At the current threshold `t`: `t` signed attest duties, the `t - 1`
/// non-threshold attests before the payout, each bounded by the last since
/// the signer count only grows while the committee is unchanged, and the
/// payout attest with its signers', submitter's and treasury's balance
/// changes. A member who leaves after signing costs one further attest from
/// a current member, which this price does not cover.
fn certification_weight() -> Weight {
    type W = <Runtime as pallet_orinq_receipts::Config>::WeightInfo;
    let t = pallet_orinq_receipts::AttestationThreshold::<Runtime>::get().clamp(
        1,
        <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize::get(),
    );
    ExtrinsicBaseWeight::get()
        .saturating_mul(t.into())
        .saturating_add(W::attest_non_threshold(t - 1).saturating_mul((t - 1).into()))
        .saturating_add(W::attest_threshold(t))
        .saturating_add(W::balance_mutations(t.saturating_add(2)))
}

/// The threshold read `deferred_weight` makes before dispatch, charged to
/// each submission's own weight. Its proof bound is a u32 value under three
/// 495-byte trie layers.
pub fn threshold_read() -> Weight {
    <Runtime as frame_system::Config>::DbWeight::get()
        .reads(1)
        .saturating_add(Weight::from_parts(0, 4 + 3 * 495))
}

fn submissions(call: &RuntimeCall) -> u64 {
    match call {
        RuntimeCall::OrinqReceipts(
            pallet_orinq_receipts::Call::submit_receipt { .. }
            | pallet_orinq_receipts::Call::submit_receipt_v2 { .. },
        ) => 1,
        _ => carried(call)
            .iter()
            .map(submissions)
            .fold(0, u64::saturating_add),
    }
}

/// The calls a wrapper carries, whatever origin it dispatches them under.
pub(crate) fn carried(call: &RuntimeCall) -> &[RuntimeCall] {
    match call {
        RuntimeCall::Utility(
            pallet_utility::Call::batch { calls }
            | pallet_utility::Call::batch_all { calls }
            | pallet_utility::Call::force_batch { calls },
        ) => calls,
        RuntimeCall::Utility(
            pallet_utility::Call::as_derivative { call, .. }
            | pallet_utility::Call::dispatch_as { call, .. }
            | pallet_utility::Call::with_weight { call, .. },
        )
        | RuntimeCall::Sudo(
            pallet_sudo::Call::sudo { call }
            | pallet_sudo::Call::sudo_unchecked_weight { call, .. }
            | pallet_sudo::Call::sudo_as { call, .. },
        )
        | RuntimeCall::Multisig(
            pallet_multisig::Call::as_multi_threshold_1 { call, .. }
            | pallet_multisig::Call::as_multi { call, .. },
        )
        | RuntimeCall::Recovery(pallet_recovery::Call::as_recovered { call, .. })
        | RuntimeCall::RootTimelock(
            pallet_root_timelock::Call::schedule { call }
            | pallet_root_timelock::Call::enact { call, .. }
            | pallet_root_timelock::Call::enact_approved { call },
        ) => slice::from_ref(call.as_ref()),
        _ => &[],
    }
}
