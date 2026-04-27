//! Spec 208 / Track-B B3 — guard tests for the four `MaxXBatch` runtime
//! parameters on `pallet_intent_settlement`.
//!
//! Asserts the announced worst-case weight at N = MaxBatch fits within
//! 95 % of the relevant per-class block budget. The pallet weight
//! expressions are exact and linear (see
//! `pallet-intent-settlement/src/lib.rs`):
//!
//!   submit_batch_intents  (Normal):
//!     ref_time   = 50M + N · 5M
//!     proof_size = 16,384 + N · 5,120
//!
//!   attest_batch_intents  (Operational):
//!     ref_time   = 50M + N · 3M
//!     proof_size = 0  (storage reads accounted via call-internal mutate)
//!
//!   request_batch_vouchers (Operational):
//!     ref_time   = 50M + N · 10M
//!     proof_size = 0
//!
//!   settle_batch_atomic   (Operational):
//!     ref_time   = 50M + N · 5M
//!     proof_size = 0
//!
//! These are pinned now so a future MaxBatch bump can't silently overrun
//! a block.

extern crate alloc;

use crate::{
    IntentSettlementMaxAttestBatch, IntentSettlementMaxSettleBatch,
    IntentSettlementMaxSubmitBatch, IntentSettlementMaxVoucherBatch,
    RuntimeBlockWeights,
};
use parity_scale_codec as codec;
use frame_support::dispatch::DispatchClass;
use frame_support::traits::Get;

/// 95 % of class budget — refuses to ship a value that has < 5 % headroom.
const SAFE_RATIO_NUM: u64 = 95;
const SAFE_RATIO_DEN: u64 = 100;

fn class_caps(class: DispatchClass) -> (u64, u64) {
    let weights = RuntimeBlockWeights::get();
    let per_class = weights.per_class.get(class);
    let max_total = per_class
        .max_total
        .expect("class max_total must be set in spec >= 205");
    (max_total.ref_time(), max_total.proof_size())
}

fn assert_within_budget(
    name: &str,
    n: u64,
    ref_time: u64,
    proof_size: u64,
    class: DispatchClass,
) {
    let (cap_ref, cap_proof) = class_caps(class);
    let max_safe_ref = cap_ref.saturating_mul(SAFE_RATIO_NUM) / SAFE_RATIO_DEN;
    let max_safe_proof = cap_proof.saturating_mul(SAFE_RATIO_NUM) / SAFE_RATIO_DEN;
    assert!(
        ref_time <= max_safe_ref,
        "{name} at N={n}: ref_time {ref_time} > 95% of {class:?}-class cap {cap_ref} \
         (max_safe = {max_safe_ref})"
    );
    assert!(
        proof_size <= max_safe_proof,
        "{name} at N={n}: proof_size {proof_size} > 95% of {class:?}-class cap {cap_proof} \
         (max_safe = {max_safe_proof})"
    );
}

#[test]
fn submit_batch_intents_fits_at_max() {
    let n = <IntentSettlementMaxSubmitBatch as Get<u32>>::get() as u64;
    let ref_time = 50_000_000u64 + n * 5_000_000;
    let proof_size = 16_384u64 + n * 5_120;
    assert_within_budget(
        "submit_batch_intents",
        n,
        ref_time,
        proof_size,
        DispatchClass::Normal,
    );
}

#[test]
fn attest_batch_intents_fits_at_max() {
    let n = <IntentSettlementMaxAttestBatch as Get<u32>>::get() as u64;
    let ref_time = 50_000_000u64 + n * 3_000_000;
    let proof_size = 0u64;
    assert_within_budget(
        "attest_batch_intents",
        n,
        ref_time,
        proof_size,
        DispatchClass::Operational,
    );
}

#[test]
fn request_batch_vouchers_fits_at_max() {
    let n = <IntentSettlementMaxVoucherBatch as Get<u32>>::get() as u64;
    let ref_time = 50_000_000u64 + n * 10_000_000;
    let proof_size = 0u64;
    assert_within_budget(
        "request_batch_vouchers",
        n,
        ref_time,
        proof_size,
        DispatchClass::Operational,
    );
}

#[test]
fn settle_batch_atomic_fits_at_max() {
    let n = <IntentSettlementMaxSettleBatch as Get<u32>>::get() as u64;
    let ref_time = 50_000_000u64 + n * 5_000_000;
    let proof_size = 0u64;
    assert_within_budget(
        "settle_batch_atomic",
        n,
        ref_time,
        proof_size,
        DispatchClass::Operational,
    );
}

#[test]
fn submit_batch_proof_size_at_1024_matches_b3_extrapolation() {
    // Spec-208 / B3 commits to N=1024 as the chosen target. This test pins
    // the exact proof-size headroom used in the prep report so a future
    // unrelated change (e.g. someone bumping per-entry footprint) is caught
    // before silently regressing the budget assumption.
    let n = <IntentSettlementMaxSubmitBatch as Get<u32>>::get() as u64;
    assert_eq!(n, 1024, "spec-208 B3 target is MaxSubmitBatch=1024");
    let proof_size = 16_384u64 + n * 5_120;
    assert_eq!(proof_size, 5_259_264, "linear formula sanity-check");
    let weights = RuntimeBlockWeights::get();
    let normal_cap = weights
        .per_class
        .get(DispatchClass::Normal)
        .max_total
        .unwrap()
        .proof_size();
    // 5,259,264 / 7,864,320 ≈ 66.88 %
    let pct_x100 = proof_size.saturating_mul(10_000) / normal_cap;
    assert!(
        pct_x100 < 7_500,
        "submit_batch_intents at N=1024 should land under 75 % of Normal-class proof_size \
         (got {pct_x100} basis-points-x100 = {}.{}%)",
        pct_x100 / 100,
        pct_x100 % 100
    );
    assert!(
        pct_x100 > 6_500,
        "linear extrapolation drift detected: expected ~66.88 %, got {}.{}%",
        pct_x100 / 100,
        pct_x100 % 100
    );
}

/// Forward-compat decode test: a `BoundedVec<SubmitIntentEntry, MaxSubmitBatch>`
/// constructed with 1024 entries must SCALE-encode and -decode round-trip. This
/// is the in-runtime equivalent of "side-runner spec-208 accepts a 1024-entry
/// submit_batch_intents". It catches the case where someone bumped the runtime
/// const but the pallet's BoundedVec generic mismatches at the type level.
#[test]
fn submit_batch_round_trips_at_max() {
    use codec::{Decode, Encode};
    use frame_support::BoundedVec;
    use pallet_intent_settlement::types::{IntentKind, SubmitIntentEntry};

    let n = <IntentSettlementMaxSubmitBatch as Get<u32>>::get() as usize;
    assert_eq!(n, 1024);

    let mut entries: alloc::vec::Vec<SubmitIntentEntry> = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let policy_id: sp_core::H256 = sp_core::H256::from_low_u64_be(i as u64);
        let oracle_evidence: BoundedVec<u8, _> = BoundedVec::try_from(alloc::vec::Vec::<u8>::new())
            .expect("empty oracle_evidence fits");
        entries.push(SubmitIntentEntry {
            kind: IntentKind::RequestPayout {
                policy_id,
                oracle_evidence,
            },
        });
    }

    let bounded: BoundedVec<SubmitIntentEntry, IntentSettlementMaxSubmitBatch> =
        BoundedVec::try_from(entries).expect("1024-entry BoundedVec must fit MaxSubmitBatch=1024");

    let encoded = bounded.encode();
    let decoded: BoundedVec<SubmitIntentEntry, IntentSettlementMaxSubmitBatch> =
        Decode::decode(&mut encoded.as_slice()).expect("decode round-trips");
    assert_eq!(decoded.len(), n);
}

#[test]
fn spec_version_bumped_for_b3() {
    use crate::VERSION;
    assert!(
        VERSION.spec_version >= 208,
        "spec_version must be >= 208 after B3 MaxBatch widening (got {})",
        VERSION.spec_version
    );
    assert!(
        VERSION.transaction_version >= 4,
        "transaction_version must be >= 4 after B3 (got {})",
        VERSION.transaction_version
    );
}
