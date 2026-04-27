//! Track A2 — runtime BlockWeights throughput tuning.
//!
//! These tests pin the post-A2 BlockWeights configuration:
//!
//!   - Normal class:      4 s ref_time × NORMAL_DISPATCH_RATIO (75%) = 3 s usable
//!   - Operational class: 4 s ref_time (full)
//!   - Mandatory class:   no max_total cap (system-only, must always fit)
//!   - Block proof_size:  10 MB (10 * 1024 * 1024)
//!
//! Why these targets:
//!
//!   * 4 s ref_time at 1 s block time (A4-lite) means 4× compute headroom per
//!     wall-clock second vs. the substrate default (2 s ref_time at 6 s blocks).
//!     With A2+A4-lite combined, the ref_time/wall-second ratio jumps from
//!     2/6 = 0.33 to 4/1 = 4.0 — a 12× increase in available chain compute.
//!   * 10 MB proof_size — receipt-shaped extrinsics consume ~30–50 KB of
//!     trie-proof per submission; 10 MB allows ~200–300 receipts per block
//!     before the proof-size dimension caps inclusion. The previous u64::MAX
//!     was effectively unbounded, but unbounded proof_size means a
//!     pathological extrinsic could DoS proof generation; a fixed 10 MB cap
//!     is a defence-in-depth measure that still leaves >5× headroom over
//!     realistic workload.
//!
//! Spec version bump: 204 → 205 (this is a chain-behaviour change — older
//! runtimes that don't know the new weight bounds would refuse to ship
//! the same block another node accepts).

use crate::{RuntimeBlockWeights, NORMAL_DISPATCH_RATIO, VERSION};
use frame_support::dispatch::DispatchClass;
use frame_support::weights::constants::WEIGHT_REF_TIME_PER_SECOND;

const TARGET_REF_TIME_PER_BLOCK: u64 = 4 * WEIGHT_REF_TIME_PER_SECOND;
const TARGET_PROOF_SIZE_PER_BLOCK: u64 = 10 * 1024 * 1024;

#[test]
fn normal_class_caps_at_4s_ref_time_times_normal_ratio() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let normal = weights.per_class.get(DispatchClass::Normal);
    let max_total = normal.max_total.expect("Normal class must have a max_total cap");

    // The Normal class is bounded by NORMAL_DISPATCH_RATIO × full-block weight.
    // We assert the *ref_time* dimension matches NORMAL_DISPATCH_RATIO × 4 s.
    let expected_ref_time =
        NORMAL_DISPATCH_RATIO * sp_weights::Weight::from_parts(TARGET_REF_TIME_PER_BLOCK, u64::MAX);

    assert_eq!(
        max_total.ref_time(),
        expected_ref_time.ref_time(),
        "Normal class ref_time = {} but expected {} (= 75% × 4s × WEIGHT_REF_TIME_PER_SECOND)",
        max_total.ref_time(),
        expected_ref_time.ref_time()
    );
}

#[test]
fn operational_class_caps_at_4s_ref_time_full() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let op = weights.per_class.get(DispatchClass::Operational);
    let max_total = op.max_total.expect("Operational class must have a max_total cap");

    // Operational gets the full block budget (no NORMAL_DISPATCH_RATIO).
    assert_eq!(
        max_total.ref_time(),
        TARGET_REF_TIME_PER_BLOCK,
        "Operational class ref_time = {} but expected {} (= 4s × WEIGHT_REF_TIME_PER_SECOND)",
        max_total.ref_time(),
        TARGET_REF_TIME_PER_BLOCK
    );
}

#[test]
fn mandatory_class_has_no_total_cap() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let mand = weights.per_class.get(DispatchClass::Mandatory);
    // Substrate's `BlockWeights::builder()` does NOT set max_total for
    // Mandatory by default — it must always succeed. We assert that
    // contract is still in place after our throughput tuning.
    assert!(
        mand.max_total.is_none(),
        "Mandatory class must NOT have a max_total cap (system-only)"
    );
}

#[test]
fn classes_partition_correctly_no_overflow() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let normal_max = weights.per_class.get(DispatchClass::Normal).max_total
        .expect("Normal must have max_total");
    let op_max = weights.per_class.get(DispatchClass::Operational).max_total
        .expect("Operational must have max_total");

    // Normal must fit within Operational (Normal ⊆ Operational by construction).
    assert!(
        normal_max.ref_time() <= op_max.ref_time(),
        "Normal class ref_time ({}) must NOT exceed Operational ({}) — invariant violated",
        normal_max.ref_time(),
        op_max.ref_time()
    );

    // Block-level max sanity: max_block must accommodate at least Operational.
    assert!(
        weights.max_block.ref_time() >= op_max.ref_time(),
        "max_block ref_time ({}) must be >= Operational max ({})",
        weights.max_block.ref_time(),
        op_max.ref_time()
    );
}

#[test]
fn proof_size_capped_at_10mb_for_normal_class() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let normal = weights.per_class.get(DispatchClass::Normal);
    let max_total = normal.max_total.expect("Normal class must have a max_total cap");

    // Post-A2: proof_size is bounded at 10 MB (75% × 10 MB for Normal).
    // The exact bound after NORMAL_DISPATCH_RATIO is 75% × 10 MB = 7.5 MB.
    let expected_proof =
        NORMAL_DISPATCH_RATIO * sp_weights::Weight::from_parts(0, TARGET_PROOF_SIZE_PER_BLOCK);

    assert_eq!(
        max_total.proof_size(),
        expected_proof.proof_size(),
        "Normal class proof_size = {} but expected {} (= 75% × 10 MB)",
        max_total.proof_size(),
        expected_proof.proof_size()
    );
}

#[test]
fn proof_size_capped_at_10mb_for_operational_class() {
    let weights: frame_system::limits::BlockWeights = RuntimeBlockWeights::get();
    let op = weights.per_class.get(DispatchClass::Operational);
    let max_total = op.max_total.expect("Operational class must have a max_total cap");

    // Operational gets the full 10 MB.
    assert_eq!(
        max_total.proof_size(),
        TARGET_PROOF_SIZE_PER_BLOCK,
        "Operational class proof_size = {} but expected {} (= 10 MB)",
        max_total.proof_size(),
        TARGET_PROOF_SIZE_PER_BLOCK
    );
}

#[test]
fn spec_version_bumped_for_a2() {
    // A2 is a runtime-behaviour change (block-validity rule); spec_version
    // MUST be bumped so post-upgrade nodes don't try to ship blocks that
    // pre-upgrade nodes would reject.
    assert!(
        VERSION.spec_version >= 205,
        "spec_version must be >= 205 after Track A2 BlockWeights bump (got {})",
        VERSION.spec_version
    );
    // Spec 205 left transaction_version at 1 (no SignedExtension change).
    // Spec 206 bumps it to 2 because PR #26 changes the `request_voucher`
    // extrinsic wire format (adds `signatures: Vec<(CommitteePubkey,
    // CommitteeSig)>`). Pre-upgrade clients must refuse to submit, hence the
    // bump.
    assert!(
        VERSION.transaction_version >= 1,
        "transaction_version must be >= 1 (got {})",
        VERSION.transaction_version
    );
}
