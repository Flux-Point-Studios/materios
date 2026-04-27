//! Spec-205: pin the `IntentSettlementDefaultMinSignerThreshold` constant
//! at 2 to enforce the bundled bump from the Wave-2 interim M=1.
//!
//! Why this lives here, not in the pallet's own test suite:
//!
//!   * The pallet is git-pinned upstream and treats the threshold as a
//!     `Get<u32>` injected via `Config::DefaultMinSignerThreshold`. The
//!     numeric value is a Materios runtime decision, not a pallet
//!     decision. Pinning it here keeps the constant a load-bearing item
//!     of the runtime upgrade contract.
//!
//!   * Storage semantics: on-chain `IntentSettlement::MinSignerThreshold`
//!     uses `0` as a sentinel meaning "fall back to this Config default"
//!     (see pallet-intent-settlement lib.rs lines 280-282 and the report
//!     at `/tmp/minsigner-threshold-fix-report.md`). Live preprod has
//!     storage = 0 today, so the spec-205 bump takes effect immediately
//!     at the apply-block — no migration required.
//!
//!   * Scope: the bump tightens `settle_claim` and `credit_deposit`,
//!     which DO take a `signatures` argument on-chain. `request_voucher`
//!     does NOT take signatures and is unaffected by this constant —
//!     closing that gap is a separate pallet-code task (#174). See the
//!     spec-205 changelog comment in `lib.rs` and the consolidated
//!     ceremony doc at `/tmp/runtime-upgrade-ceremony.md`.

use crate::IntentSettlementDefaultMinSignerThreshold;
use frame_support::traits::Get;

/// Pin the post-spec-205 numeric value. If a future change relaxes this
/// back to 1 it must be a deliberate edit to this test, surfacing the
/// reverse-tightening for review.
#[test]
fn default_min_signer_threshold_is_2() {
    let val: u32 = <IntentSettlementDefaultMinSignerThreshold as Get<u32>>::get();
    assert_eq!(
        val, 2,
        "spec 205 (consolidated runtime upgrade) bumped \
         IntentSettlementDefaultMinSignerThreshold 1 → 2 to match Aegis \
         2-of-4 expectation; got {}",
        val
    );
}

/// Belt-and-braces: the threshold must be at least the safety floor of
/// 1 (matching the pallet's `max(stored, 1)` floor — see lib.rs lines
/// 1060-1068). Threshold 0 must never appear here because the runtime's
/// `parameter_types!` is the source of the Config default; if it ever
/// went to 0 the pallet's max-floor would still rescue it but every
/// invariant pinning stronger guarantees would silently regress.
#[test]
fn default_min_signer_threshold_is_at_least_one() {
    let val: u32 = <IntentSettlementDefaultMinSignerThreshold as Get<u32>>::get();
    assert!(
        val >= 1,
        "Config default MinSignerThreshold must be ≥ 1 (pallet's effective \
         floor); got {}",
        val
    );
}

/// Document the upgrade direction: spec 204's value was 1, spec 205's
/// is 2. This test pins the *delta*, not just the absolute value.
/// Future bumps (e.g. 2 → 3 when the keeper rolls to 3-of-N) should
/// edit this test alongside the constant to surface the change.
#[test]
fn default_min_signer_threshold_was_bumped_from_1_to_2_at_spec_205() {
    let prior_default: u32 = 1; // value through spec 204
    let current_default: u32 = <IntentSettlementDefaultMinSignerThreshold as Get<u32>>::get();
    assert_ne!(
        prior_default, current_default,
        "spec 205 bump asserted but constant still equals the spec-204 \
         value; expected delta from 1 to ≥ 2"
    );
    assert!(
        current_default > prior_default,
        "post-bump value must strictly exceed prior default ({}); got {}",
        prior_default, current_default
    );
    assert_eq!(
        current_default, 2,
        "spec-205 target is 2 (Aegis 2-of-4); got {}",
        current_default
    );
}

/// Spec version must be ≥ 205 when this constant is at 2 — this links
/// the constant change to its on-chain version flag, so anyone
/// inspecting `runtimeVersion.specVersion` knows the threshold-2 invariant
/// holds.
#[test]
fn spec_version_at_least_205_when_threshold_is_2() {
    use crate::VERSION;
    let val: u32 = <IntentSettlementDefaultMinSignerThreshold as Get<u32>>::get();
    if val == 2 {
        assert!(
            VERSION.spec_version >= 205,
            "MinSignerThreshold-default = 2 implies spec_version ≥ 205, got {}",
            VERSION.spec_version
        );
    }
}
