//! `pallet-tee-attestation` — Materios TEE attestation primitive (Wave 3 / Phase 2).
//!
//! See `/home/deci/wave-3-polychain-attestation-pallet-design.md` for the
//! design intent and `/home/deci/wave-3-phase-2-acurast-scoping.md` for why
//! we vendor the Acurast Android Key Attestation verifier.
//!
//! ## Phase 2 scope
//!
//! - `EvidenceType::ArmTrustZone` is the only **fully implemented** verifier.
//! - Other variants (`AmdSevSnp`, `IntelTdx`, `ReproducibleBuild`,
//!   `ZkVmExecution`) are typed and dispatched, but their verifiers return
//!   `VerifyFailReason::NotImplemented`. Phases 3.x and 4 will fill these in.
//! - The pallet is NOT yet wired into `construct_runtime!`. Integration is a
//!   separate PR; Phase 2 only ships the standalone verifier + storage +
//!   extrinsic.
//!
//! ## Determinism rules
//!
//! Every committee member's verifier MUST produce identical bytes for the
//! same input. See `feedback_mofn_hash_determinism.md`. The Phase 2 verifier
//! achieves this by:
//!   - Using `include_bytes!` for ALL trust roots (Google RSA, Google P-384,
//!     Apple). No filesystem or network reads.
//!   - Skipping wall-clock validity checks on certificates (would otherwise
//!     diverge by node clock skew).
//!   - Not consulting any external service (no Google CRL, no Acurast
//!     marketplace).
//!
//! ## Storage layout
//!
//! - `Disabled: StorageValue<bool>` — kill-switch for `submit_evidence`.
//!   Defaults `true` at genesis; sudo flips it via `set_disabled` once
//!   Phase 2.5 ships challenge binding (see "Phase 2 status" below).
//! - `CompositeTrustScores: StorageMap<ReceiptId, CompositeTrustScore>` —
//!   the cumulative score after every successful verification.
//! - `VerifiedEntries: StorageMap<ReceiptId, BoundedVec<VerifiedEvidence>>`
//!   — extracted attest_key_hash + raw_level per receipt for audit. Sorted
//!   by `EvidenceType` discriminant (canonical ordering). This is the
//!   canonical per-receipt evidence store; the pallet does NOT keep a
//!   parallel raw-bytes map (the v1 PR-#17 design did, which let any
//!   submitter bloat state with arbitrary `receipt_id`s — see security
//!   review H-2). The verifier runs in-pallet on the extrinsic input and
//!   only the extracted `VerifiedEvidence` is persisted.
//!
//! ## Phase 2 status (kill-switch)
//!
//! Phase 2 ships the verifier with the extrinsic disabled at genesis.
//! Phase 2.5 will bind `attestation_challenge` to the receipt's
//! `content_hash`, at which point this flag is flipped permanently.
//! Without challenge binding the verifier accepts replays of any
//! well-formed Google-rooted chain — a single attestation captured from
//! any compliant Android device can be re-submitted against arbitrary
//! receipt_ids and pass. See the security review of PR #17, finding H-3.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;
pub mod verifier;
// Bundle the vendored Acurast attestation logic as a sub-module of the
// pallet. The `__root_key__` files, `asn.rs`, `error.rs` and
// `attestation.rs` all live under
// `pallets/tee-attestation/vendor/acurast-attestation/`. We use
// `#[path = ...]` to point straight at that directory while avoiding a
// separate sub-crate (which would force its own Cargo.toml + a
// polkadot-stable2409-4 pinning duplicate). The `attestation.rs` entry
// declares `pub mod asn` and `pub mod error` whose own paths resolve
// inside the vendor dir via further #[path] indirection on each.
#[path = "../vendor/acurast-attestation/attestation.rs"]
pub mod acurast_attestation_root;

pub mod vendor {
    pub mod acurast_attestation {
        pub use crate::acurast_attestation_root::*;
        pub mod asn {
            pub use crate::acurast_attestation_root::asn::*;
        }
        pub mod error {
            pub use crate::acurast_attestation_root::error::*;
        }
    }
}

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::prelude::*;

    use crate::types::{
        CompositeTrustScore, EvidenceEntry, EvidenceType, ReceiptId, VendorClass, VerifiedEvidence,
        VerifyOutcome, MAX_EVIDENCE_ENTRIES_PER_RECEIPT,
    };
    use crate::verifier::verify_evidence;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    /// Kill-switch for `submit_evidence`. Defaults `true` at genesis; sudo
    /// flips via `set_disabled` once Phase 2.5 ships challenge binding.
    /// See lib-level "Phase 2 status" docstring + security review H-3.
    #[pallet::storage]
    pub type Disabled<T: Config> = StorageValue<_, bool, ValueQuery, DefaultDisabled<T>>;

    /// Genesis default for `Disabled`: the verifier starts disabled. Phase
    /// 2.5 governance flips it.
    #[pallet::type_value]
    pub fn DefaultDisabled<T: Config>() -> bool {
        true
    }

    /// Successful verifier outputs per receipt. Canonical per-receipt
    /// evidence store; raw evidence bytes are NOT persisted (see lib-level
    /// docstring on the H-2 hardening).
    #[pallet::storage]
    pub type VerifiedEntries<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        ReceiptId,
        BoundedVec<VerifiedEvidence, ConstU32<MAX_EVIDENCE_ENTRIES_PER_RECEIPT>>,
        ValueQuery,
    >;

    /// Composite trust score per receipt — the canonical signal cert-daemon
    /// reads to populate the receipt's `attestation_evidence_hash` field.
    #[pallet::storage]
    pub type CompositeTrustScores<T: Config> =
        StorageMap<_, Blake2_128Concat, ReceiptId, CompositeTrustScore, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        EvidenceVerified {
            receipt_id: ReceiptId,
            evidence_type: EvidenceType,
            attest_key_hash: [u8; 32],
            raw_level: u32,
            new_score: CompositeTrustScore,
        },
        EvidenceRejected {
            receipt_id: ReceiptId,
            evidence_type: EvidenceType,
            reason: u8,
        },
        /// Phase 2 kill-switch flipped via `set_disabled`. Sudo-only.
        DisabledChanged {
            disabled: bool,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `submit_evidence` called when this `ReceiptId` already has the
        /// `MAX_EVIDENCE_ENTRIES_PER_RECEIPT` cap of verified entries.
        TooManyEntries,
        /// The submitted evidence failed verification. The verbose reason
        /// is in the emitted `EvidenceRejected` event.
        VerificationFailed,
        /// The pallet is disabled at genesis (Phase 2 kill-switch). Sudo
        /// flips `Disabled=false` via `set_disabled` once Phase 2.5 ships
        /// challenge binding.
        PalletDisabled,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit one evidence entry for a receipt. Anyone can call.
        ///
        /// On success: the verifier runs, the extracted `VerifiedEvidence`
        /// record is appended to `VerifiedEntries`, and the new
        /// `CompositeTrustScore` is recomputed and stored. Raw evidence
        /// bytes are NOT persisted — only the verifier's extracted
        /// `attest_key_hash` + `raw_level` survive the call.
        // Interim weight (H-1). The original value (10M ref_time, 0 proof
        // bytes) is wildly under-priced for what `submit_evidence` does —
        // the verifier walks an X.509 chain (RSA + P-256 + P-384
        // signature verifies, ASN.1 decode, SHA-256 hashing) plus
        // re-encodes the SPKI for the attest-key hash. Realistic cost is
        // ~500M-1B ref_time + ~32 KB proof_size. Hard-coding 1B / 32 KB
        // here as an interim until the FRAME benchmarking wiring lands
        // (tasks #32 / #33). TODO(#32, #33): replace with generated
        // `WeightInfo::submit_evidence()` from `weights.rs`.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(1_000_000_000, 32_768))]
        pub fn submit_evidence(
            origin: OriginFor<T>,
            receipt_id: ReceiptId,
            content_hash: [u8; 32],
            entry: EvidenceEntry,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Phase 2 kill-switch (H-3 interim mitigation). Disabled at
            // genesis; sudo flips via `set_disabled` once Phase 2.5 binds
            // attestation_challenge to content_hash.
            ensure!(!Disabled::<T>::get(), Error::<T>::PalletDisabled);

            let outcome = verify_evidence(&content_hash, &entry);

            match outcome {
                VerifyOutcome::Verified(verified) => {
                    let mut verified_entries = VerifiedEntries::<T>::get(receipt_id);
                    verified_entries
                        .try_push(verified.clone())
                        .map_err(|_| Error::<T>::TooManyEntries)?;
                    // Canonical ordering: keep verified-entries sorted by
                    // EvidenceType discriminant. Determinism + stable hashing.
                    sort_verified_entries(&mut verified_entries);

                    let score = compose_score(verified_entries.as_slice());
                    VerifiedEntries::<T>::insert(receipt_id, &verified_entries);
                    CompositeTrustScores::<T>::insert(receipt_id, score);

                    Self::deposit_event(Event::EvidenceVerified {
                        receipt_id,
                        evidence_type: verified.evidence_type,
                        attest_key_hash: verified.attest_key_hash,
                        raw_level: verified.raw_level,
                        new_score: score,
                    });
                    Ok(())
                }
                VerifyOutcome::Failed(reason) => {
                    let reason_byte = reason as u8;
                    Self::deposit_event(Event::EvidenceRejected {
                        receipt_id,
                        evidence_type: entry.evidence_type,
                        reason: reason_byte,
                    });
                    Err(Error::<T>::VerificationFailed.into())
                }
            }
        }

        /// Sudo-only: flip the Phase 2 kill-switch. Set `disabled=false`
        /// once Phase 2.5 ships challenge binding (the H-3 interim
        /// mitigation can come off then). The pallet is disabled at
        /// genesis — see lib-level "Phase 2 status" docstring.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(1_000_000_000, 32_768))]
        pub fn set_disabled(origin: OriginFor<T>, disabled: bool) -> DispatchResult {
            ensure_root(origin)?;
            Disabled::<T>::put(disabled);
            Self::deposit_event(Event::DisabledChanged { disabled });
            Ok(())
        }
    }

    /// Read-API helper for cert-daemon — query the composite trust score for
    /// a receipt. Returns the baseline (tier 0) when no evidence has been
    /// verified.
    impl<T: Config> Pallet<T> {
        pub fn trust_score(receipt_id: &ReceiptId) -> CompositeTrustScore {
            if !CompositeTrustScores::<T>::contains_key(receipt_id) {
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            } else {
                CompositeTrustScores::<T>::get(receipt_id)
            }
        }

        pub fn verified_entries(
            receipt_id: &ReceiptId,
        ) -> BoundedVec<VerifiedEvidence, ConstU32<MAX_EVIDENCE_ENTRIES_PER_RECEIPT>> {
            VerifiedEntries::<T>::get(receipt_id)
        }
    }

    /// Compose verified evidence into a CompositeTrustScore.
    /// Mirrors the table in design doc §5.
    pub fn compose_score(verified: &[VerifiedEvidence]) -> CompositeTrustScore {
        // Group by vendor class — collapse 2 AMD chips down to 1 silicon vendor.
        let mut has_silicon_amd = false;
        let mut has_silicon_intel = false;
        let mut has_silicon_arm = false;
        let mut has_silicon_riscv = false;
        let mut has_build_attest = false;
        let mut has_zk_exec = false;

        for v in verified {
            match v.evidence_type.vendor_class() {
                VendorClass::SiliconAmd => has_silicon_amd = true,
                VendorClass::SiliconIntel => has_silicon_intel = true,
                VendorClass::SiliconArm => has_silicon_arm = true,
                VendorClass::SiliconRiscV => has_silicon_riscv = true,
                VendorClass::BuildAttestation => has_build_attest = true,
                VendorClass::ExecutionProof => has_zk_exec = true,
            }
        }

        let silicon_count = (has_silicon_amd as u32)
            + (has_silicon_intel as u32)
            + (has_silicon_arm as u32)
            + (has_silicon_riscv as u32);

        let score = match (silicon_count, has_build_attest, has_zk_exec) {
            (0, _, _) => 0u8,
            (1, _, _) => 1u8,
            (_, false, false) => 2u8,
            (_, true, false) | (_, false, true) => 3u8,
            (_, true, true) => 4u8,
        };
        CompositeTrustScore(score)
    }

    /// Sort `VerifiedEvidence` entries by `EvidenceType` discriminant so the
    /// downstream cert_hash pre-image bytes are deterministic regardless of
    /// extrinsic submission order.
    fn sort_verified_entries(
        entries: &mut BoundedVec<VerifiedEvidence, ConstU32<MAX_EVIDENCE_ENTRIES_PER_RECEIPT>>,
    ) {
        entries.sort_by_key(|v| v.evidence_type as u8);
    }
}
