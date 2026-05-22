//! Materios TEE attestation primitive.
//!
//! Only `EvidenceType::ArmTrustZone` is fully implemented; other verifiers
//! return `VerifyFailReason::NotImplemented`.
//!
//! Determinism: every committee member's verifier MUST produce identical
//! bytes for the same input. The verifier uses `include_bytes!` for all
//! trust roots, skips wall-clock validity checks, and never consults
//! external services.
//!
//! `Disabled` is `true` at genesis and stays so until `submit_evidence`
//! binds `attestation_challenge` to the receipt's `content_hash`. Without
//! that binding the verifier accepts replays of any well-formed
//! Google-rooted chain against arbitrary `receipt_id`s.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;
pub mod verifier;
// `#[path = ...]` points at the vendored Acurast attestation logic without
// adding a sub-crate.
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

    /// Successful verifier outputs per receipt. Raw evidence bytes are NOT
    /// persisted.
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
        /// Kill-switch flipped via `set_disabled`. Sudo-only.
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
        /// The pallet's kill-switch is engaged. Sudo flips `Disabled=false`
        /// via `set_disabled` once challenge binding ships.
        PalletDisabled,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit one evidence entry for a receipt. Anyone can call.
        ///
        /// On success, the verifier runs, the extracted `VerifiedEvidence`
        /// is appended to `VerifiedEntries`, and the new
        /// `CompositeTrustScore` is recomputed and stored.
        // Hand-tuned weight: 1B ref_time / 32 KB proof_size covers an X.509
        // chain walk + ASN.1 decode + SPKI re-encode.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(1_000_000_000, 32_768))]
        pub fn submit_evidence(
            origin: OriginFor<T>,
            receipt_id: ReceiptId,
            content_hash: [u8; 32],
            entry: EvidenceEntry,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            ensure!(!Disabled::<T>::get(), Error::<T>::PalletDisabled);

            let outcome = verify_evidence(&content_hash, &entry);

            match outcome {
                VerifyOutcome::Verified(verified) => {
                    let mut verified_entries = VerifiedEntries::<T>::get(receipt_id);
                    verified_entries
                        .try_push(verified.clone())
                        .map_err(|_| Error::<T>::TooManyEntries)?;
                    // Sort by EvidenceType discriminant for canonical ordering.
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

        /// Sudo-only: flip the kill-switch. Set `disabled=false` once
        /// challenge binding ships.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(1_000_000_000, 32_768))]
        pub fn set_disabled(origin: OriginFor<T>, disabled: bool) -> DispatchResult {
            ensure_root(origin)?;
            Disabled::<T>::put(disabled);
            Self::deposit_event(Event::DisabledChanged { disabled });
            Ok(())
        }
    }

    /// Read-API helpers. `trust_score` returns the baseline when no
    /// evidence has been verified.
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
    pub fn compose_score(verified: &[VerifiedEvidence]) -> CompositeTrustScore {
        // Collapse multiple chips from the same vendor down to one.
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
