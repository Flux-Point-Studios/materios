//! Materios TEE attestation primitive.
//!
//! Only `EvidenceType::ArmTrustZone` is fully implemented; other verifiers
//! return `VerifyFailReason::NotImplemented`.
//!
//! Determinism: every committee member's verifier MUST produce identical
//! bytes for the same input. The verifier uses `include_bytes!` for all
//! trust roots, judges certificate validity at the block timestamp
//! (`Config::UnixTime`), reads revocations from `RevokedCertificates`, and
//! never consults external services.
//!
//! Receipt binding: `submit_evidence` reads the receipt's content hash from
//! the receipt registry (`Config::Receipts`) and the chain's genesis hash
//! from System, and an ArmTrustZone leaf counts only if its
//! `attestationChallenge` equals `verifier::arm_trustzone_challenge` over
//! them. A chain minted for one receipt verifies for no other receipt and on
//! no other network. Only the receipt's submitter and the receipt committee
//! may attach evidence, and a receipt holds one entry per evidence type.
//!
//! `Disabled` is `true` at genesis; Root releases it with `set_disabled`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod migrations;
pub mod types;
pub mod verifier;
pub mod weights;
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

/// Read access to the receipt registry evidence attaches to, and to the
/// committee that certifies its receipts.
pub trait ReceiptRegistry<AccountId> {
    /// The content hash and submitter recorded for `receipt_id`, if the
    /// receipt exists.
    fn receipt(receipt_id: &types::ReceiptId) -> Option<types::RegisteredReceipt<AccountId>>;
    /// Whether `who` sits on the receipt committee.
    fn is_committee_member(who: &AccountId) -> bool;
    /// Records a receipt submitted by `submitter`.
    #[cfg(feature = "runtime-benchmarks")]
    fn register_receipt(receipt_id: types::ReceiptId, content_hash: [u8; 32], submitter: AccountId);
    /// Seats `who` on the receipt committee.
    #[cfg(feature = "runtime-benchmarks")]
    fn add_committee_member(who: AccountId);
}

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::traits::UnixTime;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_runtime::traits::Zero;
    use sp_std::prelude::*;

    use crate::types::{
        CertificateSerial, CompositeTrustScore, EvidenceEntry, EvidenceType, ReceiptBinding,
        ReceiptId, VendorClass, VerifiedEvidence, VerifyOutcome, MAX_ENTRIES_PER_EVIDENCE_TYPE,
        MAX_EVIDENCE_ENTRIES_PER_RECEIPT, MAX_REVOCATIONS_PER_CALL, MAX_REVOKED_CERTIFICATES,
    };
    use crate::verifier::{
        claimed_attest_key_hash, verify_evidence, ArmTrustZoneVerifier, GOOGLE_ATTESTATION_ROOTS,
    };
    use crate::ReceiptRegistry;

    /// Version 1 holds only evidence bound to its receipt
    /// (`migrations::ClearUnboundEvidence`).
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<Hash = H256> {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// The receipt registry whose content hashes evidence binds to.
        type Receipts: ReceiptRegistry<Self::AccountId>;
        /// The block timestamp certificate validity is checked against.
        type UnixTime: UnixTime;
    }

    /// Kill-switch for `submit_evidence`. Defaults `true` at genesis; Root
    /// flips it with `set_disabled`.
    #[pallet::storage]
    pub type Disabled<T: Config> = StorageValue<_, bool, ValueQuery, DefaultDisabled<T>>;

    /// Genesis default for `Disabled`: the verifier starts disabled.
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

    /// Revoked attestation certificates, by serial number (big-endian
    /// magnitude without leading zero bytes). A chain with any of them above
    /// its leaf is rejected.
    #[pallet::storage]
    pub type RevokedCertificates<T: Config> =
        StorageMap<_, Blake2_128Concat, CertificateSerial, (), OptionQuery>;

    /// Number of entries in `RevokedCertificates`, at most
    /// `MAX_REVOKED_CERTIFICATES`.
    #[pallet::storage]
    pub type RevokedCertificateCount<T: Config> = StorageValue<_, u32, ValueQuery>;

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
        /// Deposited when verification rejects evidence. The call then fails,
        /// so the event is rolled back with it and never reaches a block.
        EvidenceRejected {
            receipt_id: ReceiptId,
            evidence_type: EvidenceType,
            reason: u8,
        },
        /// Kill-switch flipped via `set_disabled`. Sudo-only.
        DisabledChanged { disabled: bool },
        /// `set_certificates_revoked` changed a serial's revocation state.
        CertificateRevocationSet {
            serial: CertificateSerial,
            revoked: bool,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `submit_evidence` called when this `ReceiptId` already has the
        /// `MAX_EVIDENCE_ENTRIES_PER_RECEIPT` cap of verified entries.
        TooManyEntries,
        /// The submitted evidence failed verification. The reason is not kept
        /// on chain: `EvidenceRejected` is rolled back with the failing call.
        /// `verifier::verify_evidence` over the same inputs reproduces it.
        VerificationFailed,
        /// The pallet's kill-switch (`Disabled`) is engaged.
        PalletDisabled,
        /// `receipt_id` names no receipt in the receipt registry.
        UnknownReceipt,
        /// `content_hash` differs from the content hash the receipt registry
        /// holds for `receipt_id`.
        ContentHashMismatch,
        /// The receipt already holds evidence from this attested key.
        DuplicateEvidence,
        /// The signer is neither the receipt's submitter nor a member of the
        /// receipt committee.
        UnauthorizedSubmitter,
        /// The receipt already holds `MAX_ENTRIES_PER_EVIDENCE_TYPE` entries
        /// of this evidence type, from another key.
        EvidenceTypeFull,
        /// A serial is empty or starts with a zero byte, so it would match
        /// no certificate's serial magnitude.
        NonCanonicalSerial,
        /// `RevokedCertificates` already holds `MAX_REVOKED_CERTIFICATES`
        /// serials.
        TooManyRevokedCertificates,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit one evidence entry for a receipt. The signer must be the
        /// receipt's submitter or a member of the receipt committee (the
        /// cert-daemon's evidence submitter signs with its committee key).
        ///
        /// `content_hash` must be the content hash the receipt registry holds
        /// for `receipt_id`. A receipt holds one entry per evidence type. These
        /// checks run before any certificate is verified. On success, the
        /// extracted `VerifiedEvidence` is appended to `VerifiedEntries`, and
        /// the new `CompositeTrustScore` is recomputed and stored.
        #[pallet::call_index(0)]
        #[pallet::weight(crate::weights::submit_evidence::<T>())]
        pub fn submit_evidence(
            origin: OriginFor<T>,
            receipt_id: ReceiptId,
            content_hash: [u8; 32],
            entry: EvidenceEntry,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::accept_evidence(
                &who,
                receipt_id,
                content_hash,
                &entry,
                &GOOGLE_ATTESTATION_ROOTS,
            )
        }

        /// Root-only: engage (`true`) or release (`false`) the kill-switch.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(1_000_000_000, 32_768))]
        pub fn set_disabled(origin: OriginFor<T>, disabled: bool) -> DispatchResult {
            ensure_root(origin)?;
            Disabled::<T>::put(disabled);
            Self::deposit_event(Event::DisabledChanged { disabled });
            Ok(())
        }

        /// Root-only: revoke (`true`) or clear (`false`) attestation
        /// certificates by serial number, the big-endian magnitude Google's
        /// attestation status list writes in hex. A chain with a revoked
        /// certificate above its leaf is rejected.
        #[pallet::call_index(2)]
        #[pallet::weight(
            Weight::from_parts(10_000_000, 1_024)
                .saturating_add(T::DbWeight::get().reads_writes(1, 1))
                .saturating_add(
                    Weight::from_parts(5_000_000, 128)
                        .saturating_add(T::DbWeight::get().reads_writes(1, 1))
                        .saturating_mul(serials.len() as u64)
                )
        )]
        pub fn set_certificates_revoked(
            origin: OriginFor<T>,
            serials: BoundedVec<CertificateSerial, ConstU32<MAX_REVOCATIONS_PER_CALL>>,
            revoked: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                serials
                    .iter()
                    .all(|serial| serial.first().is_some_and(|b| *b != 0)),
                Error::<T>::NonCanonicalSerial
            );
            let mut count = RevokedCertificateCount::<T>::get();
            for serial in serials {
                if RevokedCertificates::<T>::contains_key(&serial) == revoked {
                    continue;
                }
                if revoked {
                    ensure!(
                        count < MAX_REVOKED_CERTIFICATES,
                        Error::<T>::TooManyRevokedCertificates
                    );
                    RevokedCertificates::<T>::insert(&serial, ());
                    count += 1;
                } else {
                    RevokedCertificates::<T>::remove(&serial);
                    count -= 1;
                }
                Self::deposit_event(Event::CertificateRevocationSet { serial, revoked });
            }
            RevokedCertificateCount::<T>::put(count);
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// `submit_evidence` after the origin check. `arm_trustzone_roots` are
        /// the anchors ArmTrustZone chains may start from.
        pub(crate) fn accept_evidence(
            who: &T::AccountId,
            receipt_id: ReceiptId,
            content_hash: [u8; 32],
            entry: &EvidenceEntry,
            arm_trustzone_roots: &[&[u8]],
        ) -> DispatchResult {
            ensure!(!Disabled::<T>::get(), Error::<T>::PalletDisabled);

            let receipt = T::Receipts::receipt(&receipt_id).ok_or(Error::<T>::UnknownReceipt)?;
            ensure!(
                *who == receipt.submitter || T::Receipts::is_committee_member(who),
                Error::<T>::UnauthorizedSubmitter
            );
            ensure!(
                receipt.content_hash == content_hash,
                Error::<T>::ContentHashMismatch
            );

            let mut verified_entries = VerifiedEntries::<T>::get(receipt_id);
            let claimed = claimed_attest_key_hash(entry);
            let held: Vec<&VerifiedEvidence> = verified_entries
                .iter()
                .filter(|v| v.evidence_type == entry.evidence_type)
                .collect();
            ensure!(
                !held.iter().any(|v| Some(v.attest_key_hash) == claimed),
                Error::<T>::DuplicateEvidence
            );
            ensure!(
                (held.len() as u32) < MAX_ENTRIES_PER_EVIDENCE_TYPE,
                Error::<T>::EvidenceTypeFull
            );

            let binding = ReceiptBinding {
                genesis_hash: frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()).0,
                receipt_id,
                content_hash,
            };

            let is_revoked = |serial: &[u8]| {
                CertificateSerial::try_from(serial.to_vec())
                    .is_ok_and(RevokedCertificates::<T>::contains_key)
            };
            let arm_trustzone = ArmTrustZoneVerifier {
                trusted_roots: arm_trustzone_roots,
                now: T::UnixTime::now().as_secs(),
                is_revoked: &is_revoked,
            };

            match verify_evidence(&binding, entry, &arm_trustzone) {
                VerifyOutcome::Verified(verified) => {
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
