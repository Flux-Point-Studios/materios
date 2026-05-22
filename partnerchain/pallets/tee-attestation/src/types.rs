//! Type definitions for `pallet-tee-attestation`.
//!
//! Only `EvidenceType::ArmTrustZone` is implemented; other variants are
//! typed but their verifiers return `NotImplemented`. Discriminant indices
//! MUST stay append-only so on-wire SCALE encoding is forwards-compatible.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

use frame_support::pallet_prelude::ConstU32;
use frame_support::BoundedVec;
use sp_runtime::RuntimeDebug;

/// Upper bound on the `EvidenceEntry` payload submitted on-extrinsic. ARM
/// Key-Attestation chains run ~12 kB; rounded up.
pub const MAX_EVIDENCE_PAYLOAD_BYTES: u32 = 16 * 1024;

/// Bound on the number of evidence entries per receipt.
pub const MAX_EVIDENCE_ENTRIES_PER_RECEIPT: u32 = 8;

/// Receipt identifier. Matches `pallet-orinq-receipts` `ReceiptId`.
pub type ReceiptId = H256;

/// Bounded evidence payload for on-extrinsic submission.
pub type EvidencePayload = BoundedVec<u8, ConstU32<MAX_EVIDENCE_PAYLOAD_BYTES>>;

/// Discriminator for evidence types. SCALE-encoded as a 1-byte index.
/// Indices MUST stay append-only.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
#[repr(u8)]
pub enum EvidenceType {
    /// AMD SEV-SNP attestation report. Verifier stubs `NotImplemented`.
    AmdSevSnp = 0,
    /// Intel TDX attestation quote. Verifier stubs `NotImplemented`.
    IntelTdx = 1,
    /// Android Hardware Key Attestation. Implemented.
    ArmTrustZone = 2,
    /// Reproducible-build co-attestation. Verifier stubs `NotImplemented`.
    ReproducibleBuild = 3,
    /// ZK-VM execution proof. Verifier stubs `NotImplemented`.
    ZkVmExecution = 4,
}

/// Stable groupings used by the composer. Two evidence entries from the
/// SAME class do NOT count as a multi-vendor quorum.
#[derive(Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub enum VendorClass {
    SiliconAmd,
    SiliconIntel,
    SiliconArm,
    SiliconRiscV,
    BuildAttestation,
    ExecutionProof,
}

impl EvidenceType {
    pub const fn vendor_class(self) -> VendorClass {
        match self {
            EvidenceType::AmdSevSnp => VendorClass::SiliconAmd,
            EvidenceType::IntelTdx => VendorClass::SiliconIntel,
            EvidenceType::ArmTrustZone => VendorClass::SiliconArm,
            EvidenceType::ReproducibleBuild => VendorClass::BuildAttestation,
            EvidenceType::ZkVmExecution => VendorClass::ExecutionProof,
        }
    }
}

/// On-extrinsic-input evidence entry. For `ArmTrustZone` the `payload` is a
/// SCALE-encoded `Vec<Vec<u8>>` X.509 chain (root → intermediates → leaf,
/// DER-encoded).
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub struct EvidenceEntry {
    pub evidence_type: EvidenceType,
    pub payload: EvidencePayload,
}

/// What the verifier returns on success. Must be bytes-deterministic across
/// every committee member for the same input.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub struct VerifiedEvidence {
    pub evidence_type: EvidenceType,
    /// SHA-256 of the leaf attestation key's SubjectPublicKeyInfo (canonical
    /// DER). NOT a stable per-device identifier: each new KeyStore key
    /// produces a new leaf cert, hence a new SPKI, hence a new hash.
    pub attest_key_hash: [u8; 32],
    /// Vendor-specific level. For ARM TrustZone:
    ///   0 = software (rejected)
    ///   1 = TEE (TrustZone, not StrongBox)
    ///   2 = StrongBox (hardware-isolated security chip)
    pub raw_level: u32,
}

/// On-chain composite trust score per receipt.
///
/// Tier semantics:
///   0 — committee-attested baseline (no TEE evidence)
///   1 — single TEE vendor verified
///   2 — two unrelated silicon vendors verified
///   3 — two vendors + (build attestation OR ZK-VM proof)
///   4 — two vendors + build attestation + ZK-VM proof
#[derive(
    Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, Default,
)]
pub struct CompositeTrustScore(pub u8);

impl CompositeTrustScore {
    /// Default tier with no TEE evidence — only M-of-N committee attestation.
    pub const COMMITTEE_ATTESTED_BASELINE: CompositeTrustScore = CompositeTrustScore(0);
    pub const SINGLE_VENDOR: CompositeTrustScore = CompositeTrustScore(1);
    pub const MULTI_VENDOR: CompositeTrustScore = CompositeTrustScore(2);
    pub const MULTI_VENDOR_PLUS_BUILD: CompositeTrustScore = CompositeTrustScore(3);
    pub const FULL_QUORUM: CompositeTrustScore = CompositeTrustScore(4);
}

/// Composer output. Stored on chain alongside `CompositeTrustScore`.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, Default)]
pub struct VerifiedEvidenceSet {
    pub entries: BoundedVec<VerifiedEvidence, ConstU32<MAX_EVIDENCE_ENTRIES_PER_RECEIPT>>,
    pub composite_score: CompositeTrustScore,
    /// Bitset over EvidenceType discriminants (bit 0 = AmdSevSnp, …).
    pub type_bitset: u16,
}

/// Verifier failure reasons. Diagnostic; never enters the cert_hash pre-image.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
pub enum VerifyFailReason {
    NotImplemented,
    PayloadMalformed,
    ChainOfTrustBroken,
    SignatureInvalid,
    NonceMismatch,
    UnknownChipId,
    PolicyViolation,
}

/// Outcome of a single evidence-entry verification.
#[derive(Clone, PartialEq, Eq, RuntimeDebug)]
pub enum VerifyOutcome {
    Verified(VerifiedEvidence),
    Failed(VerifyFailReason),
}
