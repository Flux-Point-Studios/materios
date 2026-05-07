//! Type definitions for `pallet-tee-attestation`.
//!
//! Wave 3 / Phase 2 scope: only `EvidenceType::ArmTrustZone` is implemented.
//! All other variants are typed but their verifiers return `NotImplemented`
//! at runtime. The on-wire SCALE encoding is stable across phases so a
//! receipt submitted with Phase 2 code can be re-verified by Phase 3+ code
//! once the additional verifiers ship — discriminant indices MUST be
//! append-only (see `feedback_pallet_index_shift.md`).

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

use frame_support::pallet_prelude::ConstU32;
use frame_support::BoundedVec;
use sp_runtime::RuntimeDebug;

/// Stable upper bound on the on-chain `EvidenceEntry` payload length per
/// receipt. ARM Key-Attestation chains are typically 4 certs * up to 3000
/// bytes/cert = ~12 kB; we round up. The pallet should not store the raw
/// chain forever — only its canonical hash plus the verifier's extracted
/// outputs — but the extrinsic input must accept the full chain.
pub const MAX_EVIDENCE_PAYLOAD_BYTES: u32 = 16 * 1024;

/// Bound on the number of evidence entries per receipt. Mirrors
/// `BoundedVec<VerifiedEvidence, ConstU32<8>>` from the design doc §3.2.
pub const MAX_EVIDENCE_ENTRIES_PER_RECEIPT: u32 = 8;

/// Receipt identifier. Matches `pallet-orinq-receipts` `ReceiptId`.
pub type ReceiptId = H256;

/// Bounded evidence payload for on-extrinsic submission.
pub type EvidencePayload = BoundedVec<u8, ConstU32<MAX_EVIDENCE_PAYLOAD_BYTES>>;

/// Discriminator for evidence types.
///
/// SCALE-encoded as a 1-byte index. **Indices MUST be append-only** — see
/// design doc §3.2 and `feedback_pallet_index_shift.md`. The pallet's
/// `verifier_for(EvidenceType)` dispatch matches on this discriminant.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
#[repr(u8)]
pub enum EvidenceType {
    /// AMD SEV-SNP attestation report. Phase 3.1 — verifier currently stubs
    /// `NotImplemented`.
    AmdSevSnp = 0,
    /// Intel TDX attestation quote. Phase 3.2 — verifier currently stubs
    /// `NotImplemented`.
    IntelTdx = 1,
    /// Android Hardware Key Attestation. Phase 2 — IMPLEMENTED.
    ArmTrustZone = 2,
    /// Reproducible-build co-attestation (Nix-style nar_hash). Phase 3.3 —
    /// verifier currently stubs `NotImplemented`.
    ReproducibleBuild = 3,
    /// ZK-VM execution proof. Phase 4 — verifier currently stubs
    /// `NotImplemented`.
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

/// On-extrinsic-input evidence entry.
///
/// The `payload` field is the type-specific blob:
/// - `ArmTrustZone`: SCALE-encoded `Vec<Vec<u8>>` — the X.509 cert chain
///   (root → intermediate(s) → leaf attestation cert), DER-encoded.
/// - other variants: TBD when their verifiers ship.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub struct EvidenceEntry {
    pub evidence_type: EvidenceType,
    pub payload: EvidencePayload,
}

/// What the verifier returns on a successful verification. Bytes-deterministic
/// — must produce identical output across all committee members for the same
/// input. See cert_hash determinism notes in design doc §6 and
/// `feedback_mofn_hash_determinism.md`.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub struct VerifiedEvidence {
    pub evidence_type: EvidenceType,
    /// 32-byte SHA-256 hash of the **leaf attestation key's**
    /// SubjectPublicKeyInfo (canonical DER). NOT a stable per-device
    /// identifier — each new KeyStore key produces a new leaf cert, hence
    /// a new SPKI, hence a new hash. The ARM Key Attestation standard
    /// does not expose a chip-stable serial at the leaf level; for
    /// per-chip identity the upstream submitter would have to hash the
    /// chip-stable intermediate cert serial, which is not implemented in
    /// Phase 2. Renamed from `chip_id_hash` (M-2 of the PR-#17 review)
    /// because the old name implied stable per-device identity that this
    /// hash does not provide.
    pub attest_key_hash: [u8; 32],
    /// Vendor-specific level extracted from the attestation extension.
    /// For ARM TrustZone:
    ///   0 = software (rejected by the verifier)
    ///   1 = TEE (TrustZone, not StrongBox)
    ///   2 = StrongBox (hardware-isolated security chip)
    pub raw_level: u32,
}

/// On-chain composite trust score per receipt. 1 byte.
///
/// Tier semantics (from design doc §5):
///   0 — Wave 1+2 baseline (no evidence, M-of-N committee only)
///   1 — Single TEE vendor verified
///   2 — Two unrelated silicon vendors verified
///   3 — Two vendors + (build attestation OR ZK-VM proof)
///   4 — Two vendors + build attestation + ZK-VM proof
#[derive(
    Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, Default,
)]
pub struct CompositeTrustScore(pub u8);

impl CompositeTrustScore {
    /// The Wave 1+2 baseline — no TEE evidence, only M-of-N committee
    /// attestation. Default tier for v2 receipts that pre-date Phase 2.
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

/// Verifier failure reasons. Diagnostic; never enters the cert_hash
/// pre-image (per design doc §6).
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
