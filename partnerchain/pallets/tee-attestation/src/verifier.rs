//! Verifier trait and concrete implementations.
//!
//! Only `ArmTrustZoneVerifier` is implemented; the others return
//! `VerifyFailReason::NotImplemented`. The dispatch table in `lib.rs` calls
//! the right verifier based on `EvidenceType`.
//!
//! Determinism rules:
//!   - All trust roots are pinned via `include_bytes!`.
//!   - No network calls in the verify path.
//!   - No wall-clock checks: certificate `not_before`/`not_after` would
//!     diverge by node clock skew.
//!   - `attest_key_hash` is SHA-256 of the leaf cert's SPKI in canonical DER.
//!
//! For `EvidenceType::ArmTrustZone`, `EvidenceEntry::payload` is a
//! SCALE-encoded `Vec<Vec<u8>>` X.509 chain (root → intermediates → leaf,
//! DER-encoded). The chain may omit the root if its public key matches one
//! of the pinned trust roots.

use alloc::vec::Vec;
use parity_scale_codec::Decode;
use sp_std::prelude::*;

use crate::types::{
    EvidenceEntry, EvidenceType, VerifiedEvidence, VerifyFailReason, VerifyOutcome,
};
use crate::vendor::acurast_attestation::asn::{KeyDescription, ParsedAttestation};
use crate::vendor::acurast_attestation::{
    extract_attestation, validate_certificate_chain, CertificateChainInput, CertificateInput,
};

use sha2::{Digest, Sha256};

/// Trait every evidence verifier implements. Implementations MUST produce
/// bit-identical `VerifyOutcome::Verified` records for identical inputs
/// across all committee members.
pub trait EvidenceVerifier {
    fn evidence_type(&self) -> EvidenceType;

    /// Verify a single evidence entry. `content_hash` is the receipt's
    /// `content_hash`; verifiers MAY use it to bind the evidence to the
    /// receipt. `ArmTrustZoneVerifier` currently does NOT check the
    /// challenge field.
    fn verify(&self, content_hash: &[u8; 32], entry: &EvidenceEntry) -> VerifyOutcome;
}

/// ARM TrustZone (Android Hardware Key Attestation) verifier.
///
/// Wraps the vendored Acurast logic. The verifier:
///   1. SCALE-decodes the cert chain bytes from the entry payload.
///   2. Calls Acurast's `validate_certificate_chain` to walk
///      Google Root → Intermediate(s) → Leaf, verifying every signature.
///   3. Calls `extract_attestation` on the leaf cert's extension to confirm
///      the leaf is a Key-Attestation cert (vs unrelated leaf).
///   4. Reads the security level (TEE / StrongBox) from the
///      `KeyDescription`.
///   5. Computes `attest_key_hash = sha256(leaf_subject_public_key_info DER)`.
pub struct ArmTrustZoneVerifier;

impl EvidenceVerifier for ArmTrustZoneVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ArmTrustZone
    }

    fn verify(&self, _content_hash: &[u8; 32], entry: &EvidenceEntry) -> VerifyOutcome {
        debug_assert_eq!(entry.evidence_type, EvidenceType::ArmTrustZone);
        // 1. Decode the chain.
        let raw_chain: Vec<Vec<u8>> = match Vec::<Vec<u8>>::decode(&mut &entry.payload[..]) {
            Ok(c) => c,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed),
        };

        if raw_chain.is_empty() {
            return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed);
        }

        let chain = match build_chain_input(raw_chain) {
            Ok(c) => c,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed),
        };

        // 2. Walk the chain — every link signature has to verify.
        let (_cert_ids, leaf_tbs, _last_pbk) = match validate_certificate_chain(&chain) {
            Ok(t) => t,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::ChainOfTrustBroken),
        };

        // 3. Confirm the leaf is a Key-Attestation cert.
        let parsed = match extract_attestation(leaf_tbs.extensions) {
            Ok(p) => p,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation),
        };

        let raw_level = match &parsed {
            ParsedAttestation::KeyDescription(kd) => key_description_security_level(kd),
            ParsedAttestation::DeviceAttestation(_) => {
                // Apple device-attestation extension instead of an Android
                // Key-Attestation extension — out of scope for ArmTrustZone.
                return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
            }
        };

        // Positive allowlist: only TrustedEnvironment (1) and StrongBox (2)
        // represent attested hardware-rooted keys; reject everything else.
        if !is_security_level_allowed(raw_level) {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // attest_key_hash = sha256 of the SPKI re-encoded to canonical DER.
        let spki_der = match asn1::write_single(&leaf_tbs.subject_public_key_info) {
            Ok(b) => b,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed),
        };
        let attest_key_hash = sha256_array(&spki_der);

        VerifyOutcome::Verified(VerifiedEvidence {
            evidence_type: EvidenceType::ArmTrustZone,
            attest_key_hash,
            raw_level,
        })
    }
}

/// Positive allowlist of AOSP `SecurityLevel` values representing attested
/// hardware: 1 = TrustedEnvironment (TEE), 2 = StrongBox. Reject Software
/// (0), Keystore (3), and anything outside the AOSP-defined enum range.
/// Ref: <https://source.android.com/docs/security/features/keystore/attestation>
pub(crate) fn is_security_level_allowed(raw_level: u32) -> bool {
    raw_level == 1 || raw_level == 2
}

/// Read `key_mint_security_level` (where the attested key lives), not
/// `attestation_security_level` (where the signer lives). A TEE-attested
/// chain that mints the key in software produces
/// `attestation_security_level=1, key_mint_security_level=0` and must be
/// rejected.
pub(crate) fn key_description_security_level(kd: &KeyDescription<'_>) -> u32 {
    let sl_value = match kd {
        KeyDescription::V1(v) => v.key_mint_security_level.value(),
        KeyDescription::V2(v) => v.key_mint_security_level.value(),
        KeyDescription::V3(v) => v.key_mint_security_level.value(),
        KeyDescription::V4(v) => v.key_mint_security_level.value(),
        KeyDescription::V100(v) => v.key_mint_security_level.value(),
        KeyDescription::V200(v) => v.key_mint_security_level.value(),
        KeyDescription::V300(v) => v.key_mint_security_level.value(),
    };
    sl_value
}

fn sha256_array(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Convert a `Vec<Vec<u8>>` cert chain to Acurast's `CertificateChainInput`.
/// Errors out if any cert exceeds `CERT_MAX_LENGTH` (Acurast's bound).
fn build_chain_input(raw: Vec<Vec<u8>>) -> Result<CertificateChainInput, ()> {
    let bounded: Result<Vec<CertificateInput>, ()> = raw
        .into_iter()
        .map(|c| CertificateInput::try_from(c).map_err(|_| ()))
        .collect();
    let bounded = bounded?;
    CertificateChainInput::try_from(bounded).map_err(|_| ())
}

// ----- Stubs for the other evidence types ---------------------------------

pub struct AmdSevSnpVerifier;
impl EvidenceVerifier for AmdSevSnpVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::AmdSevSnp
    }
    fn verify(&self, _content_hash: &[u8; 32], _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct IntelTdxVerifier;
impl EvidenceVerifier for IntelTdxVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::IntelTdx
    }
    fn verify(&self, _content_hash: &[u8; 32], _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct ReproducibleBuildVerifier;
impl EvidenceVerifier for ReproducibleBuildVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ReproducibleBuild
    }
    fn verify(&self, _content_hash: &[u8; 32], _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct ZkVmExecutionVerifier;
impl EvidenceVerifier for ZkVmExecutionVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ZkVmExecution
    }
    fn verify(&self, _content_hash: &[u8; 32], _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

/// Static dispatch to the right verifier for an evidence type.
pub fn verify_evidence(content_hash: &[u8; 32], entry: &EvidenceEntry) -> VerifyOutcome {
    match entry.evidence_type {
        EvidenceType::ArmTrustZone => ArmTrustZoneVerifier.verify(content_hash, entry),
        EvidenceType::AmdSevSnp => AmdSevSnpVerifier.verify(content_hash, entry),
        EvidenceType::IntelTdx => IntelTdxVerifier.verify(content_hash, entry),
        EvidenceType::ReproducibleBuild => ReproducibleBuildVerifier.verify(content_hash, entry),
        EvidenceType::ZkVmExecution => ZkVmExecutionVerifier.verify(content_hash, entry),
    }
}
