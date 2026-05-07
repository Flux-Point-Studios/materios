//! Verifier trait and concrete implementations.
//!
//! Wave 3 / Phase 2 ships only `ArmTrustZoneVerifier`, which wraps the
//! vendored Acurast `validate_certificate_chain` + `extract_attestation`
//! helpers. The other verifiers (AMD SEV-SNP, Intel TDX, reproducible
//! build, ZK-VM execution proof) are stubs that return
//! `VerifyFailReason::NotImplemented`. The dispatch table in `lib.rs` calls
//! the right verifier based on `EvidenceType`.
//!
//! ## Determinism rules
//!
//! Per `feedback_mofn_hash_determinism.md`:
//!   - ALL trust roots are pinned via `include_bytes!` — see vendored
//!     `__root_key__/google-public.key` etc.
//!   - NO network calls in the verify path. The X.509 chain is parsed and
//!     verified entirely in-memory.
//!   - NO wall-clock dependence. We do NOT check certificate `not_before` /
//!     `not_after` — committee members in different time zones / drifted
//!     clocks would otherwise diverge. The chain's chain-of-trust validation
//!     is the only signature check.
//!   - The `chip_id_hash` extraction is deterministic — SHA-256 of the leaf
//!     cert's SubjectPublicKeyInfo bytes (canonical DER).
//!
//! ## Wire format
//!
//! For `EvidenceType::ArmTrustZone`, the `EvidenceEntry::payload` is the
//! SCALE-encoded `Vec<Vec<u8>>` cert chain — index 0 is the root cert,
//! ascending toward the leaf. The chain is allowed to omit the root if the
//! root's public key matches one of the pinned trust roots; this matches
//! Acurast's behaviour and Android's standard chain emission.

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

/// Trait every evidence verifier implements.
///
/// ## Determinism
///
/// Implementations MUST produce bit-identical `VerifyOutcome::Verified`
/// records for identical inputs across all committee members. See
/// `feedback_mofn_hash_determinism.md` for the load-bearing rule.
pub trait EvidenceVerifier {
    fn evidence_type(&self) -> EvidenceType;

    /// Verify a single evidence entry. The `content_hash` is the receipt's
    /// content_hash from the receipt record; verifiers MAY use it to bind
    /// the evidence to the receipt (e.g. the attestation_challenge field in
    /// ARM Key Attestation, REPORT_DATA in AMD SEV-SNP). Phase 2 of the
    /// `ArmTrustZoneVerifier` does NOT check the challenge field — that is
    /// queued for Phase 2.5 when the off-chain submitter contract for the
    /// challenge derivation is finalised.
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
///   5. Computes `chip_id_hash = sha256(leaf_subject_public_key_info DER)`.
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

        // Software-only attested keys are not "TrustZone-rooted" and we
        // reject them. raw_level == 0 is the Software level.
        if raw_level == 0 {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // 4. Derive chip_id_hash = sha256 of the leaf SubjectPublicKeyInfo.
        // Re-encode the SPKI to canonical DER for hashing — matches Android's
        // per-device key serial used in upstream Acurast pallet integration.
        let spki_der = match asn1::write_single(&leaf_tbs.subject_public_key_info) {
            Ok(b) => b,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed),
        };
        let chip_id_hash = sha256_array(&spki_der);

        VerifyOutcome::Verified(VerifiedEvidence {
            evidence_type: EvidenceType::ArmTrustZone,
            chip_id_hash,
            raw_level,
        })
    }
}

/// Map a parsed `KeyDescription` to the `raw_level` integer the pallet
/// stores. The mapping mirrors Android's `SecurityLevel` enum:
///   0 = Software-only attestation (rejected by the verifier)
///   1 = TrustedEnvironment / TEE (TrustZone)
///   2 = StrongBox (hardware-isolated security chip)
///
/// Acurast's `SecurityLevel` is `asn1::Enumerated` whose `value()` is the
/// raw ASN.1 ENUMERATED integer; we surface that integer directly.
fn key_description_security_level(kd: &KeyDescription<'_>) -> u32 {
    let sl_value = match kd {
        KeyDescription::V1(v) => v.attestation_security_level.value(),
        KeyDescription::V2(v) => v.attestation_security_level.value(),
        KeyDescription::V3(v) => v.attestation_security_level.value(),
        KeyDescription::V4(v) => v.attestation_security_level.value(),
        KeyDescription::V100(v) => v.attestation_security_level.value(),
        KeyDescription::V200(v) => v.attestation_security_level.value(),
        KeyDescription::V300(v) => v.attestation_security_level.value(),
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

/// Static dispatch — returns the right verifier for an evidence type.
/// Phase 2 hard-wires implementations; later phases switch on Config when
/// per-pallet verifier configuration becomes useful.
pub fn verify_evidence(content_hash: &[u8; 32], entry: &EvidenceEntry) -> VerifyOutcome {
    match entry.evidence_type {
        EvidenceType::ArmTrustZone => ArmTrustZoneVerifier.verify(content_hash, entry),
        EvidenceType::AmdSevSnp => AmdSevSnpVerifier.verify(content_hash, entry),
        EvidenceType::IntelTdx => IntelTdxVerifier.verify(content_hash, entry),
        EvidenceType::ReproducibleBuild => ReproducibleBuildVerifier.verify(content_hash, entry),
        EvidenceType::ZkVmExecution => ZkVmExecutionVerifier.verify(content_hash, entry),
    }
}
