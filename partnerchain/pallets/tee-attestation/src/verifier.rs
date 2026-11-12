//! Verifier trait and concrete implementations.
//!
//! Only `ArmTrustZoneVerifier` is implemented; the others return
//! `VerifyFailReason::NotImplemented`. `verify_evidence` dispatches to the
//! right verifier based on `EvidenceType`.
//!
//! Determinism rules:
//!   - All trust roots are pinned via `include_bytes!`.
//!   - No network calls in the verify path.
//!   - No wall-clock checks: certificate `not_before`/`not_after` would
//!     diverge by node clock skew.
//!   - The receipt binding is read from chain state (`ReceiptBinding`).
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
    EvidenceEntry, EvidenceType, ReceiptBinding, VerifiedEvidence, VerifyFailReason, VerifyOutcome,
};
use crate::vendor::acurast_attestation::asn::{Certificate, KeyDescription, ParsedAttestation};
use crate::vendor::acurast_attestation::{
    extract_attestation, validate_certificate_chain, CertificateChainInput, CertificateInput,
    KEY_ATTESTATION_OID,
};

use sha2::{Digest, Sha256};

/// Trait every evidence verifier implements. Implementations MUST produce
/// bit-identical `VerifyOutcome::Verified` records for identical inputs
/// across all committee members.
pub trait EvidenceVerifier {
    fn evidence_type(&self) -> EvidenceType;

    /// Verify a single evidence entry for the receipt `binding` names.
    fn verify(&self, binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome;
}

/// Google's Android key-attestation root keys (DER SubjectPublicKeyInfo):
/// the RSA root behind factory-provisioned and RKP chains, and the P-384
/// root that signs chains from February 2026. ArmTrustZone evidence chains
/// to these and to nothing else.
pub const GOOGLE_ATTESTATION_ROOTS: [&[u8]; 2] = [
    include_bytes!("../vendor/acurast-attestation/__root_key__/google-public.key"),
    include_bytes!("../vendor/acurast-attestation/__root_key__/google-p384-public.key"),
];

/// Domain tag of the ArmTrustZone challenge preimage. A challenge minted for
/// another protocol equals a Materios challenge only through a SHA-256
/// preimage.
pub const ARM_TRUSTZONE_CHALLENGE_TAG: &[u8] =
    b"materios/tee-attestation/arm-trustzone-challenge/v1";

/// The `attestationChallenge` an ArmTrustZone leaf must carry to count as
/// evidence for `binding`:
/// `SHA-256(ARM_TRUSTZONE_CHALLENGE_TAG ‖ genesis_hash ‖ receipt_id ‖ content_hash)`.
pub fn arm_trustzone_challenge(binding: &ReceiptBinding) -> [u8; 32] {
    sha256_array(
        &[
            ARM_TRUSTZONE_CHALLENGE_TAG,
            &binding.genesis_hash,
            binding.receipt_id.as_bytes(),
            &binding.content_hash,
        ]
        .concat(),
    )
}

/// ARM TrustZone (Android Hardware Key Attestation) verifier.
///
/// Wraps the vendored Acurast logic. The verifier:
///   1. SCALE-decodes the cert chain bytes from the entry payload.
///   2. Calls Acurast's `validate_certificate_chain` to walk
///      `trusted_roots` → Intermediate(s) → Leaf, verifying every signature.
///   3. Rejects a chain in which a certificate other than the leaf carries
///      the key-attestation extension. Only secure hardware issues that
///      extension; an attested key that signs a further certificate can put
///      any challenge and security level in it.
///   4. Calls `extract_attestation` on the leaf cert's extension to confirm
///      the leaf is a Key-Attestation cert (vs unrelated leaf).
///   5. Reads the security level (TEE / StrongBox) from the
///      `KeyDescription`.
///   6. Requires the leaf's `attestationChallenge` to equal
///      `arm_trustzone_challenge(binding)`.
///   7. Computes `attest_key_hash = sha256(leaf_subject_public_key_info DER)`.
pub struct ArmTrustZoneVerifier<'r> {
    /// DER SubjectPublicKeyInfo of each key a chain may be anchored at.
    pub trusted_roots: &'r [&'r [u8]],
}

impl EvidenceVerifier for ArmTrustZoneVerifier<'_> {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ArmTrustZone
    }

    fn verify(&self, binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome {
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
        let (_cert_ids, leaf_tbs, _last_pbk) =
            match validate_certificate_chain(&chain, self.trusted_roots) {
                Ok(t) => t,
                Err(_) => return VerifyOutcome::Failed(VerifyFailReason::ChainOfTrustBroken),
            };

        // 3. Only the leaf may carry the key-attestation extension.
        if !attestation_extension_only_in_leaf(&chain) {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // 4. Confirm the leaf is a Key-Attestation cert.
        let parsed = match extract_attestation(leaf_tbs.extensions) {
            Ok(p) => p,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation),
        };

        let key_description = match &parsed {
            ParsedAttestation::KeyDescription(kd) => kd,
            ParsedAttestation::DeviceAttestation(_) => {
                // Apple device-attestation extension instead of an Android
                // Key-Attestation extension — out of scope for ArmTrustZone.
                return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
            }
        };

        // 5. Positive allowlist: only TrustedEnvironment (1) and StrongBox
        // (2) represent attested hardware-rooted keys; reject everything else.
        let raw_level = key_description_security_level(key_description);
        if !is_security_level_allowed(raw_level) {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // 6. The key was minted for this receipt on this chain.
        if key_description_challenge(key_description) != arm_trustzone_challenge(binding) {
            return VerifyOutcome::Failed(VerifyFailReason::NonceMismatch);
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
    match kd {
        KeyDescription::V1(v) => v.key_mint_security_level.value(),
        KeyDescription::V2(v) => v.key_mint_security_level.value(),
        KeyDescription::V3(v) => v.key_mint_security_level.value(),
        KeyDescription::V4(v) => v.key_mint_security_level.value(),
        KeyDescription::V100(v) => v.key_mint_security_level.value(),
        KeyDescription::V200(v) => v.key_mint_security_level.value(),
        KeyDescription::V300(v) => v.key_mint_security_level.value(),
    }
}

/// The `attestationChallenge` the key was minted with. Every KeyDescription
/// version the vendored parser accepts carries it as a mandatory OCTET
/// STRING.
pub(crate) fn key_description_challenge<'a>(kd: &KeyDescription<'a>) -> &'a [u8] {
    match kd {
        KeyDescription::V1(v) => v.attestation_challenge,
        KeyDescription::V2(v) => v.attestation_challenge,
        KeyDescription::V3(v) => v.attestation_challenge,
        KeyDescription::V4(v) => v.attestation_challenge,
        KeyDescription::V100(v) => v.attestation_challenge,
        KeyDescription::V200(v) => v.attestation_challenge,
        KeyDescription::V300(v) => v.attestation_challenge,
    }
}

/// Whether every certificate but the last (the leaf) lacks the
/// key-attestation extension. The chain has already been validated, so each
/// certificate parses.
fn attestation_extension_only_in_leaf(chain: &CertificateChainInput) -> bool {
    let Some((_leaf, issuers)) = chain.split_last() else {
        return false;
    };
    issuers
        .iter()
        .all(|der| match asn1::parse_single::<Certificate>(der) {
            Ok(cert) => !cert
                .tbs_certificate
                .extensions
                .is_some_and(|mut extensions| {
                    extensions.any(|extension| extension.extn_id == KEY_ATTESTATION_OID)
                }),
            Err(_) => false,
        })
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
    fn verify(&self, _binding: &ReceiptBinding, _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct IntelTdxVerifier;
impl EvidenceVerifier for IntelTdxVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::IntelTdx
    }
    fn verify(&self, _binding: &ReceiptBinding, _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct ReproducibleBuildVerifier;
impl EvidenceVerifier for ReproducibleBuildVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ReproducibleBuild
    }
    fn verify(&self, _binding: &ReceiptBinding, _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

pub struct ZkVmExecutionVerifier;
impl EvidenceVerifier for ZkVmExecutionVerifier {
    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::ZkVmExecution
    }
    fn verify(&self, _binding: &ReceiptBinding, _entry: &EvidenceEntry) -> VerifyOutcome {
        VerifyOutcome::Failed(VerifyFailReason::NotImplemented)
    }
}

/// Static dispatch to the right verifier for an evidence type.
/// `arm_trustzone_roots` are the anchors an ArmTrustZone chain may start
/// from; on chain they are `GOOGLE_ATTESTATION_ROOTS`.
pub fn verify_evidence(
    binding: &ReceiptBinding,
    entry: &EvidenceEntry,
    arm_trustzone_roots: &[&[u8]],
) -> VerifyOutcome {
    match entry.evidence_type {
        EvidenceType::ArmTrustZone => ArmTrustZoneVerifier {
            trusted_roots: arm_trustzone_roots,
        }
        .verify(binding, entry),
        EvidenceType::AmdSevSnp => AmdSevSnpVerifier.verify(binding, entry),
        EvidenceType::IntelTdx => IntelTdxVerifier.verify(binding, entry),
        EvidenceType::ReproducibleBuild => ReproducibleBuildVerifier.verify(binding, entry),
        EvidenceType::ZkVmExecution => ZkVmExecutionVerifier.verify(binding, entry),
    }
}
