//! Verifier trait and concrete implementations.
//!
//! Only `ArmTrustZoneVerifier` is implemented; the others return
//! `VerifyFailReason::NotImplemented`. `verify_evidence` dispatches to the
//! right verifier based on `EvidenceType`.
//!
//! Determinism rules:
//!   - All trust roots are pinned via `include_bytes!`.
//!   - No network calls in the verify path.
//!   - Certificate validity is judged at the block timestamp
//!     (`ArmTrustZoneVerifier::now`), never a node clock.
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
use crate::vendor::acurast_attestation::asn::{
    Certificate, KeyDescription, Name, ParsedAttestation, SubjectPublicKeyInfo, Time,
};
use crate::vendor::acurast_attestation::{
    extract_attestation, validate_certificate_chain, CertificateChainInput, CertificateInput,
    KEY_ATTESTATION_OID,
};
use asn1::ObjectIdentifier;

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
///   4. Rejects a revoked certificate above the leaf, or one not valid at
///      the block time (`certificate_status`).
///   5. Calls `extract_attestation` on the leaf cert's extension to confirm
///      the leaf is a Key-Attestation cert (vs unrelated leaf).
///   6. Reads the security level (TEE / StrongBox) from the
///      `KeyDescription`.
///   7. Requires the leaf's `attestationChallenge` to equal
///      `arm_trustzone_challenge(binding)`.
///   8. Computes `attest_key_hash = sha256(leaf_subject_public_key_info DER)`.
pub struct ArmTrustZoneVerifier<'r> {
    /// DER SubjectPublicKeyInfo of each key a chain may be anchored at.
    pub trusted_roots: &'r [&'r [u8]],
    /// Block timestamp, in seconds since the Unix epoch.
    pub now: u64,
    /// Whether a certificate serial (big-endian magnitude without leading
    /// zero bytes) is revoked.
    pub is_revoked: &'r dyn Fn(&[u8]) -> bool,
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
        if validate_certificate_chain(&chain, self.trusted_roots).is_err() {
            return VerifyOutcome::Failed(VerifyFailReason::ChainOfTrustBroken);
        }
        let certs = match chain
            .iter()
            .map(|der| asn1::parse_single::<Certificate>(der))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(certs) => certs,
            Err(_) => return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed),
        };
        let Some((leaf, issuers)) = certs.split_last() else {
            return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed);
        };

        // 3. Only the leaf may carry the key-attestation extension.
        if issuers.iter().any(carries_attestation_extension) {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // 4. Revocation and validity at the block time.
        if let Err(reason) = self.certificate_status(issuers) {
            return VerifyOutcome::Failed(reason);
        }

        // 5. Confirm the leaf is a Key-Attestation cert.
        let parsed = match extract_attestation(leaf.tbs_certificate.extensions.clone()) {
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

        // 6. Positive allowlist: only TrustedEnvironment (1) and StrongBox
        // (2) represent attested hardware-rooted keys; reject everything else.
        let raw_level = key_description_security_level(key_description);
        if !is_security_level_allowed(raw_level) {
            return VerifyOutcome::Failed(VerifyFailReason::PolicyViolation);
        }

        // 7. The key was minted for this receipt on this chain.
        if key_description_challenge(key_description) != arm_trustzone_challenge(binding) {
            return VerifyOutcome::Failed(VerifyFailReason::NonceMismatch);
        }

        let Some(attest_key_hash) = attest_key_hash(&leaf.tbs_certificate.subject_public_key_info) else {
            return VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed);
        };

        VerifyOutcome::Verified(VerifiedEvidence {
            evidence_type: EvidenceType::ArmTrustZone,
            attest_key_hash,
            raw_level,
        })
    }
}

impl ArmTrustZoneVerifier<'_> {
    /// Revocation and validity of the certificates above the leaf at block
    /// time `now`, following Google's android/keyattestation verifier:
    ///   - none may be revoked, looked up by serial magnitude;
    ///   - each one below the anchor must have become valid, and must not
    ///     have expired unless the chain is factory provisioned. Factory
    ///     attestation keys cannot be rotated and Google keeps trusting them
    ///     past expiry; remotely provisioned (RKP) certificates are
    ///     short-lived on purpose;
    ///   - the anchor's own certificate is not dated: the pinned key is the
    ///     anchor.
    ///
    /// The leaf is not checked: the device sets its serial (Keystore uses 1)
    /// and its validity (Keystore defaults run from 1970 to 2048).
    fn certificate_status(&self, issuers: &[Certificate<'_>]) -> Result<(), VerifyFailReason> {
        if issuers
            .iter()
            .any(|cert| (self.is_revoked)(serial_magnitude(cert)))
        {
            return Err(VerifyFailReason::CertificateRevoked);
        }
        let below_anchor = match issuers.split_first() {
            Some((first, rest)) if self.is_anchor(first) => rest,
            _ => issuers,
        };
        let factory_provisioned = below_anchor.first().is_some_and(names_a_serial_number);
        let now = i64::try_from(self.now).unwrap_or(i64::MAX);
        for cert in below_anchor {
            let validity = &cert.tbs_certificate.validity;
            let expired = now > unix_seconds(&validity.not_after);
            if now < unix_seconds(&validity.not_before) || (expired && !factory_provisioned) {
                return Err(VerifyFailReason::CertificateNotValidAtBlockTime);
            }
        }
        Ok(())
    }

    /// Whether `cert` carries one of the trusted root keys.
    fn is_anchor(&self, cert: &Certificate<'_>) -> bool {
        asn1::write_single(&cert.tbs_certificate.subject_public_key_info)
            .is_ok_and(|spki| self.trusted_roots.contains(&spki.as_slice()))
    }
}

/// X.520 `serialNumber`. Google's verifier treats a chain as factory
/// provisioned when the certificate its root issued names one (an OEM batch
/// key); RKP intermediates are named "Droid CA2" by Google LLC.
const SERIAL_NUMBER_ATTRIBUTE: ObjectIdentifier = asn1::oid!(2, 5, 4, 5);

fn names_a_serial_number(cert: &Certificate<'_>) -> bool {
    let Name::RDNSequence(rdns) = &cert.tbs_certificate.subject;
    rdns.clone()
        .any(|mut rdn| rdn.any(|attribute| attribute.typ == SERIAL_NUMBER_ATTRIBUTE))
}

fn carries_attestation_extension(cert: &Certificate<'_>) -> bool {
    cert.tbs_certificate
        .extensions
        .clone()
        .is_some_and(|mut extensions| {
            extensions.any(|extension| extension.extn_id == KEY_ATTESTATION_OID)
        })
}

/// A certificate's serial number as its big-endian magnitude without
/// leading zero bytes; DER prefixes a zero byte when the high bit is set.
fn serial_magnitude<'a>(cert: &Certificate<'a>) -> &'a [u8] {
    let bytes = cert.tbs_certificate.serial_number.as_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Seconds from the Unix epoch to an X.509 time (UTC, proleptic Gregorian),
/// by Howard Hinnant's `days_from_civil`.
pub(crate) fn unix_seconds(time: &Time) -> i64 {
    let t = match time {
        Time::UTCTime(t) => t.as_datetime(),
        Time::GeneralizedTime(t) => t.as_datetime(),
    };
    let month = i64::from(t.month());
    let year = i64::from(t.year()) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + i64::from(t.day()) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days * 86_400 + i64::from(t.hour()) * 3_600 + i64::from(t.minute()) * 60 + i64::from(t.second())
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

/// SHA-256 of a SubjectPublicKeyInfo re-encoded to canonical DER.
fn attest_key_hash(spki: &SubjectPublicKeyInfo<'_>) -> Option<[u8; 32]> {
    asn1::write_single(spki).ok().map(|der| sha256_array(&der))
}

/// The `attest_key_hash` an ArmTrustZone entry's leaf names, read without
/// checking any signature, so a repeated key is refused before verification.
/// Verification computes the same hash from the same certificate.
pub fn claimed_attest_key_hash(entry: &EvidenceEntry) -> Option<[u8; 32]> {
    if entry.evidence_type != EvidenceType::ArmTrustZone {
        return None;
    }
    let chain = Vec::<Vec<u8>>::decode(&mut &entry.payload[..]).ok()?;
    let leaf = asn1::parse_single::<Certificate>(chain.last()?).ok()?;
    attest_key_hash(&leaf.tbs_certificate.subject_public_key_info)
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
pub fn verify_evidence(
    binding: &ReceiptBinding,
    entry: &EvidenceEntry,
    arm_trustzone: &ArmTrustZoneVerifier,
) -> VerifyOutcome {
    match entry.evidence_type {
        EvidenceType::ArmTrustZone => arm_trustzone.verify(binding, entry),
        EvidenceType::AmdSevSnp => AmdSevSnpVerifier.verify(binding, entry),
        EvidenceType::IntelTdx => IntelTdxVerifier.verify(binding, entry),
        EvidenceType::ReproducibleBuild => ReproducibleBuildVerifier.verify(binding, entry),
        EvidenceType::ZkVmExecution => ZkVmExecutionVerifier.verify(binding, entry),
    }
}
