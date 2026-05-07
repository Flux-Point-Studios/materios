// Vendored from Acurast/acurast-substrate@d205a7d37d119e6c25269d5141eb16ecd36eaf22
// on 2026-05-06; do not edit by hand. Patches via README.md in this dir.
//
// SPDX-License-Identifier: MIT (see ./LICENSE)
// Original path: pallets/acurast/common/src/attestation.rs
//
// Materios patches (search for [materios-patch] inline):
//
// [materios-patch] Replace Acurast-fork-only direct AffinePoint{x,y,infinity}
//   construction + ecdsa-vendored crate references with upstream
//   p384 = 0.13 / ecdsa = 0.16 APIs. The verifier semantics are unchanged
//   (the wire format is bit-identical: SEC1 uncompressed point, DER-encoded
//   ECDSA signature, SHA-256 / SHA-384 prehash, then Verifier::verify_prehash).
//   Acurast's variant relied on `expose-field` plus a public-fielded
//   AffinePoint shipped only in their p384 fork; upstream's AffinePoint is
//   opaque and we use VerifyingKey::from_sec1_bytes + PrehashVerifier instead.
//
// [materios-patch] Drop in-file `mod tests` (lines 386-697 upstream) — we
//   replace it with `tests.rs` at the pallet root, which targets our pallet's
//   public verifier API rather than the bare `validate_certificate_chain`
//   function. The reference test vectors (Samsung StrongBox, Pixel TEE,
//   Solana Seeker) are reused from upstream and hex-imported in
//   `tests.rs`.
//
// [materios-patch] Drop `BoundedKeyDescription` import — we never call
//   `extract_attestation()->BoundedKeyDescription::try_into()` because the
//   Materios pallet does not store the rich Acurast key-description object;
//   we only extract the chip ID hash (sha256 of the leaf cert's public key)
//   and the security level (TEE / StrongBox), which we read from the
//   attestation extension's bytes directly via `extract_attestation()` and
//   `parse_key_description()` outputs.

pub mod asn;
pub mod error;

use asn::*;
use asn1::{oid, BitString, ObjectIdentifier, ParseError, SequenceOf};
use core::cell::RefCell;
use error::ValidationError;
use frame_support::{traits::ConstU32, BoundedVec};
use num_bigint::BigUint;
use p256::ecdsa::{signature::Verifier as _, VerifyingKey as P256VerifyingKey};

use sha2::Digest;
use sp_std::prelude::*;

pub const CHAIN_MAX_LENGTH: u32 = 5;
pub const CERT_MAX_LENGTH: u32 = 3000;
pub type CertificateInput = BoundedVec<u8, ConstU32<CERT_MAX_LENGTH>>;
pub type CertificateChainInput = BoundedVec<CertificateInput, ConstU32<CHAIN_MAX_LENGTH>>;

fn parse_cert(serialized: &[u8]) -> Result<Certificate, ParseError> {
    let data = asn1::parse_single::<Certificate>(serialized)?;
    Ok(data)
}

fn parse_cert_payload(serialized: &[u8]) -> Result<&[u8], ParseError> {
    let payload = asn1::parse_single::<CertificateRawPayload>(serialized)?;

    Ok(payload.tbs_certificate.full_data())
}

pub type CertificateId = (Vec<u8>, Vec<u8>);

/// Creates a unique id for a certificate.
pub fn unique_id(
    issuer: &Name,
    serial_number: &asn1::BigUint,
) -> Result<CertificateId, ValidationError> {
    let issuer_encoded = asn1::write_single(issuer).map_err(|_| ValidationError::InvalidIssuer)?;
    let serial_number_encoded = serial_number.as_bytes().to_vec();
    Ok((issuer_encoded, serial_number_encoded))
}

/// The OID of the Attestation Extension to a X.509 certificate.
/// [See docs](https://source.android.com/docs/security/keystore/attestation#tbscertificate-sequence)
pub const KEY_ATTESTATION_OID: ObjectIdentifier = oid!(1, 3, 6, 1, 4, 1, 11129, 2, 1, 17);
const APPLE_DEVICE_ATTESTATION_KEY_USAGE_PROPERTIES: ObjectIdentifier =
    oid!(1, 2, 840, 113635, 100, 8, 5);
const APPLE_DEVICE_ATTESTATION_DEVICE_OS_INFORMATION: ObjectIdentifier =
    oid!(1, 2, 840, 113635, 100, 8, 7);
const APPLE_DEVICE_ATTESTATION_NONCE: ObjectIdentifier = oid!(1, 2, 840, 113635, 100, 8, 2);

/// Extracts and parses the attestation from the extension field of a X.509 certificate.
pub fn extract_attestation<'a>(
    extensions: Option<SequenceOf<'a, Extension<'a>>>,
) -> Result<ParsedAttestation<'a>, ValidationError> {
    let extensions = extensions
        .ok_or(ValidationError::ExtensionMissing)?
        .collect::<Vec<_>>();
    if let Some(extension) = &extensions.iter().find(|e| e.extn_id == KEY_ATTESTATION_OID) {
        return Ok(ParsedAttestation::KeyDescription(parse_key_description(
            extension,
        )?));
    }

    Ok(ParsedAttestation::DeviceAttestation(
        parse_apple_attestation(&extensions)?,
    ))
}

fn parse_key_description<'a>(
    extension: &Extension<'a>,
) -> Result<KeyDescription<'a>, ValidationError> {
    let version = peek_attestation_version(extension.extn_value)?;

    match version {
        1 => {
            let parsed = asn1::parse_single::<KeyDescriptionV1>(extension.extn_value)?;
            Ok(KeyDescription::V1(parsed))
        }
        2 => {
            let parsed = asn1::parse_single::<KeyDescriptionV2>(extension.extn_value)?;
            Ok(KeyDescription::V2(parsed))
        }
        3 => {
            let parsed = asn1::parse_single::<KeyDescriptionV3>(extension.extn_value)?;
            Ok(KeyDescription::V3(parsed))
        }
        4 => {
            let parsed = asn1::parse_single::<KeyDescriptionV4>(extension.extn_value)?;
            Ok(KeyDescription::V4(parsed))
        }
        100 => {
            let parsed = asn1::parse_single::<KeyDescriptionKeyMint>(extension.extn_value)?;
            Ok(KeyDescription::V100(parsed))
        }
        200 => {
            let parsed = asn1::parse_single::<KeyDescriptionKeyMint>(extension.extn_value)?;
            Ok(KeyDescription::V200(parsed))
        }
        300 => {
            let parsed = asn1::parse_single::<KeyDescriptionKeyMint>(extension.extn_value)?;
            Ok(KeyDescription::V300(parsed))
        }
        _ => Err(ValidationError::UnsupportedAttestationVersion(version)),
    }
}

fn parse_apple_attestation<'a>(
    extensions: &[Extension<'a>],
) -> Result<DeviceAttestation<'a>, ValidationError> {
    if let Some(key_usage_properties) = &extensions
        .iter()
        .find(|e| e.extn_id == APPLE_DEVICE_ATTESTATION_KEY_USAGE_PROPERTIES)
    {
        let key_usage_properties = asn1::parse_single::<DeviceAttestationKeyUsageProperties>(
            key_usage_properties.extn_value,
        )?;
        if let Some(device_os_information) = &extensions
            .iter()
            .find(|e| e.extn_id == APPLE_DEVICE_ATTESTATION_DEVICE_OS_INFORMATION)
        {
            let device_os_information = asn1::parse_single::<DeviceAttestationDeviceOSInformation>(
                device_os_information.extn_value,
            )?;
            if let Some(nonce) = &extensions
                .iter()
                .find(|e| e.extn_id == APPLE_DEVICE_ATTESTATION_NONCE)
            {
                let nonce = asn1::parse_single::<DeviceAttestationNonce>(nonce.extn_value)?;
                return Ok(DeviceAttestation {
                    key_usage_properties,
                    device_os_information,
                    nonce,
                });
            }
        }
    }
    Err(ValidationError::ExtensionMissing)
}

const RSA_ALGORITHM: ObjectIdentifier = oid!(1, 2, 840, 113549, 1, 1, 11);
const ECDSA_WITH_SHA256_ALGORITHM: ObjectIdentifier = oid!(1, 2, 840, 10045, 4, 3, 2); // https://oidref.com/1.2.840.10045.4.3.2
const ECDSA_WITH_SHA384_ALGORITHM: ObjectIdentifier = oid!(1, 2, 840, 10045, 4, 3, 3); // https://oidref.com/1.2.840.10045.4.3.3

const RSA_PBK: ObjectIdentifier = oid!(1, 2, 840, 113549, 1, 1, 1);
const ECDSA_PBK: ObjectIdentifier = oid!(1, 2, 840, 10045, 2, 1);

#[derive(Clone, Eq, PartialEq)]
pub enum PublicKey {
    RSA(RSAPbk),
    ECDSA(ECDSACurve),
}

#[derive(Clone, Eq, PartialEq)]
pub struct RSAPbk {
    exponent: BigUint,
    modulus: BigUint,
}

/// [materios-patch] Switched from Acurast's `p384::AffinePoint` (vendored fork
/// with public x/y fields, requires `expose-field`) to upstream
/// `p384::ecdsa::VerifyingKey`. The wire encoding (uncompressed SEC1 point in
/// the X.509 SubjectPublicKey BIT STRING) is identical; the verifier surface
/// switches from `verify_prehashed(FieldBytes, Signature)` to
/// `PrehashVerifier::verify_prehash(&[u8], &Signature)`.
#[derive(Clone, Eq, PartialEq)]
pub enum ECDSACurve {
    CurveP256(P256VerifyingKey),
    CurveP384(p384::ecdsa::VerifyingKey),
}

impl PublicKey {
    fn parse(info: &SubjectPublicKeyInfo) -> Result<Self, ValidationError> {
        match info.algorithm.algorithm {
            RSA_PBK => {
                let pbk = parse_rsa_pbk(info.subject_public_key.as_bytes())?;
                Ok(PublicKey::RSA(pbk))
            }
            ECDSA_PBK => {
                let pbk_param = info
                    .algorithm
                    .parameters
                    .ok_or(ValidationError::MissingECDSAAlgorithmTyp)?;
                let typ = asn1::parse_single::<ObjectIdentifier>(pbk_param.full_data())?;
                match typ {
                    CURVE_P256 => {
                        let verifying_key =
                            P256VerifyingKey::from_sec1_bytes(info.subject_public_key.as_bytes())
                                .or(Err(ValidationError::ParseP256PublicKey))?;
                        Ok(PublicKey::ECDSA(ECDSACurve::CurveP256(verifying_key)))
                    }
                    CURVE_P384 => {
                        // [materios-patch] Use upstream P-384 SEC1 parsing.
                        // The X.509 `subject_public_key` BIT STRING for an
                        // EC public key is the SEC1 encoding of the point —
                        // 0x04 || X || Y (uncompressed) for the keys we expect.
                        // upstream `p384::ecdsa::VerifyingKey::from_sec1_bytes`
                        // is the documented entry point.
                        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
                            info.subject_public_key.as_bytes(),
                        )
                        .or(Err(ValidationError::ParseP384PublicKey))?;
                        Ok(PublicKey::ECDSA(ECDSACurve::CurveP384(verifying_key)))
                    }
                    _ => Result::Err(ValidationError::UnsupportedSignatureAlgorithm)?,
                }
            }
            _ => Result::Err(ValidationError::UnsupportedPublicKeyAlgorithm),
        }
    }
}

const CURVE_P256: ObjectIdentifier = oid!(1, 2, 840, 10045, 3, 1, 7);
const CURVE_P384: ObjectIdentifier = oid!(1, 3, 132, 0, 34);

fn validate(
    cert: &Certificate<'_>,
    payload: &[u8],
    pbk: &PublicKey,
) -> Result<(), ValidationError> {
    if cert.signature_algorithm.algorithm != cert.tbs_certificate.signature.algorithm {
        return Err(ValidationError::SignatureMismatch);
    }
    match cert.signature_algorithm.algorithm {
        RSA_ALGORITHM => match pbk {
            PublicKey::RSA(pbk) => validate_rsa(payload, &cert.signature_value, pbk),
            _ => Err(ValidationError::UnsupportedPublicKeyAlgorithm),
        },
        ECDSA_WITH_SHA256_ALGORITHM => match pbk {
            PublicKey::ECDSA(pbk) => {
                validate_ecdsa::<sha2::Sha256>(payload, &cert.signature_value, pbk)
            }
            _ => Err(ValidationError::UnsupportedPublicKeyAlgorithm),
        },
        ECDSA_WITH_SHA384_ALGORITHM => match pbk {
            PublicKey::ECDSA(pbk) => {
                validate_ecdsa::<sha2::Sha384>(payload, &cert.signature_value, pbk)
            }
            _ => Err(ValidationError::UnsupportedPublicKeyAlgorithm),
        },
        _ => Err(ValidationError::UnsupportedSignatureAlgorithm)?,
    }
}

fn validate_rsa(
    payload: &[u8],
    signature: &BitString,
    pbk: &RSAPbk,
) -> Result<(), ValidationError> {
    use rsa::signature::Verifier;

    let modulus = rsa::BigUint::from_bytes_be(pbk.modulus.to_bytes_be().as_slice());
    let exponent = rsa::BigUint::from_bytes_be(pbk.exponent.to_bytes_be().as_slice());
    let pk =
        rsa::RsaPublicKey::new(modulus, exponent).map_err(|_| ValidationError::InvalidSignature)?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk);
    let signature = rsa::pkcs1v15::Signature::try_from(signature.as_bytes())
        .map_err(|_| ValidationError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| ValidationError::InvalidSignature)?;

    Ok(())
}

fn validate_ecdsa<D>(
    payload: &[u8],
    signature: &BitString,
    curve: &ECDSACurve,
) -> Result<(), ValidationError>
where
    D: Digest,
{
    match curve {
        ECDSACurve::CurveP256(verifying_key) => {
            let signature = p256::ecdsa::Signature::from_der(signature.as_bytes())
                .or(Err(ValidationError::InvalidSignatureEncoding))?;
            verifying_key
                .verify(payload, &signature)
                .or(Err(ValidationError::InvalidSignature))?;
        }
        ECDSACurve::CurveP384(verifying_key) => {
            // [materios-patch] Switched to upstream `p384::ecdsa::Signature` +
            // `PrehashVerifier::verify_prehash`. Acurast's path was
            // `ecdsa_vendored::Signature::from_der` then
            // `affine_point.verify_prehashed(field_bytes, &signature)` from
            // their `expose-field` fork; the produced/verified signature bytes
            // are identical.
            use ecdsa::signature::hazmat::PrehashVerifier;
            let signature = p384::ecdsa::Signature::from_der(signature.as_bytes())
                .or(Err(ValidationError::InvalidSignatureEncoding))?;

            // Acurast pads SHA-256 hashes (32 bytes) up to 48 bytes for P-384;
            // upstream's `verify_prehash` accepts a slice and does its own
            // length-handling. Pass the raw digest output through.
            let hashed = D::digest(payload);
            let mut padded: [u8; 48] = [0; 48];
            if hashed.len() == 32 {
                padded[16..].copy_from_slice(&hashed);
            } else {
                padded.copy_from_slice(&hashed);
            }
            verifying_key
                .verify_prehash(&padded, &signature)
                .or(Err(ValidationError::InvalidSignature))?;
        }
    };

    Ok(())
}

fn parse_rsa_pbk(data: &[u8]) -> Result<RSAPbk, ParseError> {
    let pbk = asn1::parse_single::<RSAPublicKey>(data)?;
    Ok(RSAPbk {
        exponent: BigUint::from_bytes_be(pbk.exponent.as_bytes()),
        modulus: BigUint::from_bytes_be(pbk.modulus.as_bytes()),
    })
}

pub fn peek_attestation_version(data: &[u8]) -> Result<i64, ParseError> {
    let result: asn1::ParseResult<_> = asn1::parse(data, |d| {
        // as we are not reading the sequence to the end, the parser always returns an error result
        // therefore setup a cell to store the result and ignore result
        let attestation_version: RefCell<i64> = RefCell::from(0);
        let _: Result<_, ParseError> = d.read_element::<asn1::Sequence>()?.parse(|d| {
            *attestation_version.borrow_mut() = d.read_element::<i64>()?;
            // this gets always covered by parse error
            Ok(())
        });

        Ok(attestation_version.into_inner())
    });
    result
}

/// Validates the chain by ensuring that
///
/// - the chain starts with a self-signed certificate at index 0 that matches one of the known [TRUSTED_ROOT_CERTS]
/// - that the root's contained public key signs the next certificate in the chain
/// - the next certificate's public key signs the next one and so on...
pub fn validate_certificate_chain(
    chain: &CertificateChainInput,
) -> Result<(Vec<CertificateId>, TBSCertificate<'_>, PublicKey), ValidationError> {
    let google_root_pub_key = PublicKey::parse(&asn1::parse_single::<SubjectPublicKeyInfo>(
        GOOGLE_ROOT_PUB_KEY,
    )?)?;
    let google_p384_root_pub_key = PublicKey::parse(&asn1::parse_single::<SubjectPublicKeyInfo>(
        GOOGLE_P384_ROOT_PUB_KEY,
    )?)?;
    let apple_root_pub_key = PublicKey::parse(&asn1::parse_single::<SubjectPublicKeyInfo>(
        APPLE_ROOT_PUB_KEY,
    )?)?;
    let trusted_roots = &[
        google_root_pub_key,
        google_p384_root_pub_key,
        apple_root_pub_key,
    ];
    let mut cert_ids = Vec::<CertificateId>::new();
    let fold_result = chain.iter().try_fold::<_, _, Result<_, ValidationError>>(
        (Option::<PublicKey>::None, Option::<Certificate>::None),
        |(prev_pbk, _), cert_data| {
            let cert = parse_cert(cert_data)?;
            let payload = parse_cert_payload(cert_data)?;
            let current_pbk = PublicKey::parse(&cert.tbs_certificate.subject_public_key_info)?;
            let validating_pbk: Option<&PublicKey> = if let Some(ref prev_pbk) = prev_pbk {
                Some(prev_pbk)
            } else if trusted_roots.contains(&current_pbk) {
                Some(&current_pbk)
            } else {
                // this can happen if the submitted certificate chain does not contain the root,
                // which is fine, we can start validating from the intermediate certificate since
                // we already have the root public key.
                None
            };

            if let Some(validating_pbk) = validating_pbk {
                validate(&cert, payload, validating_pbk)?;
            } else {
                let mut accepted = false;
                for trusted_root in trusted_roots.iter() {
                    match validate(&cert, payload, trusted_root) {
                        Ok(_) => {
                            accepted = true;
                            break;
                        }
                        Err(ValidationError::InvalidSignature)
                        | Err(ValidationError::UnsupportedPublicKeyAlgorithm) => {}
                        Err(error) => return Err(error),
                    }
                }
                if !accepted {
                    return Err(ValidationError::InvalidSignature);
                }
            }

            let unique_id = unique_id(
                &cert.tbs_certificate.issuer,
                &cert.tbs_certificate.serial_number,
            )?;
            cert_ids.push(unique_id);

            // it's crucial for security to pass on a non-null public key here,
            // otherwise self-signed certificates would get accepted later down the chain
            Ok((Some(current_pbk), Some(cert)))
        },
    )?;

    let last_cert = fold_result.1.ok_or(ValidationError::ChainTooShort)?;
    let last_cert_pbk = fold_result.0.ok_or(ValidationError::MissingPublicKey)?;

    // if the chain is non-empty as ensured above, we know that we always have Some certificate in option
    Ok((cert_ids, last_cert.tbs_certificate, last_cert_pbk))
}

const GOOGLE_ROOT_PUB_KEY: &[u8] = include_bytes!("./__root_key__/google-public.key");
const GOOGLE_P384_ROOT_PUB_KEY: &[u8] = include_bytes!("./__root_key__/google-p384-public.key");
const APPLE_ROOT_PUB_KEY: &[u8] = include_bytes!("./__root_key__/apple-public.key");

// [materios-patch] Original Acurast `mod tests` removed; see tests.rs at the
// pallet root for the equivalent reference-vector tests + Materios pallet
// integration tests.
