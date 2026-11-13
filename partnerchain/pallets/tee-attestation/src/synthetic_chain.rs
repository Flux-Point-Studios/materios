//! Synthetic Android key-attestation certificates for tests: DER built by
//! hand and signed with fixed P-256 keys. They cover what no public chain
//! can: a leaf minted for a chosen receipt, every KeyDescription version,
//! and a chain extended past an attested key. They chain to
//! `TestKey::root()`, never to a Google root.

#![cfg(test)]

use p256::ecdsa::{signature::Signer, Signature, SigningKey};

const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// 1.3.6.1.4.1.11129.2.1.17, the Android key-attestation extension.
const KEY_ATTESTATION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

pub const STRONGBOX: u8 = 2;

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n <= 0xFF => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(body);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut body = bytes[first..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(0x06, encoded)
}

fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn bits(bytes: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8][..], bytes].concat())
}

/// An X.509 UTCTime, `YYMMDDHHMMSSZ`.
pub fn utc_time(value: &str) -> Vec<u8> {
    tlv(0x17, value.as_bytes())
}

/// An X.509 GeneralizedTime, `YYYYMMDDHHMMSSZ`.
pub fn generalized_time(value: &str) -> Vec<u8> {
    tlv(0x18, value.as_bytes())
}

/// A KeyDescription of attestation `version` for a key at `security_level`,
/// minted with `challenge`. `None` leaves the mandatory challenge out.
pub fn key_description(version: u64, security_level: u8, challenge: Option<&[u8]>) -> Vec<u8> {
    let level = tlv(0x0A, &[security_level]);
    let mut fields = vec![integer(version), level.clone(), integer(version), level];
    fields.extend(challenge.map(octets));
    fields.extend([octets(&[]), sequence(&[]), sequence(&[])]);
    sequence(&fields)
}

/// The key-attestation extension carrying `key_description`.
pub fn attestation_extension(key_description: &[u8]) -> Vec<u8> {
    sequence(&[oid(KEY_ATTESTATION), octets(key_description)])
}

/// A P-256 key and the name certificates give it.
pub struct TestKey {
    signing: SigningKey,
    name: Vec<u8>,
}

impl TestKey {
    pub fn new(seed: u8, common_name: &str) -> Self {
        let rdn = sequence(&[oid(COMMON_NAME), tlv(0x0C, common_name.as_bytes())]);
        Self {
            signing: SigningKey::from_slice(&[seed; 32]).expect("seed is a valid P-256 scalar"),
            name: sequence(&[tlv(0x31, &rdn)]),
        }
    }

    pub fn root() -> Self {
        Self::new(1, "Synthetic Attestation Root")
    }

    /// DER SubjectPublicKeyInfo.
    pub fn spki(&self) -> Vec<u8> {
        let point = self.signing.verifying_key().to_encoded_point(false);
        sequence(&[
            sequence(&[oid(EC_PUBLIC_KEY), oid(PRIME256V1)]),
            bits(point.as_bytes()),
        ])
    }

    /// A DER certificate for `subject`'s key, signed by this key, valid from
    /// 2020 through 2049.
    pub fn issue(&self, subject: &TestKey, serial: u64, extensions: &[Vec<u8>]) -> Vec<u8> {
        let validity = [utc_time("200101000000Z"), utc_time("491231235959Z")];
        self.issue_valid(subject, serial, validity, extensions)
    }

    /// A DER certificate for `subject`'s key, signed by this key, valid from
    /// `validity[0]` through `validity[1]`.
    pub fn issue_valid(
        &self,
        subject: &TestKey,
        serial: u64,
        validity: [Vec<u8>; 2],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let algorithm = sequence(&[oid(ECDSA_WITH_SHA256)]);
        let mut tbs = vec![
            tlv(0xA0, &integer(2)),
            integer(serial),
            algorithm.clone(),
            self.name.clone(),
            sequence(&validity),
            subject.name.clone(),
            subject.spki(),
        ];
        if !extensions.is_empty() {
            tbs.push(tlv(0xA3, &sequence(extensions)));
        }
        let tbs = sequence(&tbs);
        let signature: Signature = self.signing.sign(&tbs);
        sequence(&[tbs, algorithm, bits(signature.to_der().as_bytes())])
    }
}
