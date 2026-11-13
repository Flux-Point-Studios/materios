//! Test suite for `pallet-tee-attestation`.
//!
//! Coverage:
//!   - `compose::*`           — composer logic (no I/O).
//!   - `reference_vectors::*` — real Android key-attestation chains (Pixel
//!     StrongBox, Samsung TEE, Seeker RKP StrongBox) reused verbatim from
//!     Acurast: every check accepts them except the receipt binding.
//!   - `tampering::*`         — mutated chain → must fail.
//!   - `challenge_binding::*` — evidence counts only for the receipt and
//!     chain its challenge commits to.
//!   - `chain_shape::*`       — trust anchors, and where the attestation
//!     extension may appear.
//!   - `pallet::*`            — `submit_evidence` extrinsic on a mock runtime.

use crate as pallet_tee_attestation;

#[path = "test_vectors.rs"]
mod test_vectors;

#[path = "synthetic_chain.rs"]
mod synthetic_chain;

use crate::types::{
    CertificateSerial, CompositeTrustScore, EvidenceEntry, EvidencePayload, EvidenceType,
    ReceiptBinding, ReceiptId, RegisteredReceipt, VerifiedEvidence, VerifyFailReason,
    VerifyOutcome, MAX_REVOCATIONS_PER_CALL, MAX_REVOKED_CERTIFICATES,
};
use crate::verifier::{
    arm_trustzone_challenge, verify_evidence, ArmTrustZoneVerifier, GOOGLE_ATTESTATION_ROOTS,
};
use base64ct::{Base64, Encoding};
use frame_support::{pallet_prelude::ConstU32, BoundedVec};
use parity_scale_codec::Encode;
use sha2::{Digest, Sha256};
use sp_core::H256;
use sp_runtime::BuildStorage;
use synthetic_chain::{
    attestation_extension, generalized_time, key_description, utc_time, TestKey, STRONGBOX,
};

// ---- Mock runtime --------------------------------------------------------

use frame_support::{construct_runtime, derive_impl};

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
    pub enum Test {
        System: frame_system,
        TeeAttestation: pallet_tee_attestation,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_tee_attestation::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Receipts = TestReceipts;
    type UnixTime = TestTime;
}

/// Block time kept in the test externalities' storage; 0 until set.
pub struct TestTime;

impl frame_support::traits::UnixTime for TestTime {
    fn now() -> core::time::Duration {
        core::time::Duration::from_secs(frame_support::storage::unhashed::get_or_default(
            TEST_NOW_KEY,
        ))
    }
}

const TEST_NOW_KEY: &[u8] = b":test:now";

fn set_now(seconds: u64) {
    frame_support::storage::unhashed::put(TEST_NOW_KEY, &seconds);
}

/// Receipt registry and committee kept in the test externalities' storage.
pub struct TestReceipts;

impl crate::ReceiptRegistry<u64> for TestReceipts {
    fn receipt(receipt_id: &ReceiptId) -> Option<RegisteredReceipt<u64>> {
        frame_support::storage::unhashed::get::<([u8; 32], u64)>(&test_receipt_key(receipt_id)).map(
            |(content_hash, submitter)| RegisteredReceipt {
                content_hash,
                submitter,
            },
        )
    }

    fn is_committee_member(who: &u64) -> bool {
        frame_support::storage::unhashed::exists(&test_committee_key(who))
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn register_receipt(receipt_id: ReceiptId, content_hash: [u8; 32], submitter: u64) {
        frame_support::storage::unhashed::put(
            &test_receipt_key(&receipt_id),
            &(content_hash, submitter),
        );
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn add_committee_member(who: u64) {
        add_committee_member(who);
    }
}

/// The account every receipt `put_receipt` records was submitted by.
const RECEIPT_SUBMITTER: u64 = 7;

fn test_receipt_key(receipt_id: &ReceiptId) -> Vec<u8> {
    [b":test:receipt:".as_slice(), receipt_id.as_bytes()].concat()
}

fn test_committee_key(who: &u64) -> Vec<u8> {
    [b":test:committee:".as_slice(), &who.to_le_bytes()].concat()
}

fn put_receipt(receipt_id: ReceiptId, content_hash: [u8; 32]) {
    frame_support::storage::unhashed::put(
        &test_receipt_key(&receipt_id),
        &(content_hash, RECEIPT_SUBMITTER),
    );
}

fn add_committee_member(who: u64) {
    frame_support::storage::unhashed::put(&test_committee_key(&who), &());
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

// ---- Helpers -------------------------------------------------------------

fn b64(s: &str) -> Vec<u8> {
    Base64::decode_vec(s).expect("test vector base64 decode")
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// An ArmTrustZone entry whose payload is the SCALE `Vec<Vec<u8>>` of these
/// DER certificates, root first.
fn entry_from_ders(chain: Vec<Vec<u8>>) -> EvidenceEntry {
    EvidenceEntry {
        evidence_type: EvidenceType::ArmTrustZone,
        payload: EvidencePayload::try_from(chain.encode()).expect("payload within bound"),
    }
}

fn arm_entry(chain_b64: &[&str]) -> EvidenceEntry {
    entry_from_ders(chain_b64.iter().map(|s| b64(s)).collect())
}

fn fake_content_hash() -> [u8; 32] {
    [0x42u8; 32]
}

fn receipt_id(byte: u8) -> ReceiptId {
    H256::from([byte; 32])
}

fn binding() -> ReceiptBinding {
    ReceiptBinding {
        genesis_hash: [0x69; 32],
        receipt_id: receipt_id(1),
        content_hash: fake_content_hash(),
    }
}

/// 2025-09-01T00:00:00Z: inside the validity of every intermediate in the
/// real vectors, the Seeker chain's short-lived RKP certificates included.
const IN_VALIDITY: u64 = 1_756_684_800;

fn never_revoked(_: &[u8]) -> bool {
    false
}

/// Verify against Google's roots at `now`, with `is_revoked` as the
/// revocation set.
fn verify_google_at(
    binding: &ReceiptBinding,
    entry: &EvidenceEntry,
    now: u64,
    is_revoked: &dyn Fn(&[u8]) -> bool,
) -> VerifyOutcome {
    let verifier = ArmTrustZoneVerifier {
        trusted_roots: &GOOGLE_ATTESTATION_ROOTS,
        now,
        is_revoked,
    };
    verify_evidence(binding, entry, &verifier)
}

fn verify_google(binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome {
    verify_google_at(binding, entry, IN_VALIDITY, &never_revoked)
}

/// Verify against the synthetic root instead of Google's, at `now`.
fn verify_synthetic_at(binding: &ReceiptBinding, entry: &EvidenceEntry, now: u64) -> VerifyOutcome {
    let root = TestKey::root().spki();
    let verifier = ArmTrustZoneVerifier {
        trusted_roots: &[&root],
        now,
        is_revoked: &never_revoked,
    };
    verify_evidence(binding, entry, &verifier)
}

fn verify_synthetic(binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome {
    verify_synthetic_at(binding, entry, IN_VALIDITY)
}

/// A one-certificate chain: the synthetic root issues `leaf_seed`'s key a
/// leaf carrying `key_description`.
fn synthetic_leaf(leaf_seed: u8, key_description: &[u8]) -> EvidenceEntry {
    let leaf = TestKey::new(leaf_seed, "Android Keystore Key");
    entry_from_ders(vec![TestKey::root().issue(
        &leaf,
        1,
        &[attestation_extension(key_description)],
    )])
}

/// A StrongBox KeyMint 3 leaf minted with `challenge`.
fn synthetic_entry(leaf_seed: u8, challenge: &[u8]) -> EvidenceEntry {
    synthetic_leaf(leaf_seed, &key_description(300, STRONGBOX, Some(challenge)))
}

/// A StrongBox KeyMint 3 leaf minted for `binding`.
fn bound_entry(leaf_seed: u8, binding: &ReceiptBinding) -> EvidenceEntry {
    synthetic_entry(leaf_seed, &arm_trustzone_challenge(binding))
}

fn flip(bytes: [u8; 32], bit: usize) -> [u8; 32] {
    let mut flipped = bytes;
    flipped[bit / 8] ^= 1 << (bit % 8);
    flipped
}

fn failed(reason: VerifyFailReason) -> VerifyOutcome {
    VerifyOutcome::Failed(reason)
}

// ---- Compose-function tests ---------------------------------------------

mod compose {
    use super::*;
    use crate::pallet::compose_score;

    fn mk(evidence_type: EvidenceType) -> VerifiedEvidence {
        VerifiedEvidence {
            evidence_type,
            attest_key_hash: [0u8; 32],
            raw_level: 1,
        }
    }

    #[test]
    fn empty_evidence_yields_baseline() {
        let s = compose_score(&[]);
        assert_eq!(s, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
    }

    #[test]
    fn single_arm_trustzone_yields_tier_one() {
        let s = compose_score(&[mk(EvidenceType::ArmTrustZone)]);
        assert_eq!(s, CompositeTrustScore::SINGLE_VENDOR);
    }

    #[test]
    fn arm_plus_amd_yields_tier_two() {
        let s = compose_score(&[mk(EvidenceType::ArmTrustZone), mk(EvidenceType::AmdSevSnp)]);
        assert_eq!(s, CompositeTrustScore::MULTI_VENDOR);
    }

    #[test]
    fn arm_plus_intel_plus_build_yields_tier_three() {
        let s = compose_score(&[
            mk(EvidenceType::ArmTrustZone),
            mk(EvidenceType::IntelTdx),
            mk(EvidenceType::ReproducibleBuild),
        ]);
        assert_eq!(s, CompositeTrustScore::MULTI_VENDOR_PLUS_BUILD);
    }

    #[test]
    fn full_quorum_yields_tier_four() {
        let s = compose_score(&[
            mk(EvidenceType::ArmTrustZone),
            mk(EvidenceType::IntelTdx),
            mk(EvidenceType::ReproducibleBuild),
            mk(EvidenceType::ZkVmExecution),
        ]);
        assert_eq!(s, CompositeTrustScore::FULL_QUORUM);
    }

    #[test]
    fn build_alone_does_not_lift_baseline() {
        // Build attestation alone proves you ran the expected code, not that
        // you ran it on attested hardware. Stays at tier 0.
        let s = compose_score(&[mk(EvidenceType::ReproducibleBuild)]);
        assert_eq!(s, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
    }

    #[test]
    fn zk_alone_does_not_lift_baseline() {
        let s = compose_score(&[mk(EvidenceType::ZkVmExecution)]);
        assert_eq!(s, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
    }

    #[test]
    fn tier_progresses_correctly_with_other_stub_types_present() {
        // Even though IntelTdx verifier returns NotImplemented at the
        // extrinsic layer, compose_score works from already-verified entries
        // — so this models the eventual Phase 3.x integration.
        let s = compose_score(&[mk(EvidenceType::ArmTrustZone)]);
        assert_eq!(s.0, 1);
        let s = compose_score(&[mk(EvidenceType::ArmTrustZone), mk(EvidenceType::AmdSevSnp)]);
        assert_eq!(s.0, 2);
    }
}

// ---- Reference vectors --------------------------------------------------
//
// The receipt binding is the verifier's last check, so `NonceMismatch` on a
// real chain means every earlier check (chain of trust, chain shape, parse,
// security level) accepted it.

mod reference_vectors {
    use super::*;
    use crate::vendor::acurast_attestation::asn::{Certificate, ParsedAttestation};
    use crate::vendor::acurast_attestation::extract_attestation;
    use crate::verifier::{key_description_challenge, key_description_security_level};

    /// Samsung chain that omits the root — Acurast's verifier accepts this
    /// because the immediately-following intermediate is signed by a pinned
    /// trusted root.
    #[test]
    fn samsung_chain_without_root_reaches_the_binding_check() {
        let entry = arm_entry(&[
            test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
            test_vectors::SAMSUNG_KEY_CERT,
        ]);
        assert_eq!(
            verify_google(&binding(), &entry),
            failed(VerifyFailReason::NonceMismatch)
        );
    }

    /// The parser exposes the challenge and key security level of real
    /// leaves at attestation versions 4 (Pixel), 100 (Samsung) and 300
    /// (Seeker).
    #[test]
    fn real_leaves_expose_their_challenge_and_security_level() {
        let leaves: [(&str, i64, &[u8], u32); 3] = [
            (test_vectors::PIXEL_KEY_CERT, 4, b"testasdf", 2),
            (test_vectors::SAMSUNG_KEY_CERT, 100, b"", 1),
            (
                test_vectors::SEEKER_KEY_CERT,
                300,
                &test_vectors::SEEKER_CHALLENGE,
                2,
            ),
        ];
        for (leaf, version, challenge, level) in leaves {
            let der = b64(leaf);
            let cert = asn1::parse_single::<Certificate>(&der).expect("real leaf parses");
            let Ok(ParsedAttestation::KeyDescription(kd)) =
                extract_attestation(cert.tbs_certificate.extensions)
            else {
                panic!("version {version} leaf has no KeyDescription");
            };
            assert_eq!(
                key_description_challenge(&kd),
                challenge,
                "version {version}"
            );
            assert_eq!(
                key_description_security_level(&kd),
                level,
                "version {version}"
            );
        }
    }
}

// ---- Tampering / negative tests -----------------------------------------

mod tampering {
    use super::*;

    /// Pixel chain where the leaf cert has its signature byte mutated.
    #[test]
    fn pixel_chain_with_tampered_leaf_fails() {
        let entry = arm_entry(&[
            test_vectors::PIXEL_ROOT_CERT,
            test_vectors::PIXEL_INTERMEDIATE_2_CERT,
            test_vectors::PIXEL_INTERMEDIATE_1_CERT,
            test_vectors::PIXEL_KEY_CERT_INVALID,
        ]);
        assert_eq!(
            verify_google(&binding(), &entry),
            failed(VerifyFailReason::ChainOfTrustBroken)
        );
    }

    /// Pixel chain where the root cert has been mutated — root is therefore
    /// not in pinned trust roots, chain MUST fail.
    #[test]
    fn pixel_chain_with_untrusted_root_fails() {
        let entry = arm_entry(&[
            test_vectors::PIXEL_ROOT_CERT_UNTRUSTED,
            test_vectors::PIXEL_INTERMEDIATE_2_CERT,
            test_vectors::PIXEL_INTERMEDIATE_1_CERT,
            test_vectors::PIXEL_KEY_CERT,
        ]);
        assert_eq!(
            verify_google(&binding(), &entry),
            failed(VerifyFailReason::ChainOfTrustBroken)
        );
    }

    #[test]
    fn empty_chain_fails() {
        assert_eq!(
            verify_google(&binding(), &entry_from_ders(Vec::new())),
            failed(VerifyFailReason::PayloadMalformed)
        );
    }

    #[test]
    fn malformed_payload_fails() {
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::ArmTrustZone,
            payload: EvidencePayload::try_from(vec![0x00, 0x01, 0x02, 0x03]).unwrap(),
        };
        assert_eq!(
            verify_google(&binding(), &entry),
            failed(VerifyFailReason::PayloadMalformed)
        );
    }
}

// ---- Challenge binding --------------------------------------------------

mod challenge_binding {
    use super::*;

    fn assert_nonce_mismatch(chain: &[&str], content_hash: [u8; 32]) {
        let replayed = ReceiptBinding {
            content_hash,
            ..binding()
        };
        assert_eq!(
            verify_google(&replayed, &arm_entry(chain)),
            failed(VerifyFailReason::NonceMismatch)
        );
    }

    /// The Pixel leaf's challenge is the 8-byte string "testasdf": a genuine
    /// chain minted for some other purpose, replayed against a receipt.
    #[test]
    fn real_pixel_chain_replayed_against_a_receipt_is_rejected() {
        assert_nonce_mismatch(
            &[
                test_vectors::PIXEL_ROOT_CERT,
                test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                test_vectors::PIXEL_KEY_CERT,
            ],
            fake_content_hash(),
        );
    }

    /// The Samsung leaf carries an empty challenge.
    #[test]
    fn real_chain_with_empty_challenge_is_rejected() {
        assert_nonce_mismatch(
            &[
                test_vectors::SAMSUNG_ROOT_CERT,
                test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
                test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
                test_vectors::SAMSUNG_KEY_CERT,
            ],
            fake_content_hash(),
        );
    }

    /// A public chain whose challenge is 32 bytes cannot be laundered into
    /// evidence by submitting a receipt whose content hash equals that
    /// challenge: receipt submitters choose `content_hash` freely.
    #[test]
    fn public_chain_cannot_be_bound_by_choosing_content_hash_equal_to_its_challenge() {
        assert_nonce_mismatch(
            &[
                test_vectors::SAMSUNG_ROOT_CERT,
                test_vectors::SEEKER_INTERMEDIATE_2_CERT,
                test_vectors::SEEKER_INTERMEDIATE_1_CERT,
                test_vectors::SEEKER_RKP_CERT,
                test_vectors::SEEKER_KEY_CERT,
            ],
            test_vectors::SEEKER_CHALLENGE,
        );
    }

    /// Known answers for device and gateway implementations: SHA-256 over
    /// the 51-byte ASCII tag, then the genesis hash, receipt id and content
    /// hash as 32 raw bytes each, 147 bytes in all.
    #[test]
    fn challenge_derivation_known_answers() {
        assert_eq!(
            crate::verifier::ARM_TRUSTZONE_CHALLENGE_TAG,
            b"materios/tee-attestation/arm-trustzone-challenge/v1"
        );
        let counting = ReceiptBinding {
            genesis_hash: core::array::from_fn(|i| i as u8),
            receipt_id: H256(core::array::from_fn(|i| 0x20 + i as u8)),
            content_hash: core::array::from_fn(|i| 0x40 + i as u8),
        };
        assert_eq!(
            arm_trustzone_challenge(&counting),
            hex_literal::hex!("2e557791bc4dc9f1730a2f2eb512df68a10426605113e2a3ca392a8e27336299")
        );
        let flat = ReceiptBinding {
            genesis_hash: [0x11; 32],
            receipt_id: H256([0x22; 32]),
            content_hash: [0x33; 32],
        };
        assert_eq!(
            arm_trustzone_challenge(&flat),
            hex_literal::hex!("210ef46d5f5c5da4d5f09f3ad2d2f63599680d6a019072d6f81cc780e935d344")
        );
    }

    #[test]
    fn leaf_minted_for_the_receipt_verifies() {
        let leaf_spki = TestKey::new(2, "Android Keystore Key").spki();
        assert_eq!(
            verify_synthetic(&binding(), &bound_entry(2, &binding())),
            VerifyOutcome::Verified(VerifiedEvidence {
                evidence_type: EvidenceType::ArmTrustZone,
                attest_key_hash: sha256(&leaf_spki),
                raw_level: 2,
            })
        );
    }

    fn assert_every_bit_flip_rejected(flipped: impl Fn(usize) -> ReceiptBinding) {
        let entry = bound_entry(2, &binding());
        assert!(matches!(
            verify_synthetic(&binding(), &entry),
            VerifyOutcome::Verified(_)
        ));
        for bit in 0..256 {
            assert_eq!(
                verify_synthetic(&flipped(bit), &entry),
                failed(VerifyFailReason::NonceMismatch),
                "bit {bit}"
            );
        }
    }

    #[test]
    fn every_single_bit_flip_of_content_hash_is_rejected() {
        assert_every_bit_flip_rejected(|bit| ReceiptBinding {
            content_hash: flip(binding().content_hash, bit),
            ..binding()
        });
    }

    #[test]
    fn every_single_bit_flip_of_receipt_id_is_rejected() {
        assert_every_bit_flip_rejected(|bit| ReceiptBinding {
            receipt_id: H256(flip(binding().receipt_id.0, bit)),
            ..binding()
        });
    }

    #[test]
    fn every_single_bit_flip_of_genesis_hash_is_rejected() {
        assert_every_bit_flip_rejected(|bit| ReceiptBinding {
            genesis_hash: flip(binding().genesis_hash, bit),
            ..binding()
        });
    }

    /// The derivation is domain-separated: a leaf whose challenge is the raw
    /// content hash is bound to nothing.
    #[test]
    fn raw_content_hash_as_challenge_is_rejected() {
        assert_eq!(
            verify_synthetic(&binding(), &synthetic_entry(2, &fake_content_hash())),
            failed(VerifyFailReason::NonceMismatch)
        );
    }

    #[test]
    fn leaf_with_empty_challenge_is_rejected() {
        assert_eq!(
            verify_synthetic(&binding(), &synthetic_entry(2, &[])),
            failed(VerifyFailReason::NonceMismatch)
        );
    }

    /// `attestationChallenge` is mandatory in every KeyDescription schema;
    /// a leaf without it does not parse.
    #[test]
    fn leaf_without_a_challenge_field_is_rejected() {
        let entry = synthetic_leaf(2, &key_description(300, STRONGBOX, None));
        assert_eq!(
            verify_synthetic(&binding(), &entry),
            failed(VerifyFailReason::PolicyViolation)
        );
    }

    /// Every KeyDescription version the parser accepts exposes the challenge
    /// the binding is checked against.
    #[test]
    fn every_accepted_key_description_version_is_bound() {
        let challenge = arm_trustzone_challenge(&binding());
        for version in [1, 2, 3, 4, 100, 200, 300] {
            let bound = synthetic_leaf(2, &key_description(version, STRONGBOX, Some(&challenge)));
            assert!(
                matches!(
                    verify_synthetic(&binding(), &bound),
                    VerifyOutcome::Verified(_)
                ),
                "version {version}"
            );
            let unbound = synthetic_leaf(2, &key_description(version, STRONGBOX, Some(&[0; 32])));
            assert_eq!(
                verify_synthetic(&binding(), &unbound),
                failed(VerifyFailReason::NonceMismatch),
                "version {version}"
            );
        }
    }

    /// KeyMint 4.0 and 5.0 (attestation versions 400 and 500) are outside
    /// the vendored parser: their leaves are refused, not read.
    #[test]
    fn key_description_versions_the_parser_does_not_know_are_rejected() {
        let challenge = arm_trustzone_challenge(&binding());
        for version in [400, 500] {
            let entry = synthetic_leaf(2, &key_description(version, STRONGBOX, Some(&challenge)));
            assert_eq!(
                verify_synthetic(&binding(), &entry),
                failed(VerifyFailReason::PolicyViolation),
                "version {version}"
            );
        }
    }
}

// ---- Chain shape --------------------------------------------------------

mod chain_shape {
    use super::*;

    /// The anchors ArmTrustZone trusts are exactly Google's published
    /// attestation root keys: the RSA root and the P-384 root that signs
    /// from February 2026. Digests are SHA-256 of the DER
    /// SubjectPublicKeyInfo published at
    /// developer.android.com/privacy-and-security/security-key-attestation.
    #[test]
    fn arm_trustzone_trusts_exactly_googles_attestation_roots() {
        let digests: Vec<[u8; 32]> = GOOGLE_ATTESTATION_ROOTS
            .iter()
            .map(|spki| sha256(spki))
            .collect();
        assert_eq!(
            digests,
            [
                hex_literal::hex!(
                    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae"
                ),
                hex_literal::hex!(
                    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"
                ),
            ]
        );
    }

    /// An Apple-anchored chain never reaches the leaf checks.
    #[test]
    fn apple_anchored_chain_is_not_an_arm_trustzone_anchor() {
        let entry = arm_entry(&[
            test_vectors::IOS_APP_ATTEST_CA_CERT,
            test_vectors::IOS_APP_ATTEST_KEY_CERT,
        ]);
        assert_eq!(
            verify_google(&binding(), &entry),
            failed(VerifyFailReason::ChainOfTrustBroken)
        );
    }

    #[test]
    fn synthetic_root_is_not_a_google_anchor() {
        assert_eq!(
            verify_google(&binding(), &bound_entry(2, &binding())),
            failed(VerifyFailReason::ChainOfTrustBroken)
        );
    }

    /// Root certificate, an intermediate without the extension, and a bound
    /// leaf: the shape of a real chain.
    #[test]
    fn chain_whose_only_attestation_extension_is_the_leafs_verifies() {
        let root = TestKey::root();
        let intermediate = TestKey::new(2, "Synthetic Batch Key");
        let leaf = TestKey::new(3, "Android Keystore Key");
        let challenge = arm_trustzone_challenge(&binding());
        let entry = entry_from_ders(vec![
            root.issue(&root, 1, &[]),
            root.issue(&intermediate, 2, &[]),
            intermediate.issue(
                &leaf,
                1,
                &[attestation_extension(&key_description(
                    300,
                    STRONGBOX,
                    Some(&challenge),
                ))],
            ),
        ]);
        assert!(matches!(
            verify_synthetic(&binding(), &entry),
            VerifyOutcome::Verified(_)
        ));
    }

    /// An attested key that signs a further certificate can write any
    /// KeyDescription into it. Only the first attestation extension was
    /// issued by secure hardware, so a chain carrying one above the leaf is
    /// refused even when the leaf is bound to the receipt.
    #[test]
    fn chain_extended_past_an_attested_key_is_rejected() {
        let root = TestKey::root();
        let attested = TestKey::new(2, "Android Keystore Key");
        let forged = TestKey::new(3, "Forged Leaf");
        let genuine = key_description(300, 1, Some(b"minted for another purpose"));
        let forged_claim =
            key_description(300, STRONGBOX, Some(&arm_trustzone_challenge(&binding())));
        let entry = entry_from_ders(vec![
            root.issue(&attested, 1, &[attestation_extension(&genuine)]),
            attested.issue(&forged, 1, &[attestation_extension(&forged_claim)]),
        ]);
        assert_eq!(
            verify_synthetic(&binding(), &entry),
            failed(VerifyFailReason::PolicyViolation)
        );
    }
}

mod chain_depth {
    use super::*;

    fn bound_claim() -> Vec<u8> {
        key_description(300, STRONGBOX, Some(&arm_trustzone_challenge(&binding())))
    }

    /// Root, two intermediates without the extension, bound leaf.
    #[test]
    fn four_certificate_chain_with_the_extension_only_in_the_leaf_verifies() {
        let root = TestKey::root();
        let batch = TestKey::new(2, "Batch");
        let mid = TestKey::new(3, "Mid");
        let leaf = TestKey::new(4, "Leaf");
        let entry = entry_from_ders(vec![
            root.issue(&root, 1, &[]),
            root.issue(&batch, 2, &[]),
            batch.issue(&mid, 3, &[]),
            mid.issue(&leaf, 1, &[attestation_extension(&bound_claim())]),
        ]);
        assert!(matches!(
            verify_synthetic(&binding(), &entry),
            VerifyOutcome::Verified(_)
        ));
    }

    /// A real device's shape, root → intermediate → batch → attested key,
    /// extended by a forged leaf the attested key signed.
    #[test]
    fn attested_key_three_below_the_root_cannot_sign_a_leaf() {
        let root = TestKey::root();
        let inter = TestKey::new(2, "Intermediate");
        let batch = TestKey::new(3, "Batch");
        let attested = TestKey::new(4, "Android Keystore Key");
        let forged = TestKey::new(5, "Forged");
        let genuine = key_description(300, 1, Some(b"other purpose"));
        let entry = entry_from_ders(vec![
            root.issue(&root, 1, &[]),
            root.issue(&inter, 2, &[]),
            inter.issue(&batch, 3, &[]),
            batch.issue(&attested, 1, &[attestation_extension(&genuine)]),
            attested.issue(&forged, 1, &[attestation_extension(&bound_claim())]),
        ]);
        assert_eq!(
            verify_synthetic(&binding(), &entry),
            failed(VerifyFailReason::PolicyViolation)
        );
    }

    /// The attested key signs an intermediate without the extension, which
    /// signs the forged leaf: the genuine extension sits two above it.
    #[test]
    fn attested_key_behind_an_intermediate_without_the_extension_is_rejected() {
        let root = TestKey::root();
        let attested = TestKey::new(4, "Android Keystore Key");
        let shim = TestKey::new(6, "Shim CA");
        let forged = TestKey::new(5, "Forged");
        let genuine = key_description(3, 1, Some(b"other purpose"));
        let entry = entry_from_ders(vec![
            root.issue(&root, 1, &[]),
            root.issue(&attested, 1, &[attestation_extension(&genuine)]),
            attested.issue(&shim, 7, &[]),
            shim.issue(&forged, 1, &[attestation_extension(&bound_claim())]),
        ]);
        assert_eq!(
            verify_synthetic(&binding(), &entry),
            failed(VerifyFailReason::PolicyViolation)
        );
    }

    /// Six certificates exceed the vendored chain bound before any
    /// signature is checked.
    #[test]
    fn six_certificate_chain_is_malformed() {
        let root = TestKey::root();
        let leaf = TestKey::new(4, "Leaf");
        let mut chain = vec![root.issue(&root, 1, &[]); 5];
        chain.push(root.issue(&leaf, 1, &[attestation_extension(&bound_claim())]));
        assert_eq!(
            verify_synthetic(&binding(), &entry_from_ders(chain)),
            failed(VerifyFailReason::PayloadMalformed)
        );
    }

    /// Repeating the self-signed root adds signature checks and nothing else.
    #[test]
    fn repeated_root_certificates_are_padding() {
        let root = TestKey::root();
        let leaf = TestKey::new(4, "Leaf");
        let mut chain = vec![root.issue(&root, 1, &[]); 4];
        chain.push(root.issue(&leaf, 1, &[attestation_extension(&bound_claim())]));
        assert!(matches!(
            verify_synthetic(&binding(), &entry_from_ders(chain)),
            VerifyOutcome::Verified(_)
        ));
    }
}

// ---- Certificate status: revocation and validity ------------------------

mod certificate_status {
    use super::*;
    use hex_literal::hex;

    /// The Seeker RKP attestation certificate's validity, the narrowest in
    /// its chain: 2025-08-19T10:29:40Z through 2025-09-16T12:58:58Z.
    const SEEKER_RKP_NOT_BEFORE: u64 = 1_755_599_380;
    const SEEKER_RKP_NOT_AFTER: u64 = 1_758_027_538;
    /// 2019-08-09T23:03:23Z: the Pixel intermediate the root issued becomes
    /// valid.
    const PIXEL_NOT_BEFORE: u64 = 1_565_391_803;
    /// 2032-01-01T00:00:00Z: every Pixel and Samsung intermediate has expired.
    const FACTORY_INTERMEDIATES_EXPIRED: u64 = 1_956_528_000;
    /// 2023-01-01T00:00:00Z.
    const IN_2023: u64 = 1_672_531_200;

    fn pixel() -> EvidenceEntry {
        arm_entry(&[
            test_vectors::PIXEL_ROOT_CERT,
            test_vectors::PIXEL_INTERMEDIATE_2_CERT,
            test_vectors::PIXEL_INTERMEDIATE_1_CERT,
            test_vectors::PIXEL_KEY_CERT,
        ])
    }

    fn samsung() -> EvidenceEntry {
        arm_entry(&[
            test_vectors::SAMSUNG_ROOT_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
            test_vectors::SAMSUNG_KEY_CERT,
        ])
    }

    fn samsung_without_root() -> EvidenceEntry {
        arm_entry(&[
            test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
            test_vectors::SAMSUNG_KEY_CERT,
        ])
    }

    fn seeker() -> EvidenceEntry {
        arm_entry(&[
            test_vectors::SAMSUNG_ROOT_CERT,
            test_vectors::SEEKER_INTERMEDIATE_2_CERT,
            test_vectors::SEEKER_INTERMEDIATE_1_CERT,
            test_vectors::SEEKER_RKP_CERT,
            test_vectors::SEEKER_KEY_CERT,
        ])
    }

    fn at(entry: &EvidenceEntry, now: u64) -> VerifyOutcome {
        verify_google_at(&binding(), entry, now, &never_revoked)
    }

    /// A synthetic chain root → intermediate → bound leaf, with each
    /// certificate's validity given; every name is a plain common name, so
    /// the chain is not factory provisioned.
    fn synthetic_chain(
        root_validity: [Vec<u8>; 2],
        intermediate_validity: [Vec<u8>; 2],
        leaf_validity: [Vec<u8>; 2],
    ) -> EvidenceEntry {
        let root = TestKey::root();
        let intermediate = TestKey::new(2, "Synthetic RKP Key");
        let leaf = TestKey::new(3, "Android Keystore Key");
        let kd = key_description(300, STRONGBOX, Some(&arm_trustzone_challenge(&binding())));
        entry_from_ders(vec![
            root.issue_valid(&root, 1, root_validity, &[]),
            root.issue_valid(&intermediate, 2, intermediate_validity, &[]),
            intermediate.issue_valid(&leaf, 1, leaf_validity, &[attestation_extension(&kd)]),
        ])
    }

    fn always() -> [Vec<u8>; 2] {
        [
            utc_time("200101000000Z"),
            generalized_time("20491231235959Z"),
        ]
    }

    fn through_2024() -> [Vec<u8>; 2] {
        [utc_time("200101000000Z"), utc_time("241231235959Z")]
    }

    /// RKP certificates are short-lived on purpose. The Seeker chain counts
    /// only while its RKP certificates are valid, both bounds inclusive.
    #[test]
    fn remotely_provisioned_chain_counts_only_inside_its_validity() {
        let outside = failed(VerifyFailReason::CertificateNotValidAtBlockTime);
        let inside = failed(VerifyFailReason::NonceMismatch);
        assert_eq!(at(&seeker(), SEEKER_RKP_NOT_BEFORE - 1), outside);
        assert_eq!(at(&seeker(), SEEKER_RKP_NOT_BEFORE), inside);
        assert_eq!(at(&seeker(), SEEKER_RKP_NOT_AFTER), inside);
        assert_eq!(at(&seeker(), SEEKER_RKP_NOT_AFTER + 1), outside);
    }

    /// Factory attestation keys cannot be rotated, and Google keeps trusting
    /// their certificates past expiry.
    #[test]
    fn factory_chains_outlive_their_intermediates() {
        for entry in [pixel(), samsung(), samsung_without_root()] {
            assert_eq!(
                at(&entry, FACTORY_INTERMEDIATES_EXPIRED),
                failed(VerifyFailReason::NonceMismatch)
            );
        }
    }

    #[test]
    fn factory_chain_before_its_intermediates_are_valid_is_rejected() {
        assert_eq!(
            at(&pixel(), PIXEL_NOT_BEFORE - 1),
            failed(VerifyFailReason::CertificateNotValidAtBlockTime)
        );
        assert_eq!(
            at(&pixel(), PIXEL_NOT_BEFORE),
            failed(VerifyFailReason::NonceMismatch)
        );
    }

    #[test]
    fn expired_intermediate_rejects_a_remotely_provisioned_chain() {
        let entry = synthetic_chain(always(), through_2024(), always());
        assert_eq!(
            verify_synthetic_at(&binding(), &entry, IN_VALIDITY),
            failed(VerifyFailReason::CertificateNotValidAtBlockTime)
        );
        assert!(matches!(
            verify_synthetic_at(&binding(), &entry, IN_2023),
            VerifyOutcome::Verified(_)
        ));
    }

    /// The pinned key is the anchor, not the certificate that carries it:
    /// the 2016 Google root certificate in the Pixel chain expired on
    /// 2026-05-24.
    #[test]
    fn anchor_certificate_validity_is_not_checked() {
        let entry = synthetic_chain(through_2024(), always(), always());
        assert!(matches!(
            verify_synthetic_at(&binding(), &entry, IN_VALIDITY),
            VerifyOutcome::Verified(_)
        ));
    }

    /// The device sets the leaf's validity (Keystore defaults run from 1970
    /// to 2048), so it says nothing about the attestation.
    #[test]
    fn leaf_validity_is_not_checked() {
        let not_yet = [
            generalized_time("20490101000000Z"),
            generalized_time("20491231235959Z"),
        ];
        let long_past = [utc_time("700101000000Z"), utc_time("710101000000Z")];
        for leaf_validity in [not_yet, long_past] {
            let entry = synthetic_chain(always(), always(), leaf_validity);
            assert!(matches!(
                verify_synthetic_at(&binding(), &entry, IN_VALIDITY),
                VerifyOutcome::Verified(_)
            ));
        }
    }

    /// Every certificate above the leaf is looked up by its serial's
    /// magnitude, the form Google's status list uses; Samsung's
    /// intermediate serial carries a DER sign byte that the lookup drops.
    #[test]
    fn a_revoked_certificate_above_the_leaf_rejects_the_chain() {
        let chains: [(EvidenceEntry, &[&[u8]]); 3] = [
            (
                pixel(),
                &[
                    &hex!("e8fa196314d2fa18"),
                    &hex!("038826676065899685f5"),
                    &hex!("15905857467176635834"),
                ],
            ),
            (
                samsung(),
                &[
                    &hex!("d50ff25ba3f2d6b3"),
                    &hex!("9deec34f5065075752a148897c9fe6e5"),
                    &hex!("707d9ec1b02deaf4ddcff5b058b5aeeb"),
                ],
            ),
            (
                seeker(),
                &[
                    &hex!("d50ff25ba3f2d6b3"),
                    &hex!("0388266760658996860f"),
                    &hex!("35772a634a0c9d3bc9466901d17cffad747726"),
                    &hex!("6b1a0d4882cf7b565006bd71a77f1159"),
                ],
            ),
        ];
        for (entry, serials) in chains {
            assert_eq!(
                verify_google_at(&binding(), &entry, IN_VALIDITY, &never_revoked),
                failed(VerifyFailReason::NonceMismatch)
            );
            for serial in serials {
                let revoked = |candidate: &[u8]| candidate == *serial;
                assert_eq!(
                    verify_google_at(&binding(), &entry, IN_VALIDITY, &revoked),
                    failed(VerifyFailReason::CertificateRevoked),
                    "serial {serial:02x?}"
                );
            }
        }
    }

    /// Expected values from `date -u -d <time> +%s`.
    #[test]
    fn certificate_times_convert_to_unix_seconds() {
        use crate::vendor::acurast_attestation::asn::Time;
        use crate::verifier::unix_seconds;
        let cases = [
            (utc_time("500101000000Z"), -631_152_000),
            (utc_time("700101000000Z"), 0),
            (utc_time("000229120000Z"), 951_825_600),
            (utc_time("250916125858Z"), 1_758_027_538),
            (generalized_time("20480101000000Z"), 2_461_449_600),
            (utc_time("491231235959Z"), 2_524_607_999),
            (generalized_time("99991231235959Z"), 253_402_300_799),
        ];
        for (der, seconds) in cases {
            let time = asn1::parse_single::<Time>(&der).expect("valid X.509 time");
            assert_eq!(unix_seconds(&time), seconds, "{der:02x?}");
        }
    }

    /// Leaf serials are chosen on the device (Keystore uses 1), so they
    /// name no attestation key.
    #[test]
    fn leaf_serials_are_not_checked_for_revocation() {
        let revoked = |candidate: &[u8]| candidate == [1];
        for entry in [pixel(), samsung(), seeker()] {
            assert_eq!(
                verify_google_at(&binding(), &entry, IN_VALIDITY, &revoked),
                failed(VerifyFailReason::NonceMismatch)
            );
        }
    }
}

// ---- Stub verifier tests ------------------------------------------------

mod stubs {
    use super::*;

    #[test]
    fn unimplemented_evidence_types_return_not_implemented() {
        for evidence_type in [
            EvidenceType::AmdSevSnp,
            EvidenceType::IntelTdx,
            EvidenceType::ReproducibleBuild,
            EvidenceType::ZkVmExecution,
        ] {
            let entry = EvidenceEntry {
                evidence_type,
                payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
            };
            assert_eq!(
                verify_google(&binding(), &entry),
                failed(VerifyFailReason::NotImplemented),
                "{evidence_type:?}"
            );
        }
    }
}

// ---- Pallet integration tests -------------------------------------------

mod pallet {
    use super::*;
    use crate::Error;
    use frame_support::{
        assert_noop, assert_ok, dispatch::DispatchResult, storage::with_storage_layer,
    };

    fn pixel_entry() -> EvidenceEntry {
        arm_entry(&[
            test_vectors::PIXEL_ROOT_CERT,
            test_vectors::PIXEL_INTERMEDIATE_2_CERT,
            test_vectors::PIXEL_INTERMEDIATE_1_CERT,
            test_vectors::PIXEL_KEY_CERT,
        ])
    }

    /// The binding the pallet derives for `receipt` on this chain.
    fn chain_binding(receipt: ReceiptId, content_hash: [u8; 32]) -> ReceiptBinding {
        ReceiptBinding {
            genesis_hash: System::block_hash(0).0,
            receipt_id: receipt,
            content_hash,
        }
    }

    fn enable_with_receipt(receipt: ReceiptId, content_hash: [u8; 32]) {
        System::set_block_number(1);
        set_now(IN_VALIDITY);
        assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
        put_receipt(receipt, content_hash);
    }

    /// The reason `submit_evidence`'s body rejects `entry` for, read from the
    /// `EvidenceRejected` event it deposits. Running outside the storage
    /// layer dispatch reverts that event in keeps it.
    fn rejection_reason(
        receipt: ReceiptId,
        content_hash: [u8; 32],
        entry: EvidenceEntry,
        roots: &[&[u8]],
    ) -> VerifyFailReason {
        assert_eq!(
            TeeAttestation::accept_evidence(
                &RECEIPT_SUBMITTER,
                receipt,
                content_hash,
                &entry,
                roots
            ),
            Err(Error::<Test>::VerificationFailed.into())
        );
        let reasons = [
            VerifyFailReason::NotImplemented,
            VerifyFailReason::PayloadMalformed,
            VerifyFailReason::ChainOfTrustBroken,
            VerifyFailReason::SignatureInvalid,
            VerifyFailReason::NonceMismatch,
            VerifyFailReason::UnknownChipId,
            VerifyFailReason::PolicyViolation,
            VerifyFailReason::CertificateRevoked,
            VerifyFailReason::CertificateNotValidAtBlockTime,
        ];
        match System::events().last().map(|record| record.event.clone()) {
            Some(RuntimeEvent::TeeAttestation(crate::Event::EvidenceRejected {
                reason, ..
            })) => reasons[reason as usize],
            other => panic!("expected EvidenceRejected, got {other:?}"),
        }
    }

    /// `submit_evidence`'s body for signer `who`, anchored at the synthetic
    /// root, in the storage layer dispatch runs every call in.
    fn accept_as(
        who: u64,
        receipt: ReceiptId,
        content_hash: [u8; 32],
        entry: EvidenceEntry,
    ) -> DispatchResult {
        let root = TestKey::root().spki();
        with_storage_layer(|| {
            TeeAttestation::accept_evidence(&who, receipt, content_hash, &entry, &[&root])
        })
    }

    /// `accept_as` the receipt's submitter.
    fn accept(receipt: ReceiptId, content_hash: [u8; 32], entry: EvidenceEntry) -> DispatchResult {
        accept_as(RECEIPT_SUBMITTER, receipt, content_hash, entry)
    }

    /// A payload no verifier accepts: rejecting it at `VerificationFailed`
    /// means the checks before verification passed.
    fn malformed_entry() -> EvidenceEntry {
        EvidenceEntry {
            evidence_type: EvidenceType::ArmTrustZone,
            payload: EvidencePayload::try_from(vec![0x00, 0x01, 0x02, 0x03]).unwrap(),
        }
    }

    /// One device mints as many attested keys as it likes, each bound to a
    /// receipt anyone can read. Only the receipt's submitter and the receipt
    /// committee may attach evidence, so a third party cannot fill a
    /// receipt.
    #[test]
    fn a_third_party_cannot_attach_evidence_to_a_receipt() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(0xAA);
            enable_with_receipt(id, fake_content_hash());
            let public = chain_binding(id, fake_content_hash());
            for seed in 100..108u8 {
                assert_noop!(
                    accept_as(666, id, fake_content_hash(), bound_entry(seed, &public)),
                    Error::<Test>::UnauthorizedSubmitter
                );
            }
            assert_eq!(TeeAttestation::verified_entries(&id).len(), 0);
            assert_ok!(accept(id, fake_content_hash(), bound_entry(50, &public)));
        });
    }

    #[test]
    fn submit_evidence_refuses_a_signer_unrelated_to_the_receipt() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(666),
                    id,
                    fake_content_hash(),
                    pixel_entry(),
                ),
                Error::<Test>::UnauthorizedSubmitter
            );
        });
    }

    /// The cert-daemon's evidence submitter signs with its committee key.
    #[test]
    fn a_committee_member_may_attach_evidence() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            add_committee_member(42);
            let entry = bound_entry(2, &chain_binding(id, fake_content_hash()));
            assert_ok!(accept_as(42, id, fake_content_hash(), entry));
            assert_eq!(TeeAttestation::verified_entries(&id).len(), 1);
        });
    }

    /// The composer counts each vendor class once, so a second entry of a
    /// type adds nothing; one per type leaves every other type its slot.
    #[test]
    fn a_receipt_holds_one_entry_per_evidence_type() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let bound = chain_binding(id, fake_content_hash());
            assert_ok!(accept(id, fake_content_hash(), bound_entry(2, &bound)));
            assert_noop!(
                accept(id, fake_content_hash(), bound_entry(3, &bound)),
                Error::<Test>::EvidenceTypeFull
            );
        });
    }

    /// Authorization, the per-type slot and the duplicate key are decided
    /// before any certificate is verified: each case below carries a chain
    /// that verification would reject.
    #[test]
    fn cheap_checks_run_before_chain_verification() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            assert_noop!(
                accept_as(666, id, fake_content_hash(), malformed_entry()),
                Error::<Test>::UnauthorizedSubmitter
            );
            assert_noop!(
                accept(id, fake_content_hash(), malformed_entry()),
                Error::<Test>::VerificationFailed
            );

            let bound = chain_binding(id, fake_content_hash());
            let leaf = TestKey::new(2, "Android Keystore Key");
            let kd = key_description(300, STRONGBOX, Some(&arm_trustzone_challenge(&bound)));
            let mut der = TestKey::root().issue(&leaf, 1, &[attestation_extension(&kd)]);
            assert_ok!(accept(
                id,
                fake_content_hash(),
                entry_from_ders(vec![der.clone()])
            ));

            *der.last_mut().expect("signature byte") ^= 0x01;
            assert_noop!(
                accept(id, fake_content_hash(), entry_from_ders(vec![der])),
                Error::<Test>::DuplicateEvidence
            );
            assert_noop!(
                accept(id, fake_content_hash(), malformed_entry()),
                Error::<Test>::EvidenceTypeFull
            );
        });
    }

    /// The genesis hash is block 0's, which System keeps past its block-hash
    /// horizon; the parent hash would bind evidence to the latest block.
    #[test]
    fn evidence_binds_to_block_zero_past_the_block_hash_horizon() {
        new_test_ext().execute_with(|| {
            let genesis = H256::repeat_byte(0xC7);
            let mut parent = genesis;
            for n in 1u64..=40 {
                System::initialize(&n, &parent, &Default::default());
                System::finalize();
                parent = H256::from_low_u64_be(0x1000 + n);
            }
            assert_eq!(System::block_hash(0), genesis);
            assert_eq!(System::block_hash(5), H256::zero());

            let id = receipt_id(0xB0);
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            put_receipt(id, fake_content_hash());
            let bound = ReceiptBinding {
                genesis_hash: genesis.0,
                receipt_id: id,
                content_hash: fake_content_hash(),
            };
            for stale in [[69u8; 32], parent.0] {
                let minted = ReceiptBinding {
                    genesis_hash: stale,
                    ..bound
                };
                assert_noop!(
                    accept(id, fake_content_hash(), bound_entry(3, &minted)),
                    Error::<Test>::VerificationFailed
                );
            }
            assert_ok!(accept(id, fake_content_hash(), bound_entry(2, &bound)));
        });
    }

    #[test]
    fn submit_evidence_rejects_a_real_chain_bound_to_no_receipt() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    pixel_entry(),
                ),
                Error::<Test>::VerificationFailed
            );
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
        });
    }

    #[test]
    fn a_real_chain_is_rejected_for_its_binding_inside_its_validity() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            assert_eq!(
                rejection_reason(
                    id,
                    fake_content_hash(),
                    pixel_entry(),
                    &GOOGLE_ATTESTATION_ROOTS
                ),
                VerifyFailReason::NonceMismatch
            );
        });
    }

    /// Certificate validity is judged at the block timestamp
    /// (`Config::UnixTime`).
    #[test]
    fn evidence_is_checked_against_the_block_timestamp() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let root = TestKey::root();
            let intermediate = TestKey::new(2, "Synthetic RKP Key");
            let leaf = TestKey::new(3, "Android Keystore Key");
            let kd = key_description(
                300,
                STRONGBOX,
                Some(&arm_trustzone_challenge(&chain_binding(
                    id,
                    fake_content_hash(),
                ))),
            );
            let entry = entry_from_ders(vec![
                root.issue_valid(
                    &intermediate,
                    2,
                    [utc_time("200101000000Z"), utc_time("241231235959Z")],
                    &[],
                ),
                intermediate.issue(&leaf, 1, &[attestation_extension(&kd)]),
            ]);
            let root_spki = root.spki();
            assert_eq!(
                rejection_reason(id, fake_content_hash(), entry.clone(), &[&root_spki]),
                VerifyFailReason::CertificateNotValidAtBlockTime
            );
            set_now(1_672_531_200);
            assert_ok!(accept(id, fake_content_hash(), entry));
        });
    }

    #[test]
    fn submit_evidence_trusts_only_googles_roots() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let entry = bound_entry(2, &chain_binding(id, fake_content_hash()));
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    entry,
                ),
                Error::<Test>::VerificationFailed
            );
        });
    }

    #[test]
    fn evidence_bound_to_the_receipt_is_recorded_and_scored() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let entry = bound_entry(2, &chain_binding(id, fake_content_hash()));
            assert_ok!(accept(id, fake_content_hash(), entry));

            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::SINGLE_VENDOR
            );
            let attest_key_hash = sha256(&TestKey::new(2, "Android Keystore Key").spki());
            assert_eq!(
                TeeAttestation::verified_entries(&id).into_inner(),
                vec![VerifiedEvidence {
                    evidence_type: EvidenceType::ArmTrustZone,
                    attest_key_hash,
                    raw_level: 2,
                }]
            );
            System::assert_last_event(
                crate::Event::<Test>::EvidenceVerified {
                    receipt_id: id,
                    evidence_type: EvidenceType::ArmTrustZone,
                    attest_key_hash,
                    raw_level: 2,
                    new_score: CompositeTrustScore::SINGLE_VENDOR,
                }
                .into(),
            );
        });
    }

    /// Receipts may share a content hash; evidence minted for one of them
    /// does not count for another.
    #[test]
    fn evidence_bound_to_one_receipt_is_rejected_for_another_with_the_same_content() {
        new_test_ext().execute_with(|| {
            let first = receipt_id(1);
            let second = receipt_id(2);
            enable_with_receipt(first, fake_content_hash());
            put_receipt(second, fake_content_hash());
            let entry = bound_entry(2, &chain_binding(first, fake_content_hash()));

            assert_ok!(accept(first, fake_content_hash(), entry.clone()));
            assert_noop!(
                accept(second, fake_content_hash(), entry),
                Error::<Test>::VerificationFailed
            );
            assert_eq!(
                TeeAttestation::trust_score(&second),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
        });
    }

    #[test]
    fn evidence_minted_for_another_network_is_rejected() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let other_network = ReceiptBinding {
                genesis_hash: [0x01; 32],
                ..chain_binding(id, fake_content_hash())
            };
            assert_noop!(
                accept(id, fake_content_hash(), bound_entry(2, &other_network)),
                Error::<Test>::VerificationFailed
            );
        });
    }

    #[test]
    fn evidence_for_an_unknown_receipt_is_rejected() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            System::set_block_number(1);
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    pixel_entry(),
                ),
                Error::<Test>::UnknownReceipt
            );
        });
    }

    #[test]
    fn every_single_bit_flip_of_the_submitted_content_hash_is_rejected() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            for bit in 0..256 {
                let submitted = flip(fake_content_hash(), bit);
                let entry = bound_entry(2, &chain_binding(id, submitted));
                assert_noop!(
                    accept(id, submitted, entry),
                    Error::<Test>::ContentHashMismatch
                );
            }
        });
    }

    #[test]
    fn the_same_attested_key_is_recorded_once_per_receipt() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let entry = bound_entry(2, &chain_binding(id, fake_content_hash()));
            assert_ok!(accept(id, fake_content_hash(), entry.clone()));
            assert_noop!(
                accept(id, fake_content_hash(), entry),
                Error::<Test>::DuplicateEvidence
            );
        });
    }

    #[test]
    fn submit_evidence_with_tampered_chain_fails_extrinsic() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(2);
            enable_with_receipt(id, fake_content_hash());
            let entry = arm_entry(&[
                test_vectors::PIXEL_ROOT_CERT,
                test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                test_vectors::PIXEL_KEY_CERT_INVALID,
            ]);
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    entry,
                ),
                Error::<Test>::VerificationFailed
            );
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
        });
    }

    #[test]
    fn no_evidence_yields_baseline_score() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(3);
            let score = TeeAttestation::trust_score(&id);
            assert_eq!(score, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
        });
    }

    #[test]
    fn stub_evidence_type_fails_the_extrinsic() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(4);
            enable_with_receipt(id, fake_content_hash());
            let entry = EvidenceEntry {
                evidence_type: EvidenceType::AmdSevSnp,
                payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
            };
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    entry,
                ),
                Error::<Test>::VerificationFailed
            );
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
        });
    }

    // ---- Revocation set ----

    fn serials(
        list: &[&[u8]],
    ) -> BoundedVec<CertificateSerial, ConstU32<MAX_REVOCATIONS_PER_CALL>> {
        list.iter()
            .map(|serial| {
                CertificateSerial::try_from(serial.to_vec()).expect("serial within bound")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("within the per-call bound")
    }

    fn revoke(list: &[&[u8]], revoked: bool) -> DispatchResult {
        TeeAttestation::set_certificates_revoked(RuntimeOrigin::root(), serials(list), revoked)
    }

    fn revocation_events() -> Vec<(Vec<u8>, bool)> {
        System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::TeeAttestation(crate::Event::CertificateRevocationSet {
                    serial,
                    revoked,
                }) => Some((serial.into_inner(), revoked)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn set_certificates_revoked_requires_root() {
        new_test_ext().execute_with(|| {
            assert_noop!(
                TeeAttestation::set_certificates_revoked(
                    RuntimeOrigin::signed(1),
                    serials(&[&[0x77]]),
                    true
                ),
                sp_runtime::DispatchError::BadOrigin
            );
        });
    }

    /// Revoking the serial of a certificate above the leaf rejects every
    /// chain through it until the serial is cleared.
    #[test]
    fn a_revoked_intermediate_rejects_evidence_until_cleared() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let root = TestKey::root();
            let intermediate = TestKey::new(2, "Synthetic RKP Key");
            let leaf = TestKey::new(3, "Android Keystore Key");
            let kd = key_description(
                300,
                STRONGBOX,
                Some(&arm_trustzone_challenge(&chain_binding(
                    id,
                    fake_content_hash(),
                ))),
            );
            let entry = entry_from_ders(vec![
                root.issue(&intermediate, 0x7777, &[]),
                intermediate.issue(&leaf, 1, &[attestation_extension(&kd)]),
            ]);
            let root_spki = root.spki();

            assert_ok!(revoke(&[&[0x77, 0x77]], true));
            assert_eq!(
                rejection_reason(id, fake_content_hash(), entry.clone(), &[&root_spki]),
                VerifyFailReason::CertificateRevoked
            );
            assert_ok!(revoke(&[&[0x77, 0x77]], false));
            assert_ok!(accept(id, fake_content_hash(), entry));
        });
    }

    /// Each serial whose state changes emits one event; repeats and serials
    /// already in the requested state change nothing.
    #[test]
    fn revocation_changes_are_recorded_and_counted() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            assert_ok!(revoke(&[&[0x0a], &[0x0b], &[0x0a]], true));
            assert_ok!(revoke(&[&[0x0a]], true));
            assert_eq!(crate::RevokedCertificateCount::<Test>::get(), 2);
            assert_ok!(revoke(&[&[0x0a], &[0x0c]], false));
            assert_eq!(crate::RevokedCertificateCount::<Test>::get(), 1);
            assert!(crate::RevokedCertificates::<Test>::contains_key(
                CertificateSerial::try_from(vec![0x0b]).unwrap()
            ));
            assert_eq!(
                revocation_events(),
                vec![(vec![0x0a], true), (vec![0x0b], true), (vec![0x0a], false)]
            );
        });
    }

    /// A serial with a leading zero byte, or none at all, would never match
    /// a certificate's serial magnitude.
    #[test]
    fn non_canonical_serials_are_refused() {
        new_test_ext().execute_with(|| {
            for serial in [&[][..], &[0x00, 0x77][..], &[0x00][..]] {
                assert_noop!(revoke(&[serial], true), Error::<Test>::NonCanonicalSerial);
            }
        });
    }

    #[test]
    fn the_revoked_set_is_bounded() {
        new_test_ext().execute_with(|| {
            let all: Vec<[u8; 3]> = (0..MAX_REVOKED_CERTIFICATES + 1)
                .map(|i| {
                    let [_, _, high, low] = i.to_be_bytes();
                    [0x01, high, low]
                })
                .collect();
            let (fits, overflow) = all.split_at(MAX_REVOKED_CERTIFICATES as usize);
            for batch in fits.chunks(MAX_REVOCATIONS_PER_CALL as usize) {
                let batch: Vec<&[u8]> = batch.iter().map(|serial| &serial[..]).collect();
                assert_ok!(revoke(&batch, true));
            }
            assert_eq!(
                crate::RevokedCertificateCount::<Test>::get(),
                MAX_REVOKED_CERTIFICATES
            );
            assert_noop!(
                revoke(&[&overflow[0][..]], true),
                Error::<Test>::TooManyRevokedCertificates
            );
        });
    }

    // ---- Genesis-disabled kill-switch ----

    /// At genesis the pallet is disabled; submit_evidence fails with
    /// PalletDisabled before any receipt lookup or verification.
    #[test]
    fn submit_evidence_when_disabled_fails() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            let id = receipt_id(20);
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(RECEIPT_SUBMITTER),
                    id,
                    fake_content_hash(),
                    pixel_entry(),
                ),
                Error::<Test>::PalletDisabled
            );
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
            assert_eq!(TeeAttestation::verified_entries(&id).len(), 0);
        });
    }

    /// set_disabled requires root; a signed-by-account-1 origin must be
    /// rejected with BadOrigin.
    #[test]
    fn set_disabled_requires_root() {
        new_test_ext().execute_with(|| {
            assert_noop!(
                TeeAttestation::set_disabled(RuntimeOrigin::signed(1), false),
                sp_runtime::DispatchError::BadOrigin
            );
        });
    }
}

// ---- Upgrade: evidence recorded before receipt binding -------------------

mod migration {
    use super::*;
    use frame_support::assert_ok;
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The pre-binding receipt: the storage `main` (7d5c36e) wrote when the
    /// public Pixel chain was submitted eight times for receipt `0xAB..AB`.
    const RECEIPT: [u8; 32] = [0xAB; 32];
    const CONTENT_HASH: [u8; 32] = [0x5E; 32];

    /// Raw keys and values as recorded from that run: `Disabled`, then
    /// `VerifiedEntries` (eight `ArmTrustZone` entries for the Pixel leaf
    /// key at StrongBox level) and `CompositeTrustScores` (single vendor).
    fn pre_binding_storage() -> Vec<(Vec<u8>, Vec<u8>)> {
        let entry = "0258fd384003f5701a74500becbfc715be854dfecc959986fcf6021ded38b5d43602000000";
        vec![
            (
                unhex("402cb5d3b38584d34a725343c873c1694111f095de636b13b56e54ec39e9c155"),
                unhex("00"),
            ),
            (
                unhex(concat!(
                    "402cb5d3b38584d34a725343c873c169636d7fa15cfed2f7849624c1a078807e",
                    "6bb3853c34cfcf3b081e5715f3c82748",
                    "abababababababababababababababababababababababababababababababab"
                )),
                unhex(&format!("20{}", entry.repeat(8))),
            ),
            (
                unhex(concat!(
                    "402cb5d3b38584d34a725343c873c169b4b0f3549ee0a56adac6f5e9aa10ada1",
                    "6bb3853c34cfcf3b081e5715f3c82748",
                    "abababababababababababababababababababababababababababababababab"
                )),
                unhex("01"),
            ),
        ]
    }

    /// Before binding, the verifier accepted any Google-rooted chain for any
    /// receipt, so no entry recorded then is bound to its receipt. The
    /// upgrade clears them all from the committed state, as a chain holds
    /// them; the receipt then takes evidence minted for it.
    #[test]
    fn the_upgrade_clears_evidence_recorded_before_binding() {
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            System::set_block_number(1);
            for (key, value) in pre_binding_storage() {
                sp_io::storage::set(&key, &value);
            }
        });
        ext.commit_all().expect("pre-binding storage committed");
        ext.execute_with(|| {
            let id = H256(RECEIPT);
            assert_eq!(
                TeeAttestation::on_chain_storage_version(),
                StorageVersion::new(0)
            );
            assert_eq!(TeeAttestation::verified_entries(&id).len(), 8);
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::SINGLE_VENDOR
            );

            crate::migrations::ClearUnboundEvidence::<Test>::on_runtime_upgrade();

            assert_eq!(
                TeeAttestation::on_chain_storage_version(),
                StorageVersion::new(1)
            );
            assert!(crate::VerifiedEntries::<Test>::iter_keys().next().is_none());
            assert!(crate::CompositeTrustScores::<Test>::iter_keys()
                .next()
                .is_none());
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE
            );
            assert!(!crate::Disabled::<Test>::get());

            put_receipt(id, CONTENT_HASH);
            let bound = ReceiptBinding {
                genesis_hash: System::block_hash(0).0,
                receipt_id: id,
                content_hash: CONTENT_HASH,
            };
            let root = TestKey::root().spki();
            assert_ok!(TeeAttestation::accept_evidence(
                &RECEIPT_SUBMITTER,
                id,
                CONTENT_HASH,
                &bound_entry(60, &bound),
                &[&root]
            ));
        });
    }

    /// Evidence recorded after the upgrade stays: the migration runs once.
    #[test]
    fn the_upgrade_runs_once() {
        new_test_ext().execute_with(|| {
            let id = H256(RECEIPT);
            StorageVersion::new(1).put::<TeeAttestation>();
            crate::CompositeTrustScores::<Test>::insert(id, CompositeTrustScore::SINGLE_VENDOR);
            crate::migrations::ClearUnboundEvidence::<Test>::on_runtime_upgrade();
            assert_eq!(
                TeeAttestation::trust_score(&id),
                CompositeTrustScore::SINGLE_VENDOR
            );
        });
    }
}

// ---- Verifier-internal unit tests ---------------------------------------
//
// These bypass the full X.509 chain validation to exercise the
// security-level extraction directly via a synthetic `KeyDescription`.

mod verifier_internal {
    use crate::vendor::acurast_attestation::asn::{
        AuthorizationListV1, KeyDescription, KeyDescriptionV1, SecurityLevel,
    };
    use crate::verifier::key_description_security_level;

    /// Build an `AuthorizationListV1` with every field None — sufficient
    /// for testing the security-level reader, which only reads top-level
    /// `KeyDescription` fields.
    fn empty_auth_list() -> AuthorizationListV1<'static> {
        AuthorizationListV1 {
            purpose: None,
            algorithm: None,
            key_size: None,
            digest: None,
            padding: None,
            ec_curve: None,
            rsa_public_exponent: None,
            rollback_resistance: None,
            active_date_time: None,
            origination_expire_date_time: None,
            usage_expire_date_time: None,
            no_auth_required: None,
            user_auth_type: None,
            auth_timeout: None,
            allow_while_on_body: None,
            trusted_user_presence_required: None,
            trusted_confirmation_required: None,
            unlocked_device_required: None,
            all_applications: None,
            application_id: None,
            creation_date_time: None,
            origin: None,
            root_of_trust: None,
            os_version: None,
            os_patch_level: None,
        }
    }

    fn kd_v1_with_levels(attestation_level: u32, key_mint_level: u32) -> KeyDescription<'static> {
        KeyDescription::V1(KeyDescriptionV1 {
            attestation_version: 1,
            attestation_security_level: SecurityLevel::new(attestation_level),
            key_mint_version: 1,
            key_mint_security_level: SecurityLevel::new(key_mint_level),
            attestation_challenge: &[],
            unique_id: &[],
            software_enforced: empty_auth_list(),
            tee_enforced: empty_auth_list(),
        })
    }

    /// M-1: key_description_security_level MUST read `key_mint_security_level`
    /// (where the KEY actually lives), NOT `attestation_security_level` (the
    /// SIGNER's level). When attestation=1 (TEE) and key_mint=0 (SOFTWARE),
    /// the helper must surface `0` so the verifier rejects the entry.
    #[test]
    fn security_level_reads_key_mint_not_attestation() {
        // attestation = TEE (1), key_mint = SOFTWARE (0)
        let kd = kd_v1_with_levels(1, 0);
        let level = key_description_security_level(&kd);
        assert_eq!(
            level, 0,
            "expected key_mint_security_level (=0/SOFTWARE), got {} \
             (verifier is reading attestation_security_level instead — M-1)",
            level
        );
    }

    /// M-1 sanity check: when key_mint is StrongBox (2) and attestation is
    /// TEE (1), the helper must surface 2 (the key's level), not 1.
    #[test]
    fn security_level_surfaces_strongbox_when_key_mint_is_strongbox() {
        let kd = kd_v1_with_levels(1, 2);
        let level = key_description_security_level(&kd);
        assert_eq!(level, 2);
    }

    // ---- Positive allowlist: TEE=1, StrongBox=2 ----

    use crate::verifier::is_security_level_allowed;

    #[test]
    fn allowlist_accepts_trusted_environment() {
        assert!(is_security_level_allowed(1));
    }

    #[test]
    fn allowlist_accepts_strongbox() {
        assert!(is_security_level_allowed(2));
    }

    #[test]
    fn allowlist_rejects_software() {
        assert!(!is_security_level_allowed(0));
    }

    /// AOSP KeyMint SecurityLevel 3 = KEYSTORE: key lives in the Android
    /// Keystore daemon's userspace, not TEE-rooted, must be rejected.
    #[test]
    fn allowlist_rejects_keystore_level_3() {
        assert!(!is_security_level_allowed(3));
    }

    /// And anything beyond the AOSP-defined enum (future values, parsing
    /// errors, etc) must also be rejected.
    #[test]
    fn allowlist_rejects_unknown_high_values() {
        assert!(!is_security_level_allowed(4));
        assert!(!is_security_level_allowed(99));
        assert!(!is_security_level_allowed(u32::MAX));
    }
}

/// Compile-time guard: `VerifiedEvidence`'s identity field is `attest_key_hash`
/// (SHA-256 of leaf SPKI DER). Failing this test means a field rename or
/// removal that would break downstream consumers.
#[test]
fn verified_evidence_field_is_named_attest_key_hash() {
    use crate::types::VerifiedEvidence;
    let _v = VerifiedEvidence {
        evidence_type: crate::types::EvidenceType::ArmTrustZone,
        attest_key_hash: [0u8; 32],
        raw_level: 1,
    };
}
