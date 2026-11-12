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
    CompositeTrustScore, EvidenceEntry, EvidencePayload, EvidenceType, ReceiptBinding, ReceiptId,
    VerifiedEvidence, VerifyFailReason, VerifyOutcome,
};
use crate::verifier::{arm_trustzone_challenge, verify_evidence, GOOGLE_ATTESTATION_ROOTS};
use base64ct::{Base64, Encoding};
use parity_scale_codec::Encode;
use sha2::{Digest, Sha256};
use sp_core::H256;
use sp_runtime::BuildStorage;
use synthetic_chain::{attestation_extension, key_description, TestKey, STRONGBOX};

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
}

/// Receipt registry kept in the test externalities' storage.
pub struct TestReceipts;

impl crate::ReceiptRegistry for TestReceipts {
    fn content_hash(receipt_id: &ReceiptId) -> Option<[u8; 32]> {
        frame_support::storage::unhashed::get(&test_receipt_key(receipt_id))
    }
}

fn test_receipt_key(receipt_id: &ReceiptId) -> Vec<u8> {
    [b":test:receipt:".as_slice(), receipt_id.as_bytes()].concat()
}

fn put_receipt(receipt_id: ReceiptId, content_hash: [u8; 32]) {
    frame_support::storage::unhashed::put(&test_receipt_key(&receipt_id), &content_hash);
}

fn new_test_ext() -> sp_io::TestExternalities {
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

fn verify_google(binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome {
    verify_evidence(binding, entry, &GOOGLE_ATTESTATION_ROOTS)
}

/// Verify against the synthetic root instead of Google's.
fn verify_synthetic(binding: &ReceiptBinding, entry: &EvidenceEntry) -> VerifyOutcome {
    let root = TestKey::root().spki();
    verify_evidence(binding, entry, &[&root])
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
        assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
        put_receipt(receipt, content_hash);
    }

    /// `submit_evidence`'s body anchored at the synthetic root, in the
    /// storage layer dispatch runs every call in.
    fn accept(receipt: ReceiptId, content_hash: [u8; 32], entry: EvidenceEntry) -> DispatchResult {
        let root = TestKey::root().spki();
        with_storage_layer(|| {
            TeeAttestation::accept_evidence(receipt, content_hash, &entry, &[&root])
        })
    }

    #[test]
    fn submit_evidence_rejects_a_real_chain_bound_to_no_receipt() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(1),
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
    fn submit_evidence_trusts_only_googles_roots() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let entry = bound_entry(2, &chain_binding(id, fake_content_hash()));
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(1),
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
                    RuntimeOrigin::signed(1),
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
    fn a_receipt_holds_at_most_eight_entries() {
        new_test_ext().execute_with(|| {
            let id = receipt_id(1);
            enable_with_receipt(id, fake_content_hash());
            let bound = chain_binding(id, fake_content_hash());
            for seed in 2..10 {
                assert_ok!(accept(id, fake_content_hash(), bound_entry(seed, &bound)));
            }
            assert_eq!(TeeAttestation::verified_entries(&id).len(), 8);
            assert_noop!(
                accept(id, fake_content_hash(), bound_entry(10, &bound)),
                Error::<Test>::TooManyEntries
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
                    RuntimeOrigin::signed(1),
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
                    RuntimeOrigin::signed(1),
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
                    RuntimeOrigin::signed(1),
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
