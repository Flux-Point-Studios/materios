//! Test suite for `pallet-tee-attestation`.
//!
//! Coverage:
//!   - `compose::*`           — composer logic (no I/O).
//!   - `reference_vectors::*` — Acurast's published Android Key Attestation
//!     test chains (Pixel StrongBox, Samsung TEE), reused verbatim.
//!   - `tampering::*`         — mutated chain → must fail.
//!   - `pallet::*`            — `submit_evidence` extrinsic on a mock runtime.

#![cfg(test)]

use crate as pallet_tee_attestation;

#[path = "test_vectors.rs"]
mod test_vectors;

use crate::types::{
    CompositeTrustScore, EvidenceEntry, EvidencePayload, EvidenceType, ReceiptId, VerifiedEvidence,
    VerifyFailReason, VerifyOutcome,
};
use crate::verifier::verify_evidence;
use base64ct::{Base64, Encoding};
use parity_scale_codec::Encode;
use sp_core::H256;
use sp_runtime::BuildStorage;

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

/// Encode a list of DER-encoded certs as the SCALE-`Vec<Vec<u8>>` payload our
/// verifier expects.
fn arm_payload(chain_b64: &[&str]) -> EvidencePayload {
    let raw_chain: Vec<Vec<u8>> = chain_b64.iter().map(|s| b64(s)).collect();
    let encoded = raw_chain.encode();
    EvidencePayload::try_from(encoded).expect("payload within bound")
}

fn arm_entry(chain_b64: &[&str]) -> EvidenceEntry {
    EvidenceEntry {
        evidence_type: EvidenceType::ArmTrustZone,
        payload: arm_payload(chain_b64),
    }
}

fn fake_content_hash() -> [u8; 32] {
    [0x42u8; 32]
}

fn receipt_id(byte: u8) -> ReceiptId {
    H256::from([byte; 32])
}

// ---- Compose-function tests ---------------------------------------------

mod compose {
    use super::*;
    use crate::pallet::compose_score;

    fn mk(evidence_type: EvidenceType) -> VerifiedEvidence {
        VerifiedEvidence {
            evidence_type,
            chip_id_hash: [0u8; 32],
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

mod reference_vectors {
    use super::*;

    /// PIXEL_ROOT + INTERMEDIATES + leaf — Pixel StrongBox-rooted chain.
    #[test]
    fn pixel_strongbox_chain_verifies() {
        let entry = arm_entry(&[
            test_vectors::PIXEL_ROOT_CERT,
            test_vectors::PIXEL_INTERMEDIATE_2_CERT,
            test_vectors::PIXEL_INTERMEDIATE_1_CERT,
            test_vectors::PIXEL_KEY_CERT,
        ]);
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Verified(v) => {
                assert_eq!(v.evidence_type, EvidenceType::ArmTrustZone);
                // StrongBox = 2; TEE = 1. The Pixel test vector is StrongBox.
                assert!(v.raw_level >= 1, "raw_level was {}", v.raw_level);
                // chip_id_hash should be 32 non-zero bytes.
                assert_ne!(v.chip_id_hash, [0u8; 32]);
            }
            VerifyOutcome::Failed(r) => panic!("Pixel chain should verify, got {:?}", r),
        }
    }

    /// Samsung TEE-only chain — KeyMint v1, attestation_version = 100.
    #[test]
    fn samsung_tee_chain_verifies() {
        let entry = arm_entry(&[
            test_vectors::SAMSUNG_ROOT_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
            test_vectors::SAMSUNG_KEY_CERT,
        ]);
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Verified(v) => {
                assert_eq!(v.evidence_type, EvidenceType::ArmTrustZone);
                assert!(v.raw_level >= 1);
            }
            VerifyOutcome::Failed(r) => panic!("Samsung chain should verify, got {:?}", r),
        }
    }

    /// Samsung chain that omits the root — Acurast's verifier accepts this
    /// because the immediately-following intermediate is signed by a pinned
    /// trusted root.
    #[test]
    fn samsung_chain_without_root_verifies() {
        let entry = arm_entry(&[
            test_vectors::SAMSUNG_INTERMEDIATE_2_CERT,
            test_vectors::SAMSUNG_INTERMEDIATE_1_CERT,
            test_vectors::SAMSUNG_KEY_CERT,
        ]);
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Verified(_) => (),
            VerifyOutcome::Failed(r) => {
                panic!("Samsung-without-root chain should verify, got {:?}", r)
            }
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
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Failed(VerifyFailReason::ChainOfTrustBroken) => (),
            other => panic!(
                "Tampered Pixel chain should fail with ChainOfTrustBroken, got {:?}",
                other
            ),
        }
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
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Failed(VerifyFailReason::ChainOfTrustBroken) => (),
            other => panic!(
                "Untrusted root should fail with ChainOfTrustBroken, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn empty_chain_fails() {
        let payload = EvidencePayload::try_from(Vec::<Vec<u8>>::new().encode()).unwrap();
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::ArmTrustZone,
            payload,
        };
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed) => (),
            other => panic!(
                "Empty chain should fail with PayloadMalformed, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn malformed_payload_fails() {
        let payload = EvidencePayload::try_from(vec![0x00, 0x01, 0x02, 0x03]).unwrap();
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::ArmTrustZone,
            payload,
        };
        let outcome = verify_evidence(&fake_content_hash(), &entry);
        match outcome {
            VerifyOutcome::Failed(VerifyFailReason::PayloadMalformed) => (),
            other => panic!(
                "Malformed payload should fail with PayloadMalformed, got {:?}",
                other
            ),
        }
    }
}

// ---- Stub verifier tests ------------------------------------------------

mod stubs {
    use super::*;

    #[test]
    fn amd_sev_snp_returns_not_implemented() {
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::AmdSevSnp,
            payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
        };
        match verify_evidence(&fake_content_hash(), &entry) {
            VerifyOutcome::Failed(VerifyFailReason::NotImplemented) => (),
            other => panic!("Expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn intel_tdx_returns_not_implemented() {
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::IntelTdx,
            payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
        };
        match verify_evidence(&fake_content_hash(), &entry) {
            VerifyOutcome::Failed(VerifyFailReason::NotImplemented) => (),
            other => panic!("Expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn reproducible_build_returns_not_implemented() {
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::ReproducibleBuild,
            payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
        };
        match verify_evidence(&fake_content_hash(), &entry) {
            VerifyOutcome::Failed(VerifyFailReason::NotImplemented) => (),
            other => panic!("Expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn zkvm_execution_returns_not_implemented() {
        let entry = EvidenceEntry {
            evidence_type: EvidenceType::ZkVmExecution,
            payload: EvidencePayload::try_from(vec![0u8]).unwrap(),
        };
        match verify_evidence(&fake_content_hash(), &entry) {
            VerifyOutcome::Failed(VerifyFailReason::NotImplemented) => (),
            other => panic!("Expected NotImplemented, got {:?}", other),
        }
    }
}

// ---- Pallet integration tests -------------------------------------------

mod pallet {
    use super::*;
    use frame_support::{assert_noop, assert_ok};

    #[test]
    fn submit_evidence_pixel_chain_writes_storage_and_score() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            // Phase 2 kill-switch: enable the verifier via root before any
            // submit_evidence call. See `submit_evidence_when_disabled_fails`
            // for the genesis-default behaviour.
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            let id = receipt_id(1);
            let entry = arm_entry(&[
                test_vectors::PIXEL_ROOT_CERT,
                test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                test_vectors::PIXEL_KEY_CERT,
            ]);
            assert_ok!(TeeAttestation::submit_evidence(
                RuntimeOrigin::signed(1),
                id,
                fake_content_hash(),
                entry
            ));

            let score = TeeAttestation::trust_score(&id);
            assert_eq!(score, CompositeTrustScore::SINGLE_VENDOR);

            let entries = TeeAttestation::verified_entries(&id);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].evidence_type, EvidenceType::ArmTrustZone);
        });
    }

    #[test]
    fn submit_evidence_with_tampered_chain_fails_extrinsic() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            let id = receipt_id(2);
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
                crate::Error::<Test>::VerificationFailed
            );

            // Score remains at baseline.
            let score = TeeAttestation::trust_score(&id);
            assert_eq!(score, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
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
    fn stub_evidence_type_records_rejection_event() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            let id = receipt_id(4);
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
                crate::Error::<Test>::VerificationFailed
            );

            let score = TeeAttestation::trust_score(&id);
            assert_eq!(score, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
        });
    }

    /// H-2 hardening: the pallet MUST NOT keep a parallel `EvidenceEntries`
    /// storage map of raw evidence — `VerifiedEntries` is canonical. Submit
    /// 8 valid Pixel chains for the same receipt and assert that the only
    /// surviving per-receipt vector is `VerifiedEntries` (length 8). The
    /// raw-evidence storage map has been dropped.
    #[test]
    fn verified_entries_is_the_only_per_receipt_evidence_store() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            // Phase 2 ships the verifier disabled at genesis; tests of the
            // verify path must explicitly flip the kill switch first.
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            let id = receipt_id(8);
            for _ in 0..8 {
                let entry = arm_entry(&[
                    test_vectors::PIXEL_ROOT_CERT,
                    test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                    test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                    test_vectors::PIXEL_KEY_CERT,
                ]);
                assert_ok!(TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(1),
                    id,
                    fake_content_hash(),
                    entry,
                ));
            }
            let entries = TeeAttestation::verified_entries(&id);
            assert_eq!(entries.len(), 8);
        });
    }

    // ---- H-3 interim mitigation: genesis-disabled kill-switch ----

    /// Genesis: the pallet is disabled. submit_evidence with a valid Pixel
    /// chain must fail with PalletDisabled — the H-3 challenge-binding
    /// followup ships in Phase 2.5; until then the verifier accepts replays
    /// of any well-formed Google-rooted chain, so the kill-switch keeps the
    /// extrinsic dormant.
    #[test]
    fn submit_evidence_when_disabled_fails() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            let id = receipt_id(20);
            let entry = arm_entry(&[
                test_vectors::PIXEL_ROOT_CERT,
                test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                test_vectors::PIXEL_KEY_CERT,
            ]);
            assert_noop!(
                TeeAttestation::submit_evidence(
                    RuntimeOrigin::signed(1),
                    id,
                    fake_content_hash(),
                    entry,
                ),
                crate::Error::<Test>::PalletDisabled
            );
            // No state change.
            let score = TeeAttestation::trust_score(&id);
            assert_eq!(score, CompositeTrustScore::COMMITTEE_ATTESTED_BASELINE);
            let entries = TeeAttestation::verified_entries(&id);
            assert_eq!(entries.len(), 0);
        });
    }

    /// Sudo flips Disabled=false; submit_evidence with a valid Pixel chain
    /// then succeeds and writes VerifiedEntries.
    #[test]
    fn submit_evidence_after_enable_succeeds() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            assert_ok!(TeeAttestation::set_disabled(RuntimeOrigin::root(), false));
            let id = receipt_id(21);
            let entry = arm_entry(&[
                test_vectors::PIXEL_ROOT_CERT,
                test_vectors::PIXEL_INTERMEDIATE_2_CERT,
                test_vectors::PIXEL_INTERMEDIATE_1_CERT,
                test_vectors::PIXEL_KEY_CERT,
            ]);
            assert_ok!(TeeAttestation::submit_evidence(
                RuntimeOrigin::signed(1),
                id,
                fake_content_hash(),
                entry,
            ));
            let entries = TeeAttestation::verified_entries(&id);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].evidence_type, EvidenceType::ArmTrustZone);
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
