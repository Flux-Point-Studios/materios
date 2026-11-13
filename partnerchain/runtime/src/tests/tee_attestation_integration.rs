//! `pallet-tee-attestation` runtime-integration tests. Pin pallet indices
//! so a future drift produces a hard test failure rather than a silent
//! consumer-side bug.

use crate::*;

use frame_support::traits::PalletInfoAccess;
use parity_scale_codec::Encode;
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_sidechain::GenesisConfig::<Runtime> {
        genesis_utxo: sidechain_domain::UtxoId::new(
            hex_literal::hex!(
                "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
            ),
            0,
        ),
        slots_per_epoch: sidechain_slots::SlotsPerEpoch(7),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("sidechain genesis builds");

    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("scv genesis builds");

    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("pcs genesis builds");

    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("ntm genesis builds");

    storage.into()
}

#[test]
fn runtime_includes_tee_attestation_pallet() {
    new_test_ext().execute_with(|| {
        let name = <pallet_tee_attestation::Pallet<Runtime> as PalletInfoAccess>::name();
        assert_eq!(
            name, "TeeAttestation",
            "construct_runtime! must list pallet-tee-attestation as `TeeAttestation`",
        );
    });
}

// Pin every pallet index so accidental insertion or removal in the middle
// of `construct_runtime!` produces a hard failure here rather than
// silently breaking every metadata consumer.
//
// Layout: System=0..Balances=4, [5 vacant], Sudo=6..Utility=8,
//   Treasury=9..Motra=12, Sidechain=13..NativeTokenManagement=18,
//   IntentSettlement=19, TeeAttestation=20.

#[test]
fn existing_pallet_indices_unchanged() {
    new_test_ext().execute_with(|| {
        // Frame-system + tx-flow
        assert_eq!(
            <frame_system::Pallet<Runtime> as PalletInfoAccess>::index(),
            0,
            "System index drift",
        );
        assert_eq!(
            <pallet_timestamp::Pallet<Runtime> as PalletInfoAccess>::index(),
            1,
            "Timestamp index drift",
        );
        assert_eq!(
            <pallet_aura::Pallet<Runtime> as PalletInfoAccess>::index(),
            2,
            "Aura index drift",
        );
        assert_eq!(
            <pallet_grandpa::Pallet<Runtime> as PalletInfoAccess>::index(),
            3,
            "Grandpa index drift",
        );
        assert_eq!(
            <pallet_balances::Pallet<Runtime> as PalletInfoAccess>::index(),
            4,
            "Balances index drift",
        );
        // index 5 vacant
        assert_eq!(
            <pallet_sudo::Pallet<Runtime> as PalletInfoAccess>::index(),
            6,
            "Sudo index drift",
        );
        assert_eq!(
            <pallet_multisig::Pallet<Runtime> as PalletInfoAccess>::index(),
            7,
            "Multisig index drift",
        );
        assert_eq!(
            <pallet_utility::Pallet<Runtime> as PalletInfoAccess>::index(),
            8,
            "Utility index drift",
        );

        // v5.1 tokenomics
        assert_eq!(
            <pallet_treasury::Pallet<Runtime> as PalletInfoAccess>::index(),
            9,
            "Treasury index drift",
        );
        assert_eq!(
            <pallet_vesting::Pallet<Runtime> as PalletInfoAccess>::index(),
            10,
            "Vesting index drift",
        );
        assert_eq!(
            <pallet_orinq_receipts::Pallet<Runtime> as PalletInfoAccess>::index(),
            11,
            "OrinqReceipts index drift",
        );
        assert_eq!(
            <pallet_motra::Pallet<Runtime> as PalletInfoAccess>::index(),
            12,
            "Motra index drift",
        );

        // IOG partner-chains
        assert_eq!(
            <pallet_sidechain::Pallet<Runtime> as PalletInfoAccess>::index(),
            13,
            "Sidechain index drift",
        );
        assert_eq!(
            <pallet_session_validator_management::Pallet<Runtime> as PalletInfoAccess>::index(),
            14,
            "SessionCommitteeManagement index drift",
        );
        assert_eq!(
            <pallet_block_rewards::Pallet<Runtime> as PalletInfoAccess>::index(),
            15,
            "BlockRewards index drift",
        );
        assert_eq!(
            <pallet_session::Pallet<Runtime> as PalletInfoAccess>::index(),
            16,
            "PalletSession (stub) index drift",
        );
        assert_eq!(
            <pallet_partner_chains_session::Pallet<Runtime> as PalletInfoAccess>::index(),
            17,
            "Session (partner-chains) index drift",
        );
        assert_eq!(
            <pallet_native_token_management::Pallet<Runtime> as PalletInfoAccess>::index(),
            18,
            "NativeTokenManagement index drift",
        );

        // Wave 2 W2.2
        assert_eq!(
            <pallet_intent_settlement::Pallet<Runtime> as PalletInfoAccess>::index(),
            19,
            "IntentSettlement index drift",
        );
        assert_eq!(
            <pallet_tee_attestation::Pallet<Runtime> as PalletInfoAccess>::index(),
            20,
            "TeeAttestation must be appended (next available index = 20)",
        );
    });
}

#[test]
fn tee_attestation_disabled_at_genesis() {
    new_test_ext().execute_with(|| {
        let disabled = pallet_tee_attestation::Disabled::<Runtime>::get();
        assert!(
            disabled,
            "pallet-tee-attestation MUST be disabled at genesis (Phase 2 kill-switch)",
        );
    });
}

#[test]
fn runtime_dispatches_submit_evidence_returns_pallet_disabled() {
    use sp_runtime::traits::Dispatchable;

    new_test_ext().execute_with(|| {
        let alice = sp_keyring::Sr25519Keyring::Alice.to_account_id();
        // Kill-switch fires before the verifier reads bytes; payload is
        // irrelevant.
        let entry = pallet_tee_attestation::types::EvidenceEntry {
            evidence_type: pallet_tee_attestation::types::EvidenceType::ArmTrustZone,
            payload: frame_support::BoundedVec::default(),
        };

        let call = RuntimeCall::TeeAttestation(
            pallet_tee_attestation::Call::<Runtime>::submit_evidence {
                receipt_id: sp_core::H256::repeat_byte(0xAB),
                content_hash: [0u8; 32],
                entry,
            }
        );

        let res = call.dispatch(RuntimeOrigin::signed(alice));
        let err = res.expect_err("call must fail with kill-switch enabled");
        // PalletDisabled is the pallet's documented Phase 2 error.
        let expected: sp_runtime::DispatchError =
            pallet_tee_attestation::Error::<Runtime>::PalletDisabled.into();
        assert_eq!(err.error, expected);
    });
}

#[test]
fn runtime_dispatches_set_disabled_requires_root() {
    use sp_runtime::traits::Dispatchable;

    new_test_ext().execute_with(|| {
        let alice = sp_keyring::Sr25519Keyring::Alice.to_account_id();
        let signed_call = RuntimeCall::TeeAttestation(
            pallet_tee_attestation::Call::<Runtime>::set_disabled { disabled: false }
        );
        let res = signed_call.dispatch(RuntimeOrigin::signed(alice));
        let err = res.expect_err("set_disabled from signed origin must fail");
        assert_eq!(
            err.error,
            sp_runtime::DispatchError::BadOrigin,
            "set_disabled MUST be ensure_root — got {:?}", err.error,
        );

        let root_call = RuntimeCall::TeeAttestation(
            pallet_tee_attestation::Call::<Runtime>::set_disabled { disabled: false }
        );
        root_call
            .dispatch(RuntimeOrigin::root())
            .expect("set_disabled from root must succeed");
        assert!(
            !pallet_tee_attestation::Disabled::<Runtime>::get(),
            "Disabled must be `false` after Root flip",
        );
    });
}

// SCALE-encoding each event variant through `RuntimeEvent` is a
// compile-time check that every variant is wired into the aggregator,
// without coupling to the metadata schema version.

#[test]
fn runtime_metadata_exposes_tee_attestation_events_and_storage() {
    new_test_ext().execute_with(|| {
        let ev_verified = pallet_tee_attestation::Event::<Runtime>::EvidenceVerified {
            receipt_id: sp_core::H256::repeat_byte(0x01),
            evidence_type: pallet_tee_attestation::types::EvidenceType::ArmTrustZone,
            attest_key_hash: [0u8; 32],
            raw_level: 1,
            new_score: pallet_tee_attestation::types::CompositeTrustScore::SINGLE_VENDOR,
        };
        let agg_verified: RuntimeEvent = ev_verified.into();
        let _ = agg_verified.encode();

        let ev_rejected = pallet_tee_attestation::Event::<Runtime>::EvidenceRejected {
            receipt_id: sp_core::H256::repeat_byte(0x02),
            evidence_type: pallet_tee_attestation::types::EvidenceType::ArmTrustZone,
            reason: 0u8,
        };
        let agg_rejected: RuntimeEvent = ev_rejected.into();
        let _ = agg_rejected.encode();

        let ev_disabled = pallet_tee_attestation::Event::<Runtime>::DisabledChanged {
            disabled: false,
        };
        let agg_disabled: RuntimeEvent = ev_disabled.into();
        let _ = agg_disabled.encode();

        let _ = pallet_tee_attestation::Disabled::<Runtime>::get();
        let receipt_id = sp_core::H256::repeat_byte(0x03);
        let entries = pallet_tee_attestation::VerifiedEntries::<Runtime>::get(receipt_id);
        assert!(entries.is_empty(), "VerifiedEntries default must be empty");
        let score = pallet_tee_attestation::CompositeTrustScores::<Runtime>::get(receipt_id);
        assert_eq!(
            score,
            pallet_tee_attestation::types::CompositeTrustScore::default(),
            "CompositeTrustScores default must be the zero score",
        );
    });
}

/// Evidence binds to the content hash `OrinqReceipts` records for the
/// receipt, and to nothing for a receipt it does not hold; its submitter is
/// read from the same record.
#[test]
fn tee_attestation_reads_content_hashes_from_orinq_receipts() {
    use pallet_tee_attestation::ReceiptRegistry;
    type Receipts = <Runtime as pallet_tee_attestation::Config>::Receipts;

    new_test_ext().execute_with(|| {
        let recorded = sp_core::H256::repeat_byte(0x11);
        let content_hash = [0x22; 32];
        pallet_orinq_receipts::Receipts::<Runtime>::insert(
            recorded,
            pallet_orinq_receipts::types::ReceiptRecord {
                schema_hash: [0; 32],
                content_hash,
                base_root_sha256: [0; 32],
                zk_root_poseidon: None,
                poseidon_params_hash: None,
                base_manifest_hash: [0; 32],
                safety_manifest_hash: [0; 32],
                monitor_config_hash: [0; 32],
                attestation_evidence_hash: [0; 32],
                storage_locator_hash: [0; 32],
                availability_cert_hash: [0; 32],
                created_at_millis: 0,
                submitter: AccountId::from([0x33; 32]),
            },
        );

        assert_eq!(
            Receipts::receipt(&recorded),
            Some(pallet_tee_attestation::types::RegisteredReceipt {
                content_hash,
                submitter: AccountId::from([0x33; 32]),
            })
        );
        assert_eq!(Receipts::receipt(&sp_core::H256::repeat_byte(0x44)), None);
    });
}

/// Only the receipt's submitter and the receipt committee may attach
/// evidence: a stranger's `submit_evidence` is refused through real runtime
/// dispatch before any certificate is read, while the submitter's and a
/// committee member's reach the verifier.
#[test]
fn only_the_receipt_submitter_and_the_committee_attach_evidence() {
    use frame_support::traits::Contains;
    use sp_runtime::traits::Dispatchable;

    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let submitter = AccountId::from([0xA1; 32]);
        let member = AccountId::from([0xB2; 32]);
        let stranger = AccountId::from([0xC3; 32]);
        let receipt_id = sp_core::H256::repeat_byte(0xA1);
        let content_hash = [0xC0; 32];
        pallet_orinq_receipts::Receipts::<Runtime>::insert(
            receipt_id,
            pallet_orinq_receipts::types::ReceiptRecord {
                schema_hash: [0; 32],
                content_hash,
                base_root_sha256: [0; 32],
                zk_root_poseidon: None,
                poseidon_params_hash: None,
                base_manifest_hash: [0; 32],
                safety_manifest_hash: [0; 32],
                monitor_config_hash: [0; 32],
                attestation_evidence_hash: [0; 32],
                storage_locator_hash: [0; 32],
                availability_cert_hash: [0; 32],
                created_at_millis: 0,
                submitter: submitter.clone(),
            },
        );
        let mut committee = frame_support::BoundedBTreeSet::new();
        committee
            .try_insert(member.clone())
            .expect("committee bound");
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(committee);
        pallet_tee_attestation::Disabled::<Runtime>::put(false);

        let call = RuntimeCall::TeeAttestation(pallet_tee_attestation::Call::submit_evidence {
            receipt_id,
            content_hash,
            entry: pallet_tee_attestation::types::EvidenceEntry {
                evidence_type: pallet_tee_attestation::types::EvidenceType::ArmTrustZone,
                payload: vec![0x00, 0x01, 0x02, 0x03]
                    .try_into()
                    .expect("payload bound"),
            },
        });
        assert!(<Runtime as frame_system::Config>::BaseCallFilter::contains(
            &call
        ));
        let outcome = |who: &AccountId| {
            call.clone()
                .dispatch(RuntimeOrigin::signed(who.clone()))
                .map_err(|e| e.error)
        };
        assert_eq!(
            outcome(&stranger),
            Err(pallet_tee_attestation::Error::<Runtime>::UnauthorizedSubmitter.into())
        );
        for allowed in [&submitter, &member] {
            assert_eq!(
                outcome(allowed),
                Err(pallet_tee_attestation::Error::<Runtime>::VerificationFailed.into())
            );
        }
    });
}

/// The upgrade that ships receipt binding clears every evidence entry and
/// score recorded before it: none was bound to its receipt.
#[test]
fn the_runtime_upgrade_clears_evidence_recorded_before_binding() {
    use frame_support::traits::{GetStorageVersion, StorageVersion};
    use pallet_tee_attestation::types::{CompositeTrustScore, EvidenceType, VerifiedEvidence};

    let receipt_id = sp_core::H256::repeat_byte(0xAB);
    let mut ext = new_test_ext();
    ext.execute_with(|| {
        StorageVersion::new(0).put::<TeeAttestation>();
        let unbound = VerifiedEvidence {
            evidence_type: EvidenceType::ArmTrustZone,
            attest_key_hash: [0x58; 32],
            raw_level: 2,
        };
        pallet_tee_attestation::VerifiedEntries::<Runtime>::insert(
            receipt_id,
            frame_support::BoundedVec::try_from(vec![unbound; 8]).expect("eight entries"),
        );
        pallet_tee_attestation::CompositeTrustScores::<Runtime>::insert(
            receipt_id,
            CompositeTrustScore::SINGLE_VENDOR,
        );
    });
    ext.commit_all().expect("pre-binding storage committed");
    ext.execute_with(|| {
        Executive::execute_on_runtime_upgrade();

        assert_eq!(
            TeeAttestation::on_chain_storage_version(),
            StorageVersion::new(1)
        );
        assert!(
            pallet_tee_attestation::VerifiedEntries::<Runtime>::iter_keys()
                .next()
                .is_none()
        );
        assert!(
            pallet_tee_attestation::CompositeTrustScores::<Runtime>::iter_keys()
                .next()
                .is_none()
        );
    });
}

/// A chain built from genesis starts at the bound storage version, so the
/// upgrade's clearing never runs on it.
#[test]
fn a_new_chain_starts_at_the_bound_storage_version() {
    use frame_support::traits::{GetStorageVersion, OnGenesis, StorageVersion};

    new_test_ext().execute_with(|| {
        AllPalletsWithSystem::on_genesis();
        assert_eq!(
            TeeAttestation::on_chain_storage_version(),
            StorageVersion::new(1)
        );
    });
}

/// `submit_evidence`'s declared weight covers every committed Wasm sample of
/// the benchmark's worst-case chains (Seeker RKP, Google's RSA root five
/// times, its P-384 root five times), and its proof covers the measured proof
/// with the receipt committee at its bound.
#[test]
fn submit_evidence_weight_bounds_its_wasm_samples() {
    use frame_support::traits::Get;
    use serde_json::Value;

    let samples: Vec<Value> = serde_json::from_str(include_str!(
        "../../../pallets/tee-attestation/benchmarking/submit-evidence-samples.json"
    ))
    .expect("submit_evidence samples");
    let weight = pallet_tee_attestation::weights::submit_evidence::<Runtime>();
    let mut shapes = std::collections::BTreeSet::new();
    let (mut slowest, mut largest_proof) = (0u64, 0u64);
    for sample in &samples {
        assert_eq!(sample["benchmark"], "submit_evidence");
        for row in sample["time_results"]
            .as_array()
            .expect("timings")
            .iter()
            .chain(sample["db_results"].as_array().expect("db results"))
        {
            shapes.insert(row["components"][0][1].as_u64().expect("chain shape"));
            slowest = slowest.max(row["extrinsic_time"].as_u64().expect("time") * 1_000);
            largest_proof = largest_proof.max(row["proof_size"].as_u64().expect("proof size"));
        }
    }
    assert_eq!(shapes.into_iter().collect::<Vec<_>>(), vec![0, 1, 2]);
    assert!(
        weight.ref_time() >= slowest,
        "slowest sample {slowest} ps exceeds {weight:?}"
    );
    let committee_bound: u32 =
        <<Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize as Get<u32>>::get();
    let committee_growth = u64::from(committee_bound - 1) * 32;
    assert!(weight.proof_size() >= largest_proof + committee_growth);
}

/// Certificate validity is judged at the block timestamp `Timestamp` holds.
#[test]
fn tee_attestation_judges_certificates_at_the_block_timestamp() {
    use frame_support::traits::UnixTime;
    type Clock = <Runtime as pallet_tee_attestation::Config>::UnixTime;

    new_test_ext().execute_with(|| {
        pallet_timestamp::Now::<Runtime>::put(1_756_684_800_123);
        assert_eq!(Clock::now().as_secs(), 1_756_684_800);
    });
}
