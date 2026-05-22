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
