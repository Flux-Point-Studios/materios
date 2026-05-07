//! Wave 3 / Phase 2 — `pallet-tee-attestation` runtime-integration tests.
//!
//! Verifies the wiring of `pallet-tee-attestation` (PR #17) into the
//! Materios runtime's `construct_runtime!` macro, its `Config` impl, and
//! confirms that the genesis kill-switch (`Disabled = true`) is honored.
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT
//! ---------------------------------------------------------------------------
//!
//! These tests are written BEFORE `pallet-tee-attestation` is wired into the
//! runtime. They will fail to compile until:
//!   1. `pallet-tee-attestation` is added to `runtime/Cargo.toml`.
//!   2. `impl pallet_tee_attestation::Config for Runtime` is added in lib.rs.
//!   3. `TeeAttestation: pallet_tee_attestation = N,` is appended to the END
//!      of `construct_runtime!` (per `feedback_pallet_index_shift.md`).
//!
//! ---------------------------------------------------------------------------
//! Pallet-index regression protection
//! ---------------------------------------------------------------------------
//!
//! `feedback_pallet_index_shift.md` is explicit: pallet indices are
//! load-bearing. Inserting OR removing a pallet in the middle of the macro
//! shifts every subsequent index by ±1, silently invalidating every
//! consumer of the runtime metadata (explorers, wallets, SDK type
//! generators). This file pins the index of every PRE-PR pallet so a
//! future drift produces a hard test failure rather than a silent bug.

use crate::*;

use frame_support::traits::PalletInfoAccess;
use parity_scale_codec::Encode;
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

// ---------------------------------------------------------------------------
// Externalities builder — minimal genesis sufficient for storage reads /
// dispatchable smoke tests on the new pallet. Mirrors the shape used in
// `treasury_integration.rs` so the two stay in sync if more pallets are
// added.
// ---------------------------------------------------------------------------

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    // IOG pallets: minimum genesis so AllPalletsWithSystem hooks don't
    // panic on default-zero data.
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

// ---------------------------------------------------------------------------
// Test 1 — runtime constructs cleanly with `TeeAttestation` listed
// ---------------------------------------------------------------------------
//
// Compiles only if `TeeAttestation: pallet_tee_attestation` is in
// construct_runtime! AND the `pallet_tee_attestation::Config for Runtime`
// impl exists. The runtime metadata MUST enumerate "TeeAttestation" as a
// pallet — `PalletInfoAccess::name()` is the canonical way to assert that.

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

// ---------------------------------------------------------------------------
// Test 2 — pallet-index regression protection
// ---------------------------------------------------------------------------
//
// Per `feedback_pallet_index_shift.md`: pallet indices are load-bearing.
// This test pins the index of every PRE-PR pallet to the value it was
// assigned before this PR landed, so an accidental insertion in the
// middle of construct_runtime! produces a hard failure here rather than
// silently breaking every metadata consumer.
//
// Pre-existing pallet indices (from main pre-PR):
//   System=0, Timestamp=1, Aura=2, Grandpa=3, Balances=4,
//   [5 reserved — was pallet_transaction_payment, removed at spec 202],
//   Sudo=6, Multisig=7, Utility=8, Treasury=9, Vesting=10,
//   OrinqReceipts=11, Motra=12, Sidechain=13,
//   SessionCommitteeManagement=14, BlockRewards=15, PalletSession=16,
//   Session=17, NativeTokenManagement=18, IntentSettlement=19.
// New pallet:
//   TeeAttestation=20  (next available index, appended at the END).

#[test]
fn existing_pallet_indices_unchanged() {
    new_test_ext().execute_with(|| {
        // Frame-system + tx-flow pallets
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
        // Index 5 deliberately vacant (was pallet_transaction_payment).
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

        // The new pallet — appended at the END of construct_runtime!.
        assert_eq!(
            <pallet_tee_attestation::Pallet<Runtime> as PalletInfoAccess>::index(),
            20,
            "TeeAttestation must be appended (next available index = 20)",
        );
    });
}

// ---------------------------------------------------------------------------
// Test 3 — `Disabled` is `true` at genesis
// ---------------------------------------------------------------------------
//
// Phase 2 ships with the kill-switch ON. Per the pallet's lib.rs docstring
// and `DefaultDisabled<T>` type-value, the `Disabled` storage value MUST
// read `true` from a fresh genesis. Phase 2.5 governance flips this via
// `set_disabled` once challenge-binding ships (security review H-3).

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

// ---------------------------------------------------------------------------
// Test 4 — `submit_evidence` and `set_disabled` route through the runtime
// ---------------------------------------------------------------------------
//
// Confirms the dispatchables are correctly aggregated into `RuntimeCall`.
// At genesis (Disabled=true), `submit_evidence` MUST fail with the pallet's
// `PalletDisabled` error — proves the call is correctly routed AND that
// the kill-switch actually short-circuits execution.

#[test]
fn runtime_dispatches_submit_evidence_returns_pallet_disabled() {
    use frame_support::dispatch::Dispatchable;

    new_test_ext().execute_with(|| {
        let alice = sp_keyring::Sr25519Keyring::Alice.to_account_id();
        // Empty payload — the kill-switch fires BEFORE the verifier reads
        // the bytes, so payload contents are irrelevant for this test.
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
    use frame_support::dispatch::Dispatchable;

    new_test_ext().execute_with(|| {
        // Non-root signer must be rejected with BadOrigin.
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

        // Root succeeds + actually flips the storage value.
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

// ---------------------------------------------------------------------------
// Test 5 — runtime metadata exposes the pallet's events
// ---------------------------------------------------------------------------
//
// `PR #17` ships three event variants: `EvidenceVerified`, `EvidenceRejected`,
// `DisabledChanged`. They MUST be reachable via the runtime's `RuntimeEvent`
// aggregator. We verify by SCALE-encoding each variant through the
// aggregator — the aggregator's `Encode` impl only succeeds if the variant
// is wired in, so this is a compile-time guarantee with a dynamic check on
// top.
//
// This is the cheapest reliable surface; a full `frame_metadata::v15`
// walk would couple the test to the metadata schema version (which varies
// across polkadot-sdk releases) for no additional safety beyond what the
// `RuntimeEvent::from(Event::*)` call already gives us.

#[test]
fn runtime_metadata_exposes_tee_attestation_events_and_storage() {
    new_test_ext().execute_with(|| {
        // -- Events: each variant must round-trip through the aggregator. --
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

        // -- Storage: every documented map must be reachable on the runtime. --
        // ValueQuery defaults exercise the storage prefix without needing to
        // mutate state.
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
