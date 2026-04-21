//! SPO cross-validation integration tests.
//!
//! This file exercises the integration of six IOG Partner Chains pallets into
//! the Materios runtime:
//!
//!   1. pallet_sidechain           -- partner chain identity (genesis UTXO, epoch tracking)
//!   2. pallet_session_validator_management -- SPO committee selection
//!   3. pallet_session             -- Substrate session rotation (stub config)
//!   4. pallet_partner_chains_session -- partner chain session extension
//!   5. pallet_block_rewards       -- SPO block rewards accumulation
//!   6. pallet_native_token_management -- cross-chain native token movement
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT
//! ---------------------------------------------------------------------------
//!
//! These tests are written BEFORE the pallets are wired into the runtime.
//! They will fail to compile until the following steps are completed:
//!
//! 1. Add the six IOG pallet crates (and their transitive dependencies:
//!    `sidechain_domain`, `sidechain_slots`, `sp_sidechain`, `sp_block_rewards`,
//!    `sp_native_token_management`, `sp_session_validator_management`,
//!    `authority_selection_inherents`, `session_manager`,
//!    `pallet_session_runtime_stub`) to `runtime/Cargo.toml`.
//!
//! 2. Implement `Config` for each pallet in `runtime/src/lib.rs`:
//!    - `pallet_sidechain::Config`
//!    - `pallet_session_validator_management::Config`
//!    - `pallet_partner_chains_session::Config`
//!    - `pallet_session::Config` (via `pallet_session_runtime_stub::impl_pallet_session_config!`)
//!    - `pallet_block_rewards::Config`
//!    - `pallet_native_token_management::Config`
//!
//! 3. Add the six pallets to `construct_runtime!`:
//!    ```ignore
//!    Sidechain: pallet_sidechain,
//!    SessionCommitteeManagement: pallet_session_validator_management,
//!    BlockRewards: pallet_block_rewards,
//!    PalletSession: pallet_session,
//!    Session: pallet_partner_chains_session,
//!    NativeTokenManagement: pallet_native_token_management,
//!    ```
//!
//! 4. Define the `BeneficiaryId` type alias and `TokenTransferHandler` impl.
//!
//! 5. Run `cargo test -p materios-runtime` -- all tests should pass.
//! ---------------------------------------------------------------------------

use crate::*;

use frame_support::{
    assert_ok,
    traits::{OnFinalize, OnInitialize},
};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

// ============================================================================
// Section 1 -- Test externalities builder
// ============================================================================

/// Build a `TestExternalities` with a complete genesis for every pallet in the
/// runtime.  If any of the six new IOG pallets are missing from
/// `construct_runtime!`, the genesis config struct will be missing the
/// corresponding field and compilation will fail.
fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    // --- Balances: give Alice and Bob some funds ---
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (account_id_alice(), 10_000_000),
            (account_id_bob(), 10_000_000),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");

    // --- pallet_sidechain ---
    // Requires the pallet in construct_runtime! and Config implemented.
    pallet_sidechain::GenesisConfig::<Runtime> {
        genesis_utxo: test_genesis_utxo(),
        slots_per_epoch: sidechain_slots::SlotsPerEpoch(SLOTS_PER_EPOCH),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("sidechain genesis builds");

    // --- pallet_session_validator_management ---
    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("session_validator_management genesis builds");

    // --- pallet_partner_chains_session ---
    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("partner_chains_session genesis builds");

    // --- pallet_native_token_management ---
    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("native_token_management genesis builds");

    // pallet_block_rewards and pallet_session (stub) have no genesis config.

    storage.into()
}

// ============================================================================
// Section 2 -- Helper constants and utilities
// ============================================================================

/// Slots per sidechain epoch, matching the IOG mock pattern.
const SLOTS_PER_EPOCH: u32 = 7;

/// Deterministic genesis UTXO for tests (same as IOG mock.rs).
fn test_genesis_utxo() -> sidechain_domain::UtxoId {
    sidechain_domain::UtxoId::new(
        hex_literal::hex!(
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        ),
        0,
    )
}

/// Alice AccountId using the sr25519 keyring.
fn account_id_alice() -> AccountId {
    sp_keyring::Sr25519Keyring::Alice.to_account_id()
}

/// Bob AccountId using the sr25519 keyring.
fn account_id_bob() -> AccountId {
    sp_keyring::Sr25519Keyring::Bob.to_account_id()
}

/// Create a deterministic 32-byte beneficiary ID for block reward tests.
///
/// The `BeneficiaryId` type is expected to be
/// `sidechain_domain::byte_string::SizedByteString<32>`, matching the IOG
/// runtime pattern.
fn test_beneficiary_id() -> BeneficiaryId {
    sidechain_domain::byte_string::SizedByteString([0xAAu8; 32])
}

/// Advance the runtime through `on_initialize` / `on_finalize` hooks up to
/// block number `n`.
fn run_to_block(n: BlockNumber) {
    while System::block_number() < n {
        let current = System::block_number();
        // Set timestamp so pallet_timestamp::on_finalize does not panic.
        // Timestamp of 0 maps to slot 0 which is the initial CurrentSlot.
        let _ = pallet_timestamp::Pallet::<Runtime>::set(
            RuntimeOrigin::none(),
            current as u64 * MILLISECS_PER_BLOCK,
        );
        // block_rewards requires CurrentBlockBeneficiary to be set before on_finalize.
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(test_beneficiary_id());
        // Finalize current
        AllPalletsWithSystem::on_finalize(current);
        System::on_finalize(current);

        // Next block
        let next = current + 1;
        System::reset_events();
        System::set_block_number(next);
        System::on_initialize(next);
        AllPalletsWithSystem::on_initialize(next);
    }
}

// ============================================================================
// Section 3 -- Pallet existence tests
// ============================================================================
//
// Each test below accesses a type or storage item that only exists if the
// pallet has been added to `construct_runtime!` AND has its `Config`
// implemented.  Missing pallets cause compile errors.

#[test]
fn pallet_sidechain_exists_in_runtime() {
    new_test_ext().execute_with(|| {
        let utxo = pallet_sidechain::Pallet::<Runtime>::genesis_utxo();
        assert_eq!(utxo, test_genesis_utxo());
    });
}

#[test]
fn pallet_session_validator_management_exists_in_runtime() {
    new_test_ext().execute_with(|| {
        let committee_info =
            pallet_session_validator_management::Pallet::<Runtime>::current_committee_storage();
        // Empty initial_authorities genesis means committee vec is empty.
        assert!(committee_info.committee.is_empty());
    });
}

#[test]
fn pallet_session_stub_exists_in_runtime() {
    // The pallet_session (stub) must be present so Grandpa can read
    // pallet_session::pallet::CurrentIndex.
    new_test_ext().execute_with(|| {
        let idx = pallet_session::Pallet::<Runtime>::current_index();
        assert_eq!(idx, 0);
    });
}

#[test]
fn pallet_partner_chains_session_exists_in_runtime() {
    new_test_ext().execute_with(|| {
        let idx = pallet_partner_chains_session::Pallet::<Runtime>::current_index();
        assert_eq!(idx, 0);
    });
}

#[test]
fn pallet_block_rewards_exists_in_runtime() {
    new_test_ext().execute_with(|| {
        let rewards = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert!(rewards.is_empty());
    });
}

#[test]
fn pallet_native_token_management_exists_in_runtime() {
    new_test_ext().execute_with(|| {
        let scripts = pallet_native_token_management::Pallet::<Runtime>::get_main_chain_scripts();
        assert!(scripts.is_some(), "Main chain scripts should be set at genesis");
    });
}

// ============================================================================
// Section 4 -- Sidechain genesis configuration tests
// ============================================================================

#[test]
fn sidechain_genesis_utxo_is_stored() {
    new_test_ext().execute_with(|| {
        let utxo = pallet_sidechain::Pallet::<Runtime>::genesis_utxo();
        assert_eq!(utxo, test_genesis_utxo());
    });
}

#[test]
fn sidechain_slots_per_epoch_is_stored() {
    new_test_ext().execute_with(|| {
        let spe = pallet_sidechain::Pallet::<Runtime>::slots_per_epoch();
        assert_eq!(spe.0, SLOTS_PER_EPOCH);
    });
}

#[test]
fn sidechain_epoch_number_derivation_at_genesis() {
    new_test_ext().execute_with(|| {
        // At genesis (slot 0) the epoch number should be 0.
        let epoch = pallet_sidechain::Pallet::<Runtime>::current_epoch_number();
        assert_eq!(epoch.0, 0);
    });
}

// ============================================================================
// Section 5 -- Session rotation and committee tests
// ============================================================================

#[test]
fn validator_management_initial_committee_is_empty() {
    new_test_ext().execute_with(|| {
        let (epoch, committee) =
            pallet_session_validator_management::Pallet::<Runtime>::get_current_committee();
        assert!(committee.is_empty());
        assert_eq!(Into::<u64>::into(epoch), 0u64);
    });
}

#[test]
fn session_index_starts_at_zero() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            pallet_partner_chains_session::Pallet::<Runtime>::current_index(),
            0
        );
    });
}

#[test]
fn next_committee_is_none_before_first_inherent() {
    new_test_ext().execute_with(|| {
        let next =
            pallet_session_validator_management::Pallet::<Runtime>::next_committee_storage();
        assert!(next.is_none());
    });
}

#[test]
fn should_end_session_returns_false_when_no_next_committee() {
    // ValidatorManagementSessionManager::should_end_session requires:
    //   a) current epoch > stored committee epoch, AND
    //   b) next_committee is Some.
    // With no next committee it should return false.
    new_test_ext().execute_with(|| {
        use pallet_partner_chains_session::ShouldEndSession;
        let result =
            session_manager::ValidatorManagementSessionManager::<Runtime>::should_end_session(
                1u32,
            );
        assert!(!result);
    });
}

#[test]
fn get_next_unset_epoch_number_is_one_at_genesis() {
    // With no next committee stored, the next unset epoch should be
    // current committee epoch + 1.
    new_test_ext().execute_with(|| {
        let next_epoch =
            pallet_session_validator_management::Pallet::<Runtime>::get_next_unset_epoch_number();
        // Initial epoch is 0, so next unset is 1.
        let val: u64 = next_epoch.into();
        assert_eq!(val, 1);
    });
}

// ============================================================================
// Section 6 -- Block rewards tests
// ============================================================================

#[test]
fn block_rewards_pending_is_empty_at_genesis() {
    new_test_ext().execute_with(|| {
        let rewards = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert!(rewards.is_empty());
    });
}

#[test]
fn block_rewards_beneficiary_can_be_set_via_inherent_call() {
    use frame_support::traits::UnfilteredDispatchable;

    new_test_ext().execute_with(|| {
        let beneficiary = test_beneficiary_id();

        let call = pallet_block_rewards::Call::<Runtime>::set_current_block_beneficiary {
            beneficiary: beneficiary.clone(),
        };

        // Inherent calls use Origin::none().
        assert_ok!(call.dispatch_bypass_filter(RuntimeOrigin::none()));

        let stored = pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::get();
        assert_eq!(stored, Some(beneficiary));
    });
}

#[test]
fn block_rewards_on_finalize_accumulates_reward() {
    new_test_ext().execute_with(|| {
        let beneficiary = test_beneficiary_id();
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary.clone());

        pallet_block_rewards::Pallet::<Runtime>::on_finalize(1u32);

        let rewards = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert_eq!(rewards.len(), 1);
        let (id, points) = &rewards[0];
        assert_eq!(id, &beneficiary);
        // SimpleBlockCount awards 1 point per block.
        assert_eq!(*points, 1u32);
    });
}

#[test]
fn block_rewards_accumulate_across_multiple_blocks() {
    new_test_ext().execute_with(|| {
        let beneficiary = test_beneficiary_id();

        for block_num in 1..=3u32 {
            pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary.clone());
            pallet_block_rewards::Pallet::<Runtime>::on_finalize(block_num);
        }

        let rewards = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert_eq!(rewards.len(), 1);
        let (_id, points) = &rewards[0];
        assert_eq!(*points, 3u32);
    });
}

#[test]
fn block_rewards_separate_beneficiaries_tracked_independently() {
    new_test_ext().execute_with(|| {
        let beneficiary_a = sidechain_domain::byte_string::SizedByteString([0xAAu8; 32]);
        let beneficiary_b = sidechain_domain::byte_string::SizedByteString([0xBBu8; 32]);

        // Block 1: beneficiary A
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary_a.clone());
        pallet_block_rewards::Pallet::<Runtime>::on_finalize(1u32);

        // Block 2: beneficiary B
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary_b.clone());
        pallet_block_rewards::Pallet::<Runtime>::on_finalize(2u32);

        // Block 3: beneficiary A again
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary_a.clone());
        pallet_block_rewards::Pallet::<Runtime>::on_finalize(3u32);

        let rewards = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert_eq!(rewards.len(), 2);

        let find_pts = |target: &BeneficiaryId| -> u32 {
            rewards.iter().find(|(id, _)| id == target).map(|(_, pts)| *pts).unwrap()
        };
        assert_eq!(find_pts(&beneficiary_a), 2u32);
        assert_eq!(find_pts(&beneficiary_b), 1u32);
    });
}

#[test]
fn block_rewards_get_rewards_and_clear_drains_storage() {
    new_test_ext().execute_with(|| {
        let beneficiary = test_beneficiary_id();
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(beneficiary.clone());
        pallet_block_rewards::Pallet::<Runtime>::on_finalize(1u32);

        // First drain returns data.
        let first = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert_eq!(first.len(), 1);

        // Second drain returns empty.
        let second = pallet_block_rewards::Pallet::<Runtime>::get_rewards_and_clear();
        assert!(second.is_empty());
    });
}

// ============================================================================
// Section 7 -- Native token management tests
// ============================================================================

#[test]
fn native_token_management_is_not_initialized_at_genesis() {
    new_test_ext().execute_with(|| {
        assert!(!pallet_native_token_management::Pallet::<Runtime>::initialized());
    });
}

#[test]
fn native_token_management_main_chain_scripts_stored_at_genesis() {
    new_test_ext().execute_with(|| {
        let scripts = pallet_native_token_management::Pallet::<Runtime>::get_main_chain_scripts();
        assert!(scripts.is_some(), "Main chain scripts should be set by genesis config");
    });
}

#[test]
fn native_token_transfer_sets_initialized_flag() {
    use frame_support::traits::UnfilteredDispatchable;

    new_test_ext().execute_with(|| {
        assert!(!pallet_native_token_management::Pallet::<Runtime>::initialized());

        let call = pallet_native_token_management::Call::<Runtime>::transfer_tokens {
            token_amount: sidechain_domain::NativeTokenAmount(1_000),
        };
        assert_ok!(call.dispatch_bypass_filter(RuntimeOrigin::none()));
        assert!(pallet_native_token_management::Pallet::<Runtime>::initialized());
    });
}

#[test]
fn native_token_transfer_fails_from_signed_origin() {
    use frame_support::traits::UnfilteredDispatchable;

    new_test_ext().execute_with(|| {
        let call = pallet_native_token_management::Call::<Runtime>::transfer_tokens {
            token_amount: sidechain_domain::NativeTokenAmount(500),
        };
        let result = call.dispatch_bypass_filter(RuntimeOrigin::signed(account_id_alice()));
        assert!(result.is_err(), "transfer_tokens must be Origin::none() (inherent only)");
    });
}

#[test]
fn native_token_set_main_chain_scripts_requires_root() {
    use frame_support::traits::UnfilteredDispatchable;

    new_test_ext().execute_with(|| {
        let call = pallet_native_token_management::Call::<Runtime>::set_main_chain_scripts {
            native_token_policy_id: sidechain_domain::PolicyId([0u8; 28]),
            native_token_asset_name: sidechain_domain::AssetName(
                frame_support::BoundedVec::try_from(Vec::new()).unwrap(),
            ),
            illiquid_supply_validator_address: "".parse::<sidechain_domain::MainchainAddress>().unwrap(),
        };

        // Signed origin should fail.
        let signed_result =
            call.dispatch_bypass_filter(RuntimeOrigin::signed(account_id_alice()));
        assert!(signed_result.is_err(), "set_main_chain_scripts must require root");
    });
}

// ============================================================================
// Section 8 -- Existing Materios pallet compatibility tests
// ============================================================================
//
// Adding the IOG pallets must not break Motra or OrinqReceipts.

#[test]
fn motra_pallet_still_accessible_after_integration() {
    new_test_ext().execute_with(|| {
        let total_issued = pallet_motra::TotalIssued::<Runtime>::get();
        assert_eq!(total_issued, 0);
    });
}

#[test]
fn orinq_receipts_pallet_still_accessible_after_integration() {
    new_test_ext().execute_with(|| {
        let count = pallet_orinq_receipts::ReceiptCount::<Runtime>::get();
        assert_eq!(count, 0);
    });
}

#[test]
fn balances_pallet_works_with_new_pallets() {
    new_test_ext().execute_with(|| {
        let free = pallet_balances::Pallet::<Runtime>::free_balance(&account_id_alice());
        assert_eq!(free, 10_000_000);
    });
}

#[test]
fn system_pallet_still_functional_after_integration() {
    new_test_ext().execute_with(|| {
        assert_eq!(System::block_number(), 0);
        run_to_block(1);
        assert_eq!(System::block_number(), 1);
    });
}

// ============================================================================
// Section 9 -- RuntimeGenesisConfig completeness test
// ============================================================================

#[test]
fn runtime_genesis_config_includes_all_iog_pallet_fields() {
    // Constructing RuntimeGenesisConfig with all fields proves that
    // construct_runtime! generated them.  Missing pallets cause a
    // compile-time error: "no field named `sidechain`".
    let _config = RuntimeGenesisConfig {
        system: Default::default(),
        balances: Default::default(),
        aura: Default::default(),
        grandpa: Default::default(),
        sudo: Default::default(),
        // transaction_payment field removed at spec 202 alongside the pallet.
        // Existing Materios pallets
        motra: Default::default(),
        // IOG pallets with genesis configs
        sidechain: pallet_sidechain::GenesisConfig {
            genesis_utxo: test_genesis_utxo(),
            slots_per_epoch: sidechain_slots::SlotsPerEpoch(SLOTS_PER_EPOCH),
            ..Default::default()
        },
        session_committee_management: pallet_session_validator_management::GenesisConfig {
            initial_authorities: Vec::new(),
            main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
        },
        session: pallet_partner_chains_session::GenesisConfig {
            initial_validators: Vec::new(),
        },
        native_token_management: pallet_native_token_management::GenesisConfig {
            main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
            ..Default::default()
        },
        // block_rewards and pallet_session (stub) have no genesis config
        ..Default::default()
    };
}

// ============================================================================
// Section 10 -- Type instantiation tests
// ============================================================================
//
// Proves that the pallet generic parameters resolve with the Runtime type.

#[test]
fn pallet_types_are_instantiable_with_runtime() {
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_sidechain::Pallet<Runtime>>()
    };
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_session_validator_management::Pallet<Runtime>>()
    };
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_partner_chains_session::Pallet<Runtime>>()
    };
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_block_rewards::Pallet<Runtime>>()
    };
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_native_token_management::Pallet<Runtime>>()
    };
    let _: fn() -> &'static str = || {
        core::any::type_name::<pallet_session::Pallet<Runtime>>()
    };
}

// ============================================================================
// Section 11 -- PalletInfo name tests
// ============================================================================

#[test]
fn pallet_info_has_correct_names() {
    use frame_support::traits::PalletInfoAccess;

    new_test_ext().execute_with(|| {
        assert_eq!(
            <pallet_sidechain::Pallet<Runtime> as PalletInfoAccess>::name(),
            "Sidechain"
        );
        assert_eq!(
            <pallet_session_validator_management::Pallet<Runtime> as PalletInfoAccess>::name(),
            "SessionCommitteeManagement"
        );
        assert_eq!(
            <pallet_block_rewards::Pallet<Runtime> as PalletInfoAccess>::name(),
            "BlockRewards"
        );
        assert_eq!(
            <pallet_partner_chains_session::Pallet<Runtime> as PalletInfoAccess>::name(),
            "Session"
        );
        assert_eq!(
            <pallet_native_token_management::Pallet<Runtime> as PalletInfoAccess>::name(),
            "NativeTokenManagement"
        );
    });
}

// ============================================================================
// Section 12 -- Pallet ordering tests
// ============================================================================
//
// IOG requires specific ordering in construct_runtime!:
//   - Sidechain AFTER Aura (reads CurrentSlot)
//   - PalletSession (stub) BEFORE pallet_partner_chains_session
//   - pallet_partner_chains_session LAST for correct init ordering

#[test]
fn pallet_ordering_sidechain_after_aura() {
    use frame_support::traits::PalletInfoAccess;

    new_test_ext().execute_with(|| {
        let aura_idx = <pallet_aura::Pallet<Runtime> as PalletInfoAccess>::index();
        let sidechain_idx =
            <pallet_sidechain::Pallet<Runtime> as PalletInfoAccess>::index();
        assert!(
            sidechain_idx > aura_idx,
            "Sidechain (idx={sidechain_idx}) must come after Aura (idx={aura_idx})"
        );
    });
}

#[test]
fn pallet_ordering_partner_session_after_stub_session() {
    use frame_support::traits::PalletInfoAccess;

    new_test_ext().execute_with(|| {
        let stub_idx =
            <pallet_session::Pallet<Runtime> as PalletInfoAccess>::index();
        let partner_idx =
            <pallet_partner_chains_session::Pallet<Runtime> as PalletInfoAccess>::index();
        assert!(
            partner_idx > stub_idx,
            "pallet_partner_chains_session (idx={partner_idx}) must come \
             after pallet_session stub (idx={stub_idx})"
        );
    });
}

// ============================================================================
// Section 13 -- SessionKeys compatibility test
// ============================================================================

#[test]
fn session_keys_contain_aura_and_grandpa() {
    use sp_runtime::traits::OpaqueKeys;

    let key_ids = opaque::SessionKeys::key_ids();
    assert!(
        key_ids.contains(&sp_core::crypto::KeyTypeId(sp_consensus_aura::AURA_ENGINE_ID)),
        "SessionKeys must include Aura"
    );
    assert!(
        key_ids.contains(&sp_core::crypto::KeyTypeId(*b"gran")),
        "SessionKeys must include Grandpa"
    );
}

// ============================================================================
// Section 14 -- Epoch transition smoke test
// ============================================================================

#[test]
fn sidechain_on_initialize_sets_epoch_tracker() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        pallet_sidechain::Pallet::<Runtime>::on_initialize(1u32);
        // Reading the epoch number should not panic; the tracker is now set.
        let _epoch = pallet_sidechain::Pallet::<Runtime>::current_epoch_number();
    });
}

// ============================================================================
// Section 15 -- Cross-chain public key type test
// ============================================================================
//
// The runtime defines `CrossChainPublic` from the opaque module.  Verify it
// is usable as the AuthorityId for session_validator_management.

#[test]
fn cross_chain_public_type_is_defined() {
    // This compiles only if `CrossChainPublic` (ecdsa-based app key) is
    // correctly defined in the runtime's opaque module.
    let _: fn() -> &'static str = || {
        core::any::type_name::<CrossChainPublic>()
    };
}

// ============================================================================
// Section 16 -- ValidatorManagementSessionManager wiring test
// ============================================================================

#[test]
fn validator_management_session_manager_is_usable() {
    // This test ensures that `session_manager::ValidatorManagementSessionManager<Runtime>`
    // implements `ShouldEndSession` for the runtime -- i.e., the pallet Config
    // bounds are satisfied.
    new_test_ext().execute_with(|| {
        use pallet_partner_chains_session::ShouldEndSession;
        // At genesis with no next committee, should_end_session is false.
        let should_end =
            session_manager::ValidatorManagementSessionManager::<Runtime>::should_end_session(
                0u32,
            );
        assert!(!should_end);
    });
}

// ============================================================================
// Section 17 -- Main-chain scripts configuration tests
// ============================================================================

#[test]
fn session_validator_management_main_chain_scripts_stored() {
    new_test_ext().execute_with(|| {
        let scripts =
            pallet_session_validator_management::Pallet::<Runtime>::get_main_chain_scripts();
        // Default MainChainScripts is stored at genesis.
        // Verify the storage item is accessible (non-panic).
        let _ = scripts;
    });
}

// ============================================================================
// Section 18 -- Token transfer handler integration test
// ============================================================================

#[test]
fn token_transfer_handler_is_wired() {
    // The runtime must define a `TokenTransferHandler` impl and wire it into
    // pallet_native_token_management::Config.  This test invokes the inherent
    // and checks that it does not panic.
    use frame_support::traits::UnfilteredDispatchable;

    new_test_ext().execute_with(|| {
        let call = pallet_native_token_management::Call::<Runtime>::transfer_tokens {
            token_amount: sidechain_domain::NativeTokenAmount(42),
        };
        // This will call TokenTransferHandler::handle_token_transfer internally.
        assert_ok!(call.dispatch_bypass_filter(RuntimeOrigin::none()));
    });
}

// ============================================================================
// Section 19 -- Block rewards inherent creation test
// ============================================================================

#[test]
fn block_rewards_create_inherent_from_inherent_data() {
    use frame_support::pallet_prelude::{InherentData, ProvideInherent};

    new_test_ext().execute_with(|| {
        let mut inherent_data = InherentData::new();
        let beneficiary = test_beneficiary_id();
        inherent_data
            .put_data(sp_block_rewards::INHERENT_IDENTIFIER, &beneficiary)
            .unwrap();

        let inherent = pallet_block_rewards::Pallet::<Runtime>::create_inherent(&inherent_data);
        assert!(inherent.is_some(), "Inherent should be created from valid data");

        let call = inherent.unwrap();
        match call {
            pallet_block_rewards::Call::set_current_block_beneficiary { beneficiary: b } => {
                assert_eq!(b, beneficiary);
            }
            _ => panic!("Unexpected call variant"),
        }
    });
}

// ============================================================================
// Section 20 -- AllPalletsWithSystem includes new pallets
// ============================================================================
//
// Running on_initialize / on_finalize with AllPalletsWithSystem should not
// panic when the new pallets are included.

#[test]
fn all_pallets_hooks_run_without_panic() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        // This exercises on_initialize for EVERY pallet in AllPalletsWithSystem,
        // including the six new IOG pallets.
        AllPalletsWithSystem::on_initialize(1u32);

        // Set timestamp to 0 so it maps to slot 0, matching the initial CurrentSlot.
        // pallet_timestamp::on_finalize requires the timestamp to have been set.
        let _ = pallet_timestamp::Pallet::<Runtime>::set(RuntimeOrigin::none(), 0);

        // block_rewards requires CurrentBlockBeneficiary to be set before
        // on_finalize, so we set it.
        pallet_block_rewards::CurrentBlockBeneficiary::<Runtime>::put(test_beneficiary_id());

        AllPalletsWithSystem::on_finalize(1u32);
    });
}
