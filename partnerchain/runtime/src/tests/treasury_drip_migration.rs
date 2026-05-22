//! Tests for the one-shot fee-router-pot sweep migration.

use crate::*;

use sp_io::TestExternalities;
use sp_runtime::{BuildStorage, traits::AccountIdConversion};

const AUTHOR_POT_SEED: Balance = 7_777_777;
const ATTESTOR_POT_SEED: Balance = 3_333_333;

fn author_pot() -> AccountId {
    PalletId(*b"mat/auth").into_account_truncating()
}

fn attestor_pot() -> AccountId {
    AttestorReservePalletId::get().into_account_truncating()
}

fn trsy_pot() -> AccountId {
    TreasuryPalletId::get().into_account_truncating()
}

fn new_test_ext_with_seeded_pots() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (author_pot(), AUTHOR_POT_SEED),
            (attestor_pot(), ATTESTOR_POT_SEED),
            // Seed trsy with ED so the later sweep deposit isn't blocked by
            // a create-account ED-check corner case — the test asserts the
            // delta, not the absolute balance.
            (trsy_pot(), ExistentialDeposit::get()),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

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
    .expect("sidechain genesis");

    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("scv genesis");

    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("pcs genesis");

    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("ntm genesis");

    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| {
        // Block 0 trips `Executive::apply_extrinsic`; advance to 1.
        frame_system::Pallet::<Runtime>::set_block_number(1);
    });
    ext
}

#[test]
fn migration_sweeps_author_and_attestor_pots_into_treasury() {
    new_test_ext_with_seeded_pots().execute_with(|| {
        // Pre-conditions: both source pots non-zero, treasury at ED.
        let pre_author = pallet_balances::Pallet::<Runtime>::free_balance(&author_pot());
        let pre_attestor = pallet_balances::Pallet::<Runtime>::free_balance(&attestor_pot());
        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_author, AUTHOR_POT_SEED);
        assert_eq!(pre_attestor, ATTESTOR_POT_SEED);

        // `Executive::execute_on_runtime_upgrade` is the real upgrade path:
        // our `SweepFeeRouterPotsIntoTreasury` migration runs first, then
        // `AllPalletsWithSystem::on_runtime_upgrade`.
        Executive::execute_on_runtime_upgrade();

        // Post: both pots drained to zero (below ED => account fully reaped),
        // treasury gained exactly the sum, and total_issuance is conserved.
        let post_author = pallet_balances::Pallet::<Runtime>::free_balance(&author_pot());
        let post_attestor = pallet_balances::Pallet::<Runtime>::free_balance(&attestor_pot());
        let post_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();

        assert_eq!(post_author, 0, "mat/auth pot must be swept to zero");
        assert_eq!(post_attestor, 0, "mat/attr pot must be swept to zero");
        assert_eq!(
            post_trsy,
            pre_trsy + AUTHOR_POT_SEED + ATTESTOR_POT_SEED,
            "mat/trsy must gain exactly the swept sum"
        );
        assert_eq!(
            pre_issuance, post_issuance,
            "sweep must preserve total_issuance (transfers, not burns)"
        );
    });
}

#[test]
fn migration_sweep_is_idempotent_on_second_call() {
    new_test_ext_with_seeded_pots().execute_with(|| {
        Executive::execute_on_runtime_upgrade();
        let trsy_after_first = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());

        // Re-seed mat/attr to simulate post-sweep slashing activity. Those
        // funds MUST NOT be swept by a second call.
        pallet_balances::Pallet::<Runtime>::force_set_balance(
            RuntimeOrigin::root(),
            sp_runtime::MultiAddress::Id(attestor_pot()),
            ATTESTOR_POT_SEED,
        )
        .expect("force_set_balance");

        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let pre_attestor = pallet_balances::Pallet::<Runtime>::free_balance(&attestor_pot());

        Executive::execute_on_runtime_upgrade();

        let post_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let post_attestor = pallet_balances::Pallet::<Runtime>::free_balance(&attestor_pot());

        assert_eq!(
            post_trsy, pre_trsy,
            "second on_runtime_upgrade must NOT transfer funds"
        );
        assert_eq!(
            post_attestor, pre_attestor,
            "post-sweep mat/attr activity must survive a second upgrade"
        );
        assert_eq!(
            trsy_after_first, pre_trsy,
            "sanity: pre-re-seed equals post-first-call"
        );

        // Read the raw key used by `SweepFeeRouterPotsIntoTreasury` so this
        // assertion trips if the gate key changes.
        let gate_key: &[u8] = b":migration:v5_1_sweep:version";
        let v: u16 = frame_support::storage::unhashed::get(gate_key).unwrap_or(0);
        assert_eq!(
            v, crate::migrations::SWEEP_MIGRATION_VERSION,
            "migration gate must be bumped to v{} after first sweep",
            crate::migrations::SWEEP_MIGRATION_VERSION,
        );
    });
}

#[test]
fn migration_with_empty_source_pots_is_noop() {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![(trsy_pot(), ExistentialDeposit::get())],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

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
    .expect("sidechain genesis");

    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("scv genesis");

    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("pcs genesis");

    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("ntm genesis");

    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| {
        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        Executive::execute_on_runtime_upgrade();
        let post_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_trsy, post_trsy, "empty-source sweep must not mutate treasury");
        assert_eq!(pre_issuance, post_issuance, "empty-source sweep preserves issuance");
    });
}

#[test]
fn spec_version_at_least_202_and_tx_version_pinned() {
    // The one-shot fee-router sweep migration landed at spec 202;
    // dropping below 202 would re-fire it.
    assert!(
        VERSION.spec_version >= 202,
        "spec_version must never drop below 202; got {}",
        VERSION.spec_version
    );
    // `attest_availability_cert` flipped to canonical-cert semantics at
    // tx_version 2; a regression dropping the bump must fail CI.
    assert!(
        VERSION.transaction_version >= 2,
        "transaction_version must be >= 2"
    );
}

#[test]
fn migration_sweeps_when_treasury_account_does_not_preexist() {
    // mat/trsy is intentionally NOT seeded: on a fresh mainnet upgrade
    // `pallet_treasury` defers account creation until its first spend,
    // so the migration's pre-creation step must establish the recipient
    // before the first transfer.
    const AUTHOR_POT_SEED: Balance = 7_777_777;

    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (PalletId(*b"mat/auth").into_account_truncating(), AUTHOR_POT_SEED),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

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
    .expect("sidechain genesis");

    pallet_session_validator_management::GenesisConfig::<Runtime> {
        initial_authorities: Vec::new(),
        main_chain_scripts: sp_session_validator_management::MainChainScripts::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("scv genesis");

    pallet_partner_chains_session::GenesisConfig::<Runtime> {
        initial_validators: Vec::new(),
    }
    .assimilate_storage(&mut storage)
    .expect("pcs genesis");

    pallet_native_token_management::GenesisConfig::<Runtime> {
        main_chain_scripts: sp_native_token_management::MainChainScripts::default(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("ntm genesis");

    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);

        let auth_pot = PalletId(*b"mat/auth").into_account_truncating();
        let trsy = trsy_pot();

        let pre_auth = pallet_balances::Pallet::<Runtime>::free_balance(&auth_pot);
        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy);
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_auth, AUTHOR_POT_SEED);
        assert_eq!(pre_trsy, 0, "mat/trsy must not pre-exist");
        // `free_balance` returns 0 for missing accounts; check AccountInfo
        // directly to confirm no row exists.
        assert!(
            !frame_system::Account::<Runtime>::contains_key(&trsy),
            "mat/trsy must have no AccountInfo before sweep"
        );

        Executive::execute_on_runtime_upgrade();

        let post_auth = pallet_balances::Pallet::<Runtime>::free_balance(&auth_pot);
        let post_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy);
        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();

        assert_eq!(
            post_auth, 0,
            "mat/auth must be drained even when treasury didn't pre-exist"
        );
        assert_eq!(
            post_trsy, AUTHOR_POT_SEED,
            "mat/trsy must receive the full sweep even when created by the migration"
        );
        assert_eq!(
            pre_issuance, post_issuance,
            "sweep preserves total_issuance regardless of treasury pre-existence"
        );
        assert!(
            frame_system::Account::<Runtime>::contains_key(&trsy),
            "mat/trsy must have AccountInfo after sweep"
        );
    });
}
