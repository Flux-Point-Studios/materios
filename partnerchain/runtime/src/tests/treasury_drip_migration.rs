//! v5.1 Midnight-style fees — one-shot migration sweep test (spec 201 → 202).
//!
//! Under the old 40/30/20/10 fee-router, two PalletId-derived accounts held
//! balances that pallet-block-rewards / Component 8 were supposed to drain:
//!   * `mat/auth` — 40% author-pot share
//!   * `mat/attr` — 30% attestor-reserve share
//!
//! With the fee router deleted, those pots become stranded value. This
//! migration sweeps any residual balances from both into `mat/trsy` exactly
//! once, at spec 201 → 202 upgrade. After that the attestor-reserve pot
//! continues to receive slashed bonds (Component 8 routes slashing to it),
//! so we only skip the sweep step itself on subsequent upgrades — Component 8
//! keeps functioning.
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT — this test is RED before the fix, GREEN after.
//! ---------------------------------------------------------------------------
//!
//! RED: no runtime-level migration sweep exists yet, so running
//! `AllPalletsWithSystem::on_runtime_upgrade` on a fresh ext with seeded
//! author + attestor pots leaves those pots untouched.
//!
//! GREEN: after the migration lands, the sweep drains both pots into treasury
//! exactly once, AND a second call is a no-op (idempotency verified via
//! StorageVersion check).

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
        // Seed the pre-upgrade storage version. The migration keys off the
        // runtime's own `FeeDeletionMigration` storage version. We start at 0
        // (= "sweep not yet run"). `System::set_block_number(1)` keeps
        // Executive::apply_extrinsic from tripping on block 0.
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

        // Act: run the runtime's on_runtime_upgrade hook chain, which must
        // include our sweep migration.
        // `Executive::execute_on_runtime_upgrade` is the real path that runs
        // at a spec bump: first our `SweepFeeRouterPotsIntoTreasury` migration
        // (the 6th Executive type-arg), THEN `AllPalletsWithSystem::
        // on_runtime_upgrade`. Calling that directly keeps this test faithful
        // to production behavior.
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
        // First call: the real sweep.
        // `Executive::execute_on_runtime_upgrade` is the real path that runs
        // at a spec bump: first our `SweepFeeRouterPotsIntoTreasury` migration
        // (the 6th Executive type-arg), THEN `AllPalletsWithSystem::
        // on_runtime_upgrade`. Calling that directly keeps this test faithful
        // to production behavior.
        Executive::execute_on_runtime_upgrade();
        let trsy_after_first = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());

        // Re-seed the source pots to simulate post-sweep Component-8 slashing
        // activity: attestor slashing continues to route funds into mat/attr.
        // Those MUST NOT be swept by a second call — the migration has already
        // run, and funds landed in mat/attr AFTER the sweep are intended state.
        pallet_balances::Pallet::<Runtime>::force_set_balance(
            RuntimeOrigin::root(),
            sp_runtime::MultiAddress::Id(attestor_pot()),
            ATTESTOR_POT_SEED,
        )
        .expect("force_set_balance");

        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let pre_attestor = pallet_balances::Pallet::<Runtime>::free_balance(&attestor_pot());

        // Second call: must be a no-op.
        // `Executive::execute_on_runtime_upgrade` is the real path that runs
        // at a spec bump: first our `SweepFeeRouterPotsIntoTreasury` migration
        // (the 6th Executive type-arg), THEN `AllPalletsWithSystem::
        // on_runtime_upgrade`. Calling that directly keeps this test faithful
        // to production behavior.
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

        // Verify the migration's version gate is bumped. We read the raw
        // storage key used by `SweepFeeRouterPotsIntoTreasury` so the test
        // is sensitive to the gate moving (which would silently break
        // idempotency).
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
    // If a fresh chain never had fee-router balances (e.g. a brand-new testnet),
    // the sweep still runs but moves nothing. Ensures the migration handles the
    // zero-source-balance case without failure.
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
        // `Executive::execute_on_runtime_upgrade` is the real path that runs
        // at a spec bump: first our `SweepFeeRouterPotsIntoTreasury` migration
        // (the 6th Executive type-arg), THEN `AllPalletsWithSystem::
        // on_runtime_upgrade`. Calling that directly keeps this test faithful
        // to production behavior.
        Executive::execute_on_runtime_upgrade();
        let post_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy_pot());
        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_trsy, post_trsy, "empty-source sweep must not mutate treasury");
        assert_eq!(pre_issuance, post_issuance, "empty-source sweep preserves issuance");
    });
}

#[test]
fn spec_version_at_least_202_and_tx_version_pinned() {
    // Treasury-drip + MOTRA-only-fees migration landed at spec 202.
    // Subsequent upgrades (spec 203: MaxCommitteeSize 16 → 64) must not
    // silently revert the spec below 202 — otherwise the one-shot
    // migration gate would re-run. `transaction_version` is pinned at 1
    // because no change since 202 has introduced a breaking wire format.
    //
    // Historical note: this test was previously `spec_version_bumped_to_202`
    // pinning `spec_version == 202` exactly; it was relaxed to `>= 202` in
    // spec 203 (MaxCommitteeSize bump). See PR feat/runtime-max-committee-64.
    assert!(
        VERSION.spec_version >= 202,
        "spec_version must never drop below 202 (treasury-drip migration gate); got {}",
        VERSION.spec_version
    );
    assert_eq!(
        VERSION.transaction_version, 1,
        "transaction_version must stay at 1 — no breaking wire format change"
    );
}

#[test]
fn migration_sweeps_when_treasury_account_does_not_preexist() {
    // MEDIUM follow-up from PR-9 security review: the existing
    // `migration_sweeps_author_and_attestor_pots_into_treasury` test
    // pre-funds treasury with ExistentialDeposit so the sweep's recipient
    // side doesn't trip the ED-on-deposit guard. On a fresh mainnet
    // spec-202 upgrade, however, `mat/trsy` may never have been touched
    // — `pallet_treasury` defers account creation until its first spend.
    //
    // This test leaves `mat/trsy` uncreated (no genesis seed, no prior
    // touch) and verifies the sweep still succeeds and preserves
    // issuance. Per the security-review spec, the migration must
    // pre-create the treasury before the first transfer so even an
    // account that didn't pre-exist gains one write and accepts the
    // subsequent credit.
    //
    // We seed `mat/auth` with a realistic sweep-worthy amount (above ED)
    // so the transfer is semantically a real sweep, not a dust-recovery
    // corner case. The sub-ED corner is Substrate-immovable (ED rule is
    // global), so the right behavior there is to log + skip, not to
    // invent bytes.
    const AUTHOR_POT_SEED: Balance = 7_777_777; // >> ED=500

    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        // mat/auth has real funds; mat/attr is empty; mat/trsy is NOT
        // seeded — this is the configuration that exercises the corner
        // case.
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

        // Pre-state: mat/auth has funds, mat/trsy has NO AccountInfo row.
        let pre_auth = pallet_balances::Pallet::<Runtime>::free_balance(&auth_pot);
        let pre_trsy = pallet_balances::Pallet::<Runtime>::free_balance(&trsy);
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(pre_auth, AUTHOR_POT_SEED);
        assert_eq!(pre_trsy, 0, "mat/trsy must not pre-exist");
        // Confirm treasury really has no AccountInfo entry; `free_balance`
        // would return 0 either way, so check the system-side directly.
        assert!(
            !frame_system::Account::<Runtime>::contains_key(&trsy),
            "mat/trsy must have no AccountInfo before sweep"
        );

        // Act: run the sweep migration.
        Executive::execute_on_runtime_upgrade();

        // Post: the sweep moves the full author pot to treasury. Even
        // though treasury didn't pre-exist, the migration's pre-creation
        // step ensures the account is established before the first
        // transfer.
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
