//! MOTRA-only fee invariant: MATRA total_issuance is conserved across
//! signed `Balances::transfer_keep_alive` dispatches. Re-introducing any
//! MATRA charging anywhere (a new transaction-payment pallet, a
//! `SignedExtension` that touches Balances, a Balances hook) trips this
//! integration test immediately.

use crate::*;

use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

// ---------------------------------------------------------------------------
// Externalities builder
// ---------------------------------------------------------------------------

const FEE_PAYER_SEED: Balance = 1_000_000_000_000;

fn fee_payer() -> AccountId {
    sp_keyring::Sr25519Keyring::Dave.to_account_id()
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");

    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![(fee_payer(), FEE_PAYER_SEED)],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");

    pallet_sidechain::GenesisConfig::<Runtime> {
        genesis_utxo: sidechain_domain::UtxoId::new(
            hex_literal::hex!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
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

    storage.into()
}

#[test]
fn matra_total_issuance_conserved_across_n_extrinsics() {
    use sp_runtime::traits::Dispatchable;

    let recipient = sp_keyring::Sr25519Keyring::Eve.to_account_id();

    new_test_ext().execute_with(|| {
        // Seed the recipient with ExistentialDeposit so subsequent
        // transfers of any size succeed; the seed is captured in
        // `pre_issuance` so the conservation invariant is unaffected.
        pallet_balances::Pallet::<Runtime>::force_set_balance(
            RuntimeOrigin::root(),
            sp_runtime::MultiAddress::Id(recipient.clone()),
            ExistentialDeposit::get(),
        )
        .expect("force_set_balance must succeed as Root");

        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        let pre_payer = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let pre_recipient = pallet_balances::Pallet::<Runtime>::free_balance(&recipient);

        let amounts: [Balance; 5] = [501, 1_000, 10_000, 97_337, 1_234_567];
        let total_transferred: Balance = amounts.iter().sum::<Balance>() * 5;
        for _ in 0..5 {
            for &amount in &amounts {
                let call = RuntimeCall::Balances(
                    pallet_balances::Call::<Runtime>::transfer_keep_alive {
                        dest: sp_runtime::MultiAddress::Id(recipient.clone()),
                        value: amount,
                    },
                );
                call.dispatch(RuntimeOrigin::signed(fee_payer()))
                    .expect("transfer_keep_alive dispatch must succeed");
            }
        }

        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        let post_payer = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let post_recipient = pallet_balances::Pallet::<Runtime>::free_balance(&recipient);

        assert_eq!(
            pre_issuance, post_issuance,
            "MATRA total_issuance must be conserved across 25 real transfer_keep_alive dispatches (drift = {})",
            (pre_issuance as i128) - (post_issuance as i128),
        );
        assert_eq!(
            pre_payer.saturating_sub(post_payer), total_transferred,
            "payer must lose exactly the sum transferred (no MATRA tx-fee burn)"
        );
        assert_eq!(
            post_recipient.saturating_sub(pre_recipient), total_transferred,
            "recipient must gain exactly the sum transferred"
        );
    });
}

#[test]
fn fresh_funding_rpc_and_sponsored_first_fee() {
    use frame_support::assert_ok;
    use parity_scale_codec::{Decode, Encode};
    use sp_runtime::traits::SignedExtension;

    new_test_ext().execute_with(|| {
        let recipient = sp_keyring::Sr25519Keyring::Eve.to_account_id();
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.generation_per_matra_per_block = 1_000;
            p.min_fee = 20_000;
            p.length_fee_per_byte = 0;
            p.congestion_rate = 0;
            p.decay_rate_per_block = sp_runtime::Perbill::one();
            p.max_balance = u128::MAX;
        });
        System::set_block_number(100);
        assert_ok!(Balances::transfer_keep_alive(
            RuntimeOrigin::signed(fee_payer()),
            recipient.clone().into(),
            1_000_000,
        ));
        let rpc = || {
            let encoded = crate::api::dispatch("MotraApi_motra_balance", &recipient.encode())
                .expect("runtime API dispatch");
            u128::decode(&mut &encoded[..]).expect("MOTRA response")
        };
        assert_eq!(Motra::last_touched(&recipient), 100);
        assert_eq!(rpc(), 0);
        let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
        let info = frame_support::dispatch::GetDispatchInfo::get_dispatch_info(&call);
        assert!(pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&recipient, &call, &info, 0)
            .is_err());
        assert_ok!(Motra::set_delegatee(
            RuntimeOrigin::signed(fee_payer()),
            Some(recipient.clone())
        ));
        System::set_block_number(110);
        let root = sp_io::storage::root(sp_runtime::StateVersion::V1);
        assert_eq!(rpc(), 10_000);
        assert_eq!(sp_io::storage::root(sp_runtime::StateVersion::V1), root);
        assert_ok!(Motra::reconcile(&recipient), rpc());
        assert!(pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&recipient, &call, &info, 0)
            .is_err());
        assert_ok!(Motra::reconcile(&fee_payer()));
        let sponsored = Motra::motra_balance(&recipient);
        assert!(sponsored > 10_000);
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&recipient, &call, &info, 0));
        assert_eq!(Motra::motra_balance(&recipient), sponsored - 20_000);
    });
}

#[test]
fn sovereign_pots_and_subaccounts_do_not_generate_motra() {
    use frame_support::assert_ok;
    use sp_runtime::traits::AccountIdConversion;

    new_test_ext().execute_with(|| {
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.generation_per_matra_per_block = 1_000;
            p.max_balance = u128::MAX;
        });
        let pot = PalletId(*b"test/pot");
        let accounts: [AccountId; 2] = [
            pot.into_account_truncating(),
            pot.into_sub_account_truncating(42u32),
        ];
        System::set_block_number(100);
        for account in &accounts {
            assert_ok!(Balances::transfer_keep_alive(
                RuntimeOrigin::signed(fee_payer()),
                sp_runtime::MultiAddress::Id(account.clone()),
                1_000_000,
            ));
        }
        System::set_block_number(200);
        for account in accounts {
            assert_eq!(Motra::projected_balance(&account), 0);
            assert_ok!(Motra::reconcile(&account), 0);
        }
    });
}

#[test]
fn legacy_holder_without_stored_motra_can_pay_after_the_upgrade() {
    use frame_support::{
        assert_ok,
        traits::{Hooks, StorageVersion},
    };
    use sp_runtime::traits::SignedExtension;

    new_test_ext().execute_with(|| {
        let who = fee_payer();
        pallet_motra::AccrualCheckpoint::<Runtime>::remove(&who);
        pallet_motra::LastTouched::<Runtime>::remove(&who);
        pallet_motra::MotraBalances::<Runtime>::remove(&who);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.min_fee = 20_000;
            p.length_fee_per_byte = 0;
            p.congestion_rate = 0;
            p.generation_per_matra_per_block = 1_000;
            p.decay_rate_per_block = sp_runtime::Perbill::one();
            p.max_balance = u128::MAX;
        });
        StorageVersion::new(0).put::<Motra>();
        System::set_block_number(1_000_000);
        Motra::on_runtime_upgrade();
        assert_eq!(Motra::projected_balance(&who), 0);
        System::set_block_number(1_000_010);
        let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
        let info = frame_support::dispatch::GetDispatchInfo::get_dispatch_info(&call);
        assert_ok!(
            pallet_motra::fee::ChargeMotra::<Runtime>::new().pre_dispatch(&who, &call, &info, 0)
        );
        assert_eq!(Motra::total_burned(), 20_000);
    });
}

#[test]
fn checkpoint_transfer_dispatch_weight_covers_both_accounts_and_creation() {
    use frame_support::dispatch::GetDispatchInfo;
    use pallet_balances::WeightInfo;

    let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
        dest: sp_keyring::Sr25519Keyring::Eve.to_account_id().into(),
        value: ExistentialDeposit::get(),
    });
    let upstream = pallet_balances::weights::SubstrateWeight::<Runtime>::transfer_keep_alive();
    // Each account budgets mutation, legacy repair and account creation.
    let checkpoints = frame_support::weights::constants::RocksDbWeight::get()
        .reads_writes(24, 6)
        .saturating_add(Weight::from_parts(0, 84_000));
    let actual = call.get_dispatch_info().weight;
    assert_eq!(actual, upstream.saturating_add(checkpoints));
    eprintln!("transfer_keep_alive weight: {upstream:?} -> {actual:?}");
}

#[test]
fn checkpoint_batch_at_block_limit_cannot_finalize_overweight() {
    use frame_support::{assert_ok, dispatch::GetDispatchInfo, traits::Hooks};
    use parity_scale_codec::Encode;
    use sp_runtime::{
        traits::{Dispatchable, SignedExtension},
        transaction_validity::InvalidTransaction,
    };

    new_test_ext().execute_with(|| {
        System::initialize(&1, &Default::default(), &Default::default());
        let transfer = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
            dest: sp_keyring::Sr25519Keyring::Eve.to_account_id().into(),
            value: ExistentialDeposit::get(),
        });
        let limits = RuntimeBlockWeights::get();
        let normal = frame_support::dispatch::DispatchClass::Normal;
        let operational = frame_support::dispatch::DispatchClass::Operational;
        let count = (1..=10_000)
            .take_while(|n| {
                use pallet_utility::WeightInfo;
                transfer
                    .get_dispatch_info()
                    .weight
                    .saturating_mul(u64::from(*n))
                    .saturating_add(<Runtime as pallet_utility::Config>::WeightInfo::batch(*n))
                    .all_lte(
                        limits
                            .get(normal)
                            .max_total
                            .expect("normal cap")
                            .saturating_sub(limits.get(normal).base_extrinsic),
                    )
            })
            .last()
            .expect("at least one transfer fits");
        let batch = RuntimeCall::Utility(pallet_utility::Call::batch {
            calls: vec![transfer.clone(); count as usize],
        });
        let info = batch.get_dispatch_info();
        let len = batch.encoded_size();
        // Previously admitted work leaves exactly this batch's declared budget.
        let prior = limits.max_block.ref_time()
            - info.weight.ref_time()
            - limits.get(normal).base_extrinsic.ref_time();
        System::register_extra_weight_unchecked(Weight::from_parts(prior, 0), operational);
        assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
            &info, len
        ));
        assert_ok!(
            pallet_motra::fee::ChargeMotra::<Runtime>::new().pre_dispatch(
                &fee_payer(),
                &batch,
                &info,
                len
            )
        );
        let post = batch
            .dispatch(RuntimeOrigin::signed(fee_payer()))
            .expect("batch dispatch");
        assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(
            Some(()),
            &info,
            &post,
            len,
            &Ok(())
        ));
        assert_eq!(
            Balances::free_balance(sp_keyring::Sr25519Keyring::Eve.to_account_id()),
            count as Balance * ExistentialDeposit::get(),
            "every inner transfer ran"
        );
        assert_eq!(
            frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
                &transfer.get_dispatch_info(),
                transfer.encoded_size()
            ),
            Err(InvalidTransaction::ExhaustsResources.into())
        );
        Motra::on_finalize(1);
        System::finalize();
        let actual = System::block_weight().total();
        assert!(
            actual.all_lte(limits.max_block),
            "finalized overweight: {actual:?} > {:?}",
            limits.max_block
        );
        eprintln!(
            "batch transfers={count}, finalized={actual:?}, maximum={:?}",
            limits.max_block
        );
    });
}

#[test]
fn checkpoint_currency_callers_and_fee_extension_have_declared_budgets() {
    let checkpoint = frame_support::weights::constants::RocksDbWeight::get()
        .reads_writes(4, 1)
        .saturating_add(Weight::from_parts(0, 14_000));
    macro_rules! covered {
        ($pallet:ident, $method:ident($($arg:expr),*), $accounts:expr) => {{
            use $pallet::WeightInfo;
            let base = $pallet::weights::SubstrateWeight::<Runtime>::$method($($arg),*);
            let actual = <Runtime as $pallet::Config>::WeightInfo::$method($($arg),*);
            assert!(actual.all_gte(base.saturating_add(checkpoint.saturating_mul($accounts))),
                "{}::{} omits checkpoint weight", stringify!($pallet), stringify!($method));
        }};
    }
    covered!(pallet_vesting, vested_transfer(1, 1), 2);
    covered!(pallet_vesting, force_vested_transfer(1, 1), 2);
    covered!(pallet_multisig, as_multi_create(2, 0), 1);
    covered!(pallet_multisig, as_multi_complete(2, 0), 1);
    covered!(pallet_multisig, cancel_as_multi(2), 1);
    covered!(pallet_recovery, create_recovery(2), 1);
    covered!(pallet_recovery, initiate_recovery(), 1);
    covered!(pallet_recovery, close_recovery(2), 2);
    covered!(pallet_recovery, remove_recovery(2), 1);
    covered!(pallet_treasury, payout(), 2);
    covered!(pallet_treasury, on_initialize_proposals(100), 201);
    covered!(pallet_intent_settlement, post_settlement_bond(), 1);
    covered!(pallet_intent_settlement, slash_bad_settlement_evidence(), 4);
    covered!(pallet_intent_settlement, release_settlement_bond(), 1);
    assert!(RuntimeBlockWeights::get()
        .get(frame_support::dispatch::DispatchClass::Normal)
        .base_extrinsic
        .all_gte(ExtrinsicBaseWeight::get().saturating_add(checkpoint)));
}

#[test]
fn checkpoint_receipt_rewards_return_hook_weight() {
    use frame_support::traits::Hooks;
    new_test_ext().execute_with(|| {
        let who = sp_keyring::Sr25519Keyring::Eve.to_account_id();
        System::set_block_number(14_400);
        pallet_orinq_receipts::BlocksAuthored::<Runtime>::insert(&who, 1);
        let before = System::block_weight();
        let weight = OrinqReceipts::on_initialize(14_400);
        assert!(Balances::free_balance(who) > 0, "era rewards were paid");
        let checkpoint = frame_support::weights::constants::RocksDbWeight::get()
            .reads_writes(4, 1)
            .saturating_add(Weight::from_parts(0, 14_000));
        assert!(
            weight.all_gte(checkpoint.saturating_mul(4)),
            "reward hook omitted balance checkpoints: {weight:?}"
        );
        assert_eq!(
            System::block_weight(),
            before,
            "hook must return its weight"
        );
    });
}

#[test]
fn checkpoint_settlement_bond_dispatches_use_the_configured_weights() {
    use frame_support::dispatch::{DispatchClass, GetDispatchInfo, Pays};
    use pallet_intent_settlement::{types::FraudProof, WeightInfo};
    type Configured = <Runtime as pallet_intent_settlement::Config>::WeightInfo;
    let calls = [
        (
            pallet_intent_settlement::Call::post_settlement_bond {
                claim_id: H256::zero(),
                amount: 1,
            },
            Configured::post_settlement_bond(),
            Pays::Yes,
        ),
        (
            pallet_intent_settlement::Call::slash_bad_settlement_evidence {
                claim_id: H256::zero(),
                fraud_proof: FraudProof::TxNotFound,
                signatures: vec![],
            },
            Configured::slash_bad_settlement_evidence(),
            Pays::No,
        ),
        (
            pallet_intent_settlement::Call::release_settlement_bond {
                claim_id: H256::zero(),
            },
            Configured::release_settlement_bond(),
            Pays::Yes,
        ),
    ];
    for (call, expected, pays_fee) in calls {
        let info = RuntimeCall::IntentSettlement(call).get_dispatch_info();
        assert_eq!(
            info.weight, expected,
            "bond dispatch bypassed configured checkpoint weight"
        );
        assert_eq!(info.class, DispatchClass::Operational);
        assert_eq!(info.pays_fee, pays_fee);
    }
}
