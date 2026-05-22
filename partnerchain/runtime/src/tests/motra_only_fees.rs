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
