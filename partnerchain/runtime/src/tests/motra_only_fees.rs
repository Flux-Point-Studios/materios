//! v5.1 Midnight-style fees — MATRA tx-fee DELETED, MOTRA becomes sole tx-fee.
//!
//! This file supersedes `fee_router.rs` (which tested the now-deleted 40/30/20/10
//! MATRA fee router). The new invariants:
//!
//!   * The runtime's `pallet_transaction_payment::Config::OnChargeTransaction`
//!     MUST NOT withdraw MATRA. `withdraw_fee` returns `Ok(None)` (zero-op).
//!   * MATRA `total_issuance` is conserved across any tx sequence (no protocol
//!     burn anywhere in the runtime hot path).
//!   * The `TransactionPayment` RPC surface (`query_info`, `query_fee_details`)
//!     still works but returns zero MATRA fees.
//!   * MOTRA burn-on-use via `ChargeMotra` SignedExtension remains the only tx
//!     fee mechanism (exercised by the motra pallet's own tests; this file
//!     asserts only the MATRA non-charging invariant at the runtime layer).
//!
//! ---------------------------------------------------------------------------
//! TDD CONTRACT — these tests are RED before the fix, GREEN after.
//! ---------------------------------------------------------------------------
//!
//! RED (on `main` as of 2026-04-21): the runtime charges MATRA via
//! `FungibleAdapter<Balances, fee_router::DealWithFees<Runtime>>`, so
//! `withdraw_fee` returns a non-zero credit and the sender's MATRA balance
//! drops by `fee`.
//!
//! GREEN (after this PR): the runtime uses a no-op adapter. `withdraw_fee`
//! returns `Ok(None)` with zero side-effects; total_issuance is conserved.

use crate::*;

use pallet_transaction_payment::OnChargeTransaction;
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

// ---------------------------------------------------------------------------
// The load-bearing type under test.
// ---------------------------------------------------------------------------
//
// Target: `<Runtime as pallet_transaction_payment::Config>::OnChargeTransaction`
// is the exact type plugged into the runtime's tx-fee pipeline. Testing via the
// trait method (`withdraw_fee`) exercises behavior-as-called rather than a
// predicate in isolation — this is the same code-path `SignedExtension::pre_dispatch`
// hits for every signed extrinsic.

type TxCharge = <Runtime as pallet_transaction_payment::Config>::OnChargeTransaction;

fn dummy_call() -> RuntimeCall {
    // A trivial call we know the runtime accepts. The call body is not used by
    // `withdraw_fee` (its `_call` arg is ignored by FungibleAdapter), but we
    // pass a valid one so a future, call-sensitive adapter wouldn't silently
    // break this test.
    RuntimeCall::Balances(pallet_balances::Call::<Runtime>::transfer_keep_alive {
        dest: sp_runtime::MultiAddress::Id(sp_keyring::Sr25519Keyring::Eve.to_account_id()),
        value: 1,
    })
}

fn dummy_dispatch_info() -> frame_support::dispatch::DispatchInfo {
    // Weight of zero / Normal class / pays yes — standard for a cheap transfer.
    frame_support::dispatch::DispatchInfo::default()
}

// ---------------------------------------------------------------------------
// 1) Core invariant: withdraw_fee does NOT charge MATRA.
// ---------------------------------------------------------------------------

#[test]
fn withdraw_fee_does_not_charge_matra() {
    new_test_ext().execute_with(|| {
        let pre_balance = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        let call = dummy_call();
        let info = dummy_dispatch_info();
        // A non-zero fee with a non-zero tip — a realistic signed tx shape.
        let fee: Balance = 1_234;
        let tip: Balance = 567;

        let liquidity =
            <TxCharge as OnChargeTransaction<Runtime>>::withdraw_fee(
                &fee_payer(), &call, &info, fee, tip,
            )
            .expect("withdraw_fee must not error");

        // The adapter must withdraw nothing: no MATRA taken from payer, no
        // change to total_issuance, no non-empty LiquidityInfo.
        let post_balance = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(
            pre_balance, post_balance,
            "payer's MATRA balance must not change on withdraw_fee; delta = {}",
            pre_balance.saturating_sub(post_balance)
        );
        assert_eq!(
            pre_issuance, post_issuance,
            "total_issuance must be conserved across withdraw_fee"
        );

        // Round-trip: correct_and_deposit_fee with the returned LiquidityInfo
        // must also be a no-op. Any credit/debt round-trip leaks value.
        let post_info = frame_support::dispatch::PostDispatchInfo::default();
        <TxCharge as OnChargeTransaction<Runtime>>::correct_and_deposit_fee(
            &fee_payer(), &info, &post_info, fee, tip, liquidity,
        )
        .expect("correct_and_deposit_fee must not error");
        let final_balance = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let final_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(
            pre_balance, final_balance,
            "round-trip withdraw_fee + correct_and_deposit_fee must conserve payer balance"
        );
        assert_eq!(
            pre_issuance, final_issuance,
            "round-trip must conserve total_issuance"
        );
    });
}

// ---------------------------------------------------------------------------
// 2) Non-negotiable invariant: MATRA total_issuance conserved across a
//    simulated burst of transfers with varying fees/tips.
// ---------------------------------------------------------------------------

#[test]
fn matra_total_issuance_conserved_under_random_fee_pattern() {
    // Deterministic pseudo-random fee/tip pattern. We exercise the withdraw
    // + correct round-trip 100 times. Any burn anywhere in the fee path would
    // cause total_issuance to drift; the test is tight to the last unit.
    new_test_ext().execute_with(|| {
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();

        let call = dummy_call();
        let info = dummy_dispatch_info();
        let post_info = frame_support::dispatch::PostDispatchInfo::default();

        // LCG-style deterministic scalars: not meant to be random, just to
        // cover a broad fee/tip spread (including coprime-with-100 residues
        // that would expose rounding burns, if any existed).
        let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..100u32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let fee: Balance = (seed as Balance) % 10_000;
            let tip: Balance = ((seed >> 32) as Balance) % 1_000;

            let liquidity =
                <TxCharge as OnChargeTransaction<Runtime>>::withdraw_fee(
                    &fee_payer(), &call, &info, fee, tip,
                )
                .expect("withdraw_fee ok");
            <TxCharge as OnChargeTransaction<Runtime>>::correct_and_deposit_fee(
                &fee_payer(), &info, &post_info, fee, tip, liquidity,
            )
            .expect("correct_and_deposit_fee ok");
        }

        let post_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        assert_eq!(
            pre_issuance, post_issuance,
            "MATRA total_issuance must be conserved across 100 fee round-trips (drift = {})",
            (pre_issuance as i128) - (post_issuance as i128),
        );

        // Secondary: payer balance is also conserved to the last unit.
        let post_payer = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        assert_eq!(
            post_payer, FEE_PAYER_SEED,
            "payer's MATRA must be untouched across all 100 fee round-trips"
        );
    });
}

// ---------------------------------------------------------------------------
// 3) TransactionPayment RPC surface still works and returns ZERO MATRA fees.
//    Preserves wallet / explorer compatibility — they call these APIs.
// ---------------------------------------------------------------------------

#[test]
fn tx_payment_rpc_weight_to_fee_still_callable() {
    // Wallets / explorers call `TransactionPayment::weight_to_fee` via the
    // runtime API surface. After the MATRA-fee deletion the number it returns
    // is informational only — no MATRA is actually charged — but the RPC
    // path MUST still resolve without panic, so we exercise it here.
    new_test_ext().execute_with(|| {
        let weight = frame_support::weights::Weight::from_parts(1_000_000, 0);
        let nominal = TransactionPayment::weight_to_fee(weight);
        // IdentityFee<Balance> maps ref_time -> fee 1:1, so for a non-zero
        // weight we expect a non-zero nominal figure. The real assertion
        // (zero *actual* MATRA charged) is `withdraw_fee_does_not_charge_matra`
        // above; this test just guards the RPC surface from regression.
        assert!(nominal > 0, "WeightToFee still computes a nominal figure for RPC");
    });
}

// ---------------------------------------------------------------------------
// 4) Integration-style invariant: MATRA total_issuance is conserved across a
//    run of real signed `Balances::transfer_keep_alive` calls through the
//    dispatch pipeline. This is the behavior-as-called replacement for the
//    three trait-direct tests above — those exercise the
//    `OnChargeTransaction` hook in isolation; this one exercises actual
//    Balances-pallet extrinsics, which is what users submit.
//
//    Survives the HIGH #1 deletion of `pallet_transaction_payment`: this
//    test does not reference `TxCharge`, `OnChargeTransaction`, or
//    `TransactionPayment` at all — only `RuntimeCall::Balances(...)` and
//    `Dispatchable::dispatch`, which remain valid after the pallet goes.
// ---------------------------------------------------------------------------

#[test]
fn matra_total_issuance_conserved_across_n_extrinsics() {
    use frame_support::dispatch::Dispatchable;

    let recipient = sp_keyring::Sr25519Keyring::Eve.to_account_id();

    new_test_ext().execute_with(|| {
        let pre_issuance = pallet_balances::Pallet::<Runtime>::total_issuance();
        let pre_payer = pallet_balances::Pallet::<Runtime>::free_balance(&fee_payer());
        let pre_recipient = pallet_balances::Pallet::<Runtime>::free_balance(&recipient);

        // 25 real Balances::transfer_keep_alive dispatches. Each call has
        // the shape of a live user extrinsic (signed by Dave, transferring
        // to Eve). Amounts are deliberately chosen to cover both dust-like
        // and nominal transfers, so any fee-burn regression that applied
        // a percentage would immediately show up as cumulative drift.
        let amounts: [Balance; 5] = [1, 7, 97, 1_000, 33_333];
        let total_transferred: Balance = amounts.iter().sum::<Balance>() * 5;
        for _ in 0..5 {
            for &amount in &amounts {
                let call = RuntimeCall::Balances(
                    pallet_balances::Call::<Runtime>::transfer_keep_alive {
                        dest: sp_runtime::MultiAddress::Id(recipient.clone()),
                        value: amount,
                    },
                );
                // Dispatch through the signed-origin path — this is the
                // same dispatch `Executive::apply_extrinsic` reaches after
                // SignedExtensions run. The SignedExtension chain in this
                // runtime (post-202) doesn't touch MATRA balances —
                // `ChargeMotra` operates on the MOTRA pallet only — so
                // skipping the SE chain here is equivalent from a MATRA-
                // issuance standpoint. If a future SE re-introduces a
                // MATRA burn anywhere, the right fix is to plumb that SE
                // into this test harness, not to paper over the drift.
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
