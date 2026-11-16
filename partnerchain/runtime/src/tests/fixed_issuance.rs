//! A chain whose genesis fixes its MATRA issuance. No signed call moves, burns,
//! mints or bonds MATRA, on its own or inside any wrapper, while Root's force
//! calls still move it once their delay has passed. A chain that fixes none, as
//! preprod, runs every one of those calls as before.

use super::root_timelock::{alice_committee, build_chain_spec};
use crate::*;
use frame_support::{
    assert_ok,
    dispatch::GetDispatchInfo,
    traits::{Contains, Currency},
};
use pallet_root_timelock::TaskId;
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring::{self as Keyring, Alice, Bob, Charlie, Dave, Eve};
use sp_runtime::{traits::Dispatchable, BuildStorage, DispatchError};

/// Each holder's endowment: a tenth of a MATRA.
const FUND: Balance = MATRA / 10;
const ISSUED: Balance = 3 * FUND;
const SUDO: Keyring = Alice;
const GUARDIAN: Keyring = Dave;

fn acct(k: Keyring) -> AccountId {
    k.to_account_id()
}

/// Alice, Bob and Charlie hold `FUND` each, Alice holds the sudo key and Dave
/// can veto its tasks. With `fixed`, genesis declares the three endowments as
/// the chain's issuance.
fn chain(fixed: bool) -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![(acct(Alice), FUND), (acct(Bob), FUND), (acct(Charlie), FUND)],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");
    pallet_orinq_receipts::GenesisConfig::<Runtime> {
        fixed_issuance: fixed.then_some(ISSUED),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("orinq-receipts genesis builds");
    pallet_sudo::GenesisConfig::<Runtime> {
        key: Some(acct(SUDO)),
    }
    .assimilate_storage(&mut storage)
    .expect("sudo genesis builds");
    pallet_root_timelock::GenesisConfig::<Runtime> {
        delays: TESTNET_TIMELOCK_DELAYS,
        guardian: Some(acct(GUARDIAN)),
        unguarded: false,
    }
    .assimilate_storage(&mut storage)
    .expect("root-timelock genesis builds");
    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn signed(who: Keyring, call: RuntimeCall) -> Result<(), DispatchError> {
    call.dispatch(RuntimeOrigin::signed(acct(who)))
        .map(|_| ())
        .map_err(|e| e.error)
}

fn call_filtered() -> DispatchError {
    frame_system::Error::<Runtime>::CallFiltered.into()
}

fn balances(call: pallet_balances::Call<Runtime>) -> RuntimeCall {
    RuntimeCall::Balances(call)
}

/// A payment of `value` from the signer to Charlie.
fn transfer(value: Balance) -> RuntimeCall {
    balances(pallet_balances::Call::transfer_keep_alive {
        dest: acct(Charlie).into(),
        value,
    })
}

/// Every call by which a signer moves, burns, mints or bonds MATRA.
fn matra_calls() -> Vec<RuntimeCall> {
    let charlie = || acct(Charlie);
    vec![
        balances(pallet_balances::Call::transfer_allow_death {
            dest: charlie().into(),
            value: 1_000,
        }),
        transfer(1_000),
        balances(pallet_balances::Call::transfer_all {
            dest: charlie().into(),
            keep_alive: false,
        }),
        balances(pallet_balances::Call::burn {
            value: 1_000,
            keep_alive: true,
        }),
        balances(pallet_balances::Call::upgrade_accounts {
            who: vec![charlie()],
        }),
        RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer {
            target: charlie().into(),
            schedule: pallet_vesting::VestingInfo::new(MATRA / 20, 1_000, 10),
        }),
        RuntimeCall::Billing(pallet_billing::Call::topup_self { amount: 1_000 }),
        RuntimeCall::Billing(pallet_billing::Call::topup_for {
            target: charlie(),
            amount: 1_000,
        }),
        RuntimeCall::Billing(pallet_billing::Call::execute_withdrawal {}),
        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::bond { amount: 1_000 }),
    ]
}

/// Whether the runtime's call filter lets `call` through to its pallet.
fn admitted(call: &RuntimeCall) -> bool {
    <root_gate::SudoRootGate as Contains<RuntimeCall>>::contains(call)
}

fn holdings() -> [Balance; 3] {
    [Alice, Bob, Charlie].map(|k| Balances::total_balance(&acct(k)))
}

#[test]
fn every_signed_matra_call_is_refused() {
    chain(true).execute_with(|| {
        for call in matra_calls() {
            assert_eq!(signed(Bob, call.clone()), Err(call_filtered()), "{call:?}");
        }
        assert_eq!(holdings(), [FUND; 3]);
        assert_eq!(Balances::total_issuance(), ISSUED);
    });
}

/// Preprod fixes no issuance: the filter lets each call through to the
/// pallet, as it always has.
#[test]
fn a_chain_that_fixes_no_issuance_runs_every_matra_call() {
    chain(false).execute_with(|| {
        for call in matra_calls() {
            assert!(admitted(&call), "{call:?}");
            assert_ne!(signed(Bob, call.clone()), Err(call_filtered()), "{call:?}");
        }
        assert_ok!(signed(Alice, transfer(1_000)));
        assert_eq!(Balances::free_balance(acct(Alice)), FUND - 1_000);
    });
}

/// The filter applies to every origin a wrapper dispatches under, so each
/// wrapper refuses the payment it carries, however deep.
#[test]
fn every_wrapper_refuses_the_matra_call_it_carries() {
    let batch = |calls| RuntimeCall::Utility(pallet_utility::Call::batch { calls });
    let batch_all = |calls| RuntimeCall::Utility(pallet_utility::Call::batch_all { calls });
    chain(true).execute_with(|| {
        assert_ok!(signed(Bob, batch(vec![transfer(1_000)])));
        System::assert_last_event(
            pallet_utility::Event::BatchInterrupted {
                index: 0,
                error: call_filtered(),
            }
            .into(),
        );

        assert_ok!(signed(
            Bob,
            RuntimeCall::Utility(pallet_utility::Call::force_batch {
                calls: vec![transfer(1_000)],
            })
        ));
        System::assert_has_event(
            pallet_utility::Event::ItemFailed {
                error: call_filtered(),
            }
            .into(),
        );

        for wrapped in [
            batch_all(vec![transfer(1_000)]),
            batch_all(vec![batch_all(vec![transfer(1_000)])]),
            RuntimeCall::Utility(pallet_utility::Call::as_derivative {
                index: 0,
                call: Box::new(transfer(1_000)),
            }),
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![acct(Charlie)],
                call: Box::new(transfer(1_000)),
            }),
        ] {
            assert_eq!(signed(Bob, wrapped.clone()), Err(call_filtered()), "{wrapped:?}");
        }

        // The second approval of a 2-of-2 runs the payment as the multisig
        // account, and reports the refusal as the call's result.
        let as_multi = |other: Keyring, maybe_timepoint| {
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: vec![acct(other)],
                maybe_timepoint,
                call: Box::new(transfer(1_000)),
                max_weight: transfer(1_000).get_dispatch_info().weight,
            })
        };
        assert_ok!(signed(Bob, as_multi(Charlie, None)));
        let timepoint = pallet_multisig::Pallet::<Runtime>::timepoint();
        assert_ok!(signed(Charlie, as_multi(Bob, Some(timepoint))));
        assert!(matches!(
            System::events().last().map(|record| &record.event),
            Some(RuntimeEvent::Multisig(pallet_multisig::Event::MultisigExecuted {
                result: Err(error),
                ..
            })) if *error == call_filtered()
        ));

        // `dispatch_as` skips the filter, and only Root may call it.
        assert_eq!(
            signed(
                Bob,
                RuntimeCall::Utility(pallet_utility::Call::dispatch_as {
                    as_origin: Box::new(frame_system::RawOrigin::Signed(acct(Alice)).into()),
                    call: Box::new(transfer(1_000)),
                })
            ),
            Err(DispatchError::BadOrigin)
        );

        // A rescuer holding Alice's account through pallet-recovery.
        pallet_recovery::Proxy::<Runtime>::insert(acct(Bob), acct(Alice));
        assert_eq!(
            signed(
                Bob,
                RuntimeCall::Recovery(pallet_recovery::Call::as_recovered {
                    account: acct(Alice).into(),
                    call: Box::new(transfer(1_000)),
                })
            ),
            Err(call_filtered())
        );

        assert_eq!(holdings(), [FUND; 3]);
        assert_eq!(Balances::total_issuance(), ISSUED);
    });
}

/// Root skips the filter, so its force calls still move MATRA, and the sudo
/// key reaches them only through the timelock.
#[test]
fn root_still_moves_matra_after_the_delay() {
    let force_transfer = balances(pallet_balances::Call::force_transfer {
        source: acct(Alice).into(),
        dest: acct(Bob).into(),
        value: 1_000,
    });
    chain(true).execute_with(|| {
        assert_eq!(
            signed(
                SUDO,
                RuntimeCall::Sudo(pallet_sudo::Call::sudo {
                    call: Box::new(force_transfer.clone()),
                })
            ),
            Err(call_filtered())
        );

        let id: TaskId = pallet_root_timelock::NextTaskId::<Runtime>::get();
        assert_ok!(signed(
            SUDO,
            RuntimeCall::Sudo(pallet_sudo::Call::sudo {
                call: Box::new(RuntimeCall::RootTimelock(
                    pallet_root_timelock::Call::schedule {
                        call: Box::new(force_transfer.clone()),
                    }
                )),
            })
        ));
        System::set_block_number(1 + TESTNET_TIMELOCK_DELAYS.standard);
        assert_ok!(signed(
            Charlie,
            RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact {
                id,
                call: Box::new(force_transfer),
            })
        ));

        assert_eq!(holdings(), [FUND - 1_000, FUND + 1_000, FUND]);
        assert_eq!(Balances::total_issuance(), ISSUED);
    });
}

/// Calls that only spend what Root approved, or forfeit a malicious
/// rescuer's deposit to the account it tried to take, stay open: the
/// recovery veto must not depend on the issuance.
#[test]
fn the_filter_keeps_root_approved_payouts_and_the_recovery_veto() {
    chain(true).execute_with(|| {
        for call in [
            RuntimeCall::Treasury(pallet_treasury::Call::payout { index: 0 }),
            RuntimeCall::Recovery(pallet_recovery::Call::close_recovery {
                rescuer: acct(Bob).into(),
            }),
            RuntimeCall::System(frame_system::Call::remark { remark: vec![1] }),
        ] {
            assert!(admitted(&call), "{call:?}");
        }
    });
}

/// The recovery veto moves the rescuer's deposit to the account it tried to
/// take and burns nothing: a deposit that would leave its payer under the
/// existential deposit is refused when it is reserved, so forfeiting one never
/// leaves dust to burn.
#[test]
fn the_recovery_veto_moves_a_deposit_and_keeps_the_issuance() {
    let initiate = || {
        RuntimeCall::Recovery(pallet_recovery::Call::initiate_recovery {
            account: acct(Alice).into(),
        })
    };
    chain(true).execute_with(|| {
        assert_ok!(signed(
            Alice,
            RuntimeCall::Recovery(pallet_recovery::Call::create_recovery {
                friends: vec![acct(Charlie)],
                threshold: 1,
                delay_period: 10,
            })
        ));

        // Eve holds one unit less than the deposit and the existential
        // deposit together.
        let short = RecoveryDeposit::get() + ExistentialDeposit::get() - 1;
        assert_ok!(balances(pallet_balances::Call::force_transfer {
            source: acct(Charlie).into(),
            dest: acct(Eve).into(),
            value: short,
        })
        .dispatch(RuntimeOrigin::root()));
        assert!(signed(Eve, initiate()).is_err());
        assert_eq!(Balances::reserved_balance(acct(Eve)), 0);

        assert_ok!(signed(Bob, initiate()));
        assert_ok!(signed(
            Alice,
            RuntimeCall::Recovery(pallet_recovery::Call::close_recovery {
                rescuer: acct(Bob).into(),
            })
        ));
        assert_eq!(
            holdings(),
            [FUND + RecoveryDeposit::get(), FUND - RecoveryDeposit::get(), FUND - short]
        );
        assert_eq!(Balances::total_issuance(), ISSUED);
    });
}

/// A chain spec declares the issuance its genesis holds, the Treasury's
/// existential deposit included, or the runtime refuses to build it.
#[test]
fn a_chain_spec_must_declare_the_issuance_its_genesis_holds() {
    let spec = |fixed_issuance: Balance| {
        serde_json::json!({
            "balances": { "balances": [[AccountId::from([0x11; 32]), 10_000], [AccountId::from([0x22; 32]), 20_000]] },
            "sudo": { "key": AccountId::from([0x5A; 32]) },
            "rootTimelock": { "delays": TESTNET_TIMELOCK_DELAYS, "guardian": AccountId::from([0x6B; 32]) },
            "sessionCommitteeManagement": alice_committee(),
            "orinqReceipts": { "fixedIssuance": fixed_issuance },
        })
    };
    let treasury = ExistentialDeposit::get();
    assert_eq!(build_chain_spec(spec(30_000 + treasury)), Ok(()));
    for wrong in [30_000, 30_000 + treasury + 1] {
        let refused = build_chain_spec(spec(wrong));
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("fixed issuance")),
            "{wrong}: {refused:?}"
        );
    }
}

#[cfg(feature = "try-runtime")]
#[test]
fn try_state_holds_the_issuance_to_the_declared() {
    use frame_support::traits::Hooks;
    let mint = balances(pallet_balances::Call::force_set_balance {
        who: acct(Bob).into(),
        new_free: FUND + 1,
    });
    chain(true).execute_with(|| {
        assert_ok!(<OrinqReceipts as Hooks<BlockNumber>>::try_state(1));
        assert_ok!(mint.clone().dispatch(RuntimeOrigin::root()));
        assert!(<OrinqReceipts as Hooks<BlockNumber>>::try_state(1).is_err());
    });
    chain(false).execute_with(|| {
        assert_ok!(mint.dispatch(RuntimeOrigin::root()));
        assert_ok!(<OrinqReceipts as Hooks<BlockNumber>>::try_state(1));
    });
}
