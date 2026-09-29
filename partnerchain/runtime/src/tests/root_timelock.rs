//! Root behind a delay: the sudo key reaches Root at once only for the
//! safety-only exempt calls, `RootTimelock::schedule` and the call the
//! guardian approved; everything else waits its class's delay in
//! `RootTimelock`, where the guardian can veto it.

use crate::migrations::{InitRootTimelock, PREPROD_GENESIS_HASH};
use crate::root_gate::{max_exempt_stall_delay, TimelockClassifier, MAX_EXEMPT_STALL_DELAY};
use crate::*;
use frame_support::{
    assert_ok,
    dispatch::{DispatchClass, GetDispatchInfo},
    storage::unhashed,
    traits::{Hooks, OnRuntimeUpgrade, OneSessionHandler},
};
use pallet_orinq_receipts::types::PinnedMember;
use pallet_root_timelock::{
    CallClass, ClassifyCall, DelayTable, Guardian, PendingGuardianChange, Task, TaskId, Tasks,
};
use parity_scale_codec::Encode;
use proptest::prelude::*;
use sidechain_domain::{AssetName, DParameter, EpochNonce, MainchainAddress, PolicyId};
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring::{self as Keyring, Alice, Bob, Charlie, Dave, Eve, Ferdie};
use sp_runtime::{
    traits::{Dispatchable, Hash as _, SignedExtension},
    transaction_validity::{TransactionPriority, ValidTransaction},
    BuildStorage, DispatchError, Perbill,
};

const FUND: Balance = 1_000_000_000_000;
const DELAYS: DelayTable<BlockNumber> = DelayTable {
    recovery: 5,
    standard: 50,
    long: 200,
};
const SUDO: Keyring = Alice;
const GUARDIAN: Keyring = Charlie;
const ENACTOR: Keyring = Dave;
/// The key the defenders rotate a stolen sudo key to.
const NEW_KEY: Keyring = Eve;
/// Preprod's session length.
const SESSION_SLOTS: u32 = 600;

fn acct(k: Keyring) -> AccountId {
    k.to_account_id()
}

fn ext_with(sudo_key: AccountId, guardian: Option<AccountId>) -> TestExternalities {
    ext_with_session(sudo_key, guardian, SESSION_SLOTS)
}

fn ext_with_session(
    sudo_key: AccountId,
    guardian: Option<AccountId>,
    slots_per_epoch: u32,
) -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (acct(Alice), FUND),
            (acct(Bob), FUND),
            (acct(Charlie), FUND),
            (acct(Dave), FUND),
            (treasury_account(), FUND),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");
    pallet_sudo::GenesisConfig::<Runtime> {
        key: Some(sudo_key),
    }
    .assimilate_storage(&mut storage)
    .expect("sudo genesis builds");
    pallet_sidechain::GenesisConfig::<Runtime> {
        slots_per_epoch: sidechain_slots::SlotsPerEpoch(slots_per_epoch),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("sidechain genesis builds");
    pallet_root_timelock::GenesisConfig::<Runtime> {
        delays: DELAYS,
        unguarded: guardian.is_none(),
        guardian,
    }
    .assimilate_storage(&mut storage)
    .expect("root-timelock genesis builds");
    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn new_test_ext() -> TestExternalities {
    ext_with(acct(SUDO), Some(acct(GUARDIAN)))
}

fn signed(who: Keyring, call: RuntimeCall) -> Result<(), DispatchError> {
    call.dispatch(RuntimeOrigin::signed(acct(who)))
        .map(|_| ())
        .map_err(|e| e.error)
}

fn call_filtered() -> DispatchError {
    frame_system::Error::<Runtime>::CallFiltered.into()
}

fn timelock_error(e: pallet_root_timelock::Error<Runtime>) -> DispatchError {
    e.into()
}

fn sudo(call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::Sudo(pallet_sudo::Call::sudo {
        call: Box::new(call),
    })
}

fn timelock(call: pallet_root_timelock::Call<Runtime>) -> RuntimeCall {
    RuntimeCall::RootTimelock(call)
}

fn schedule(call: RuntimeCall) -> TaskId {
    schedule_by(SUDO, call)
}

fn schedule_by(key: Keyring, call: RuntimeCall) -> TaskId {
    let id = pallet_root_timelock::NextTaskId::<Runtime>::get();
    assert_ok!(signed(key, sudo(schedule_call(call))));
    assert!(
        Tasks::<Runtime>::contains_key(id),
        "the sudo key could not schedule"
    );
    id
}

fn enact(id: TaskId, call: RuntimeCall) -> Result<(), DispatchError> {
    signed(
        ENACTOR,
        timelock(pallet_root_timelock::Call::enact {
            id,
            call: Box::new(call),
        }),
    )
}

fn task(id: TaskId) -> Task<Hash, BlockNumber> {
    Tasks::<Runtime>::get(id).expect("task is pending")
}

fn batch(calls: Vec<RuntimeCall>) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::batch { calls })
}

fn force_set_balance(who: AccountId, new_free: Balance) -> RuntimeCall {
    RuntimeCall::Balances(pallet_balances::Call::force_set_balance {
        who: who.into(),
        new_free,
    })
}

fn note_stalled(delay: BlockNumber, best: BlockNumber) -> RuntimeCall {
    RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled {
        delay,
        best_finalized_block_number: best,
    })
}

fn tee_disabled(disabled: bool) -> RuntimeCall {
    RuntimeCall::TeeAttestation(pallet_tee_attestation::Call::set_disabled { disabled })
}

fn debits_enabled(enabled: bool) -> RuntimeCall {
    RuntimeCall::Billing(pallet_billing::Call::governance_set_debits_enabled { enabled })
}

fn set_delay(class: CallClass, blocks: BlockNumber) -> RuntimeCall {
    timelock(pallet_root_timelock::Call::set_delay { class, blocks })
}

fn schedule_call(call: RuntimeCall) -> RuntimeCall {
    timelock(pallet_root_timelock::Call::schedule {
        call: Box::new(call),
    })
}

fn cancel_all() -> RuntimeCall {
    timelock(pallet_root_timelock::Call::cancel_all {})
}

/// The guardian's co-signature of `call`, given before the call runs.
fn approve(call: &RuntimeCall) -> RuntimeCall {
    timelock(pallet_root_timelock::Call::approve {
        call_hash: Some(BlakeTwo256::hash_of(call)),
    })
}

fn enact_approved(call: RuntimeCall) -> RuntimeCall {
    timelock(pallet_root_timelock::Call::enact_approved {
        call: Box::new(call),
    })
}

fn batch_all(calls: Vec<RuntimeCall>) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::batch_all { calls })
}

fn appoint(guardian: Option<AccountId>) -> RuntimeCall {
    timelock(pallet_root_timelock::Call::set_guardian { guardian })
}

fn set_key(new: AccountId) -> RuntimeCall {
    RuntimeCall::Sudo(pallet_sudo::Call::set_key { new: new.into() })
}

fn orinq(call: pallet_orinq_receipts::pallet::Call<Runtime>) -> RuntimeCall {
    RuntimeCall::OrinqReceipts(call)
}

fn bridge_scripts(tag: u8) -> RuntimeCall {
    RuntimeCall::NativeTokenManagement(
        pallet_native_token_management::Call::set_main_chain_scripts {
            native_token_policy_id: PolicyId([tag; 28]),
            native_token_asset_name: AssetName::default(),
            illiquid_supply_validator_address: MainchainAddress::default(),
        },
    )
}

fn min_signer_threshold(new_threshold: u32) -> RuntimeCall {
    RuntimeCall::IntentSettlement(pallet_intent_settlement::Call::set_min_signer_threshold {
        new_threshold,
    })
}

fn dispatch_as_root(call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::dispatch_as {
        as_origin: Box::new(frame_system::RawOrigin::Root.into()),
        call: Box::new(call),
    })
}

fn with_weight(call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::with_weight {
        call: Box::new(call),
        weight: Weight::zero(),
    })
}

fn remark() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
}

fn pinned_member(tag: u8) -> PinnedMember {
    PinnedMember {
        cross_chain: [2; 33],
        aura: [tag; 32],
        grandpa: [tag; 32],
    }
}

fn pin(tag: u8) -> RuntimeCall {
    orinq(pallet_orinq_receipts::pallet::Call::set_pinned_committee {
        members: vec![pinned_member(tag)],
        until_epoch: u64::MAX,
    })
}

fn break_glass_keys(tag: u8) -> RuntimeCall {
    orinq(
        pallet_orinq_receipts::pallet::Call::set_break_glass_aura_keys {
            keys: vec![[tag; 32]],
        },
    )
}

fn authorize_upgrade(tag: u8) -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::authorize_upgrade {
        code_hash: Hash::repeat_byte(tag),
    })
}

/// Reads a `StorageValue` its pallet keeps private, by its raw key.
fn private_value<V: parity_scale_codec::Decode>(pallet: &[u8], item: &[u8]) -> Option<V> {
    unhashed::get(&frame_support::storage::storage_prefix(pallet, item))
}

fn sudo_key() -> Option<AccountId> {
    private_value(b"Sudo", b"Key")
}

#[test]
fn sudo_cannot_force_set_balance_immediately() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            signed(SUDO, sudo(force_set_balance(acct(Bob), 1))),
            Err(call_filtered())
        );
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
    });
}

#[test]
fn no_direct_sudo_form_reaches_root_for_a_non_exempt_call() {
    new_test_ext().execute_with(|| {
        let mint = || force_set_balance(acct(Bob), 1);
        let attempts = vec![
            RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                call: Box::new(mint()),
                weight: Weight::zero(),
            }),
            RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
                who: acct(Bob).into(),
                call: Box::new(RuntimeCall::Balances(
                    pallet_balances::Call::transfer_allow_death {
                        dest: acct(Alice).into(),
                        value: 1,
                    },
                )),
            }),
            set_key(acct(Bob)),
            RuntimeCall::Sudo(pallet_sudo::Call::remove_key {}),
            // An exempt call cannot carry a non-exempt one past the gate.
            sudo(batch(vec![note_stalled(30, 1), mint()])),
            sudo(RuntimeCall::Utility(pallet_utility::Call::batch_all {
                calls: vec![mint()],
            })),
            sudo(RuntimeCall::Utility(pallet_utility::Call::force_batch {
                calls: vec![mint()],
            })),
            sudo(dispatch_as_root(mint())),
            sudo(with_weight(mint())),
            sudo(sudo(mint())),
            sudo(RuntimeCall::Recovery(
                pallet_recovery::Call::set_recovered {
                    lost: acct(Bob).into(),
                    rescuer: acct(Alice).into(),
                },
            )),
            sudo(appoint(Some(acct(Alice)))),
            sudo(timelock(pallet_root_timelock::Call::cancel { id: 0 })),
            sudo(timelock(pallet_root_timelock::Call::fast_track { id: 0 })),
            sudo(approve(&mint())),
        ];
        for call in attempts {
            assert_eq!(signed(SUDO, call.clone()), Err(call_filtered()), "{call:?}");
        }
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
        assert_eq!(sudo_key(), Some(acct(Alice)));
    });
}

#[test]
fn every_root_gated_call_waits_unless_exempt() {
    new_test_ext().execute_with(|| {
        let zero = || acct(Bob);
        let root_calls = vec![
            RuntimeCall::System(frame_system::Call::set_heap_pages { pages: 64 }),
            RuntimeCall::System(frame_system::Call::set_code { code: vec![1] }),
            RuntimeCall::System(frame_system::Call::set_code_without_checks { code: vec![1] }),
            RuntimeCall::System(frame_system::Call::set_storage { items: vec![] }),
            RuntimeCall::System(frame_system::Call::kill_storage { keys: vec![] }),
            RuntimeCall::System(frame_system::Call::kill_prefix {
                prefix: vec![],
                subkeys: 0,
            }),
            RuntimeCall::System(frame_system::Call::authorize_upgrade {
                code_hash: Hash::zero(),
            }),
            RuntimeCall::System(frame_system::Call::authorize_upgrade_without_checks {
                code_hash: Hash::zero(),
            }),
            RuntimeCall::Balances(pallet_balances::Call::force_transfer {
                source: treasury_account().into(),
                dest: zero().into(),
                value: 1,
            }),
            force_set_balance(zero(), 1),
            RuntimeCall::Balances(pallet_balances::Call::force_unreserve {
                who: zero().into(),
                amount: 1,
            }),
            RuntimeCall::Treasury(pallet_treasury::Call::spend_local {
                amount: 1,
                beneficiary: zero().into(),
            }),
            RuntimeCall::Treasury(pallet_treasury::Call::spend {
                asset_kind: Box::new(()),
                amount: 1,
                beneficiary: Box::new(zero()),
                valid_from: None,
            }),
            RuntimeCall::Vesting(pallet_vesting::Call::force_remove_vesting_schedule {
                target: zero().into(),
                schedule_index: 0,
            }),
            RuntimeCall::Recovery(pallet_recovery::Call::set_recovered {
                lost: zero().into(),
                rescuer: zero().into(),
            }),
            RuntimeCall::Motra(pallet_motra::Call::set_params {
                params: Default::default(),
            }),
            orinq(pallet_orinq_receipts::pallet::Call::set_availability_cert {
                receipt_id: Hash::zero(),
                cert_hash: [0; 32],
            }),
            orinq(pallet_orinq_receipts::pallet::Call::set_committee {
                members: vec![],
                threshold: 1,
            }),
            orinq(pallet_orinq_receipts::pallet::Call::join_committee { member: zero() }),
            orinq(pallet_orinq_receipts::pallet::Call::leave_committee { member: zero() }),
            orinq(pallet_orinq_receipts::pallet::Call::set_bond_requirement { value: 0 }),
            orinq(pallet_orinq_receipts::pallet::Call::set_pinned_committee {
                members: vec![],
                until_epoch: 0,
            }),
            orinq(pallet_orinq_receipts::pallet::Call::clear_pinned_committee {}),
            orinq(
                pallet_orinq_receipts::pallet::Call::set_break_glass_floor_enabled {
                    enabled: true,
                },
            ),
            orinq(
                pallet_orinq_receipts::pallet::Call::set_core_eviction_enabled { enabled: false },
            ),
            orinq(pallet_orinq_receipts::pallet::Call::reset_candidate_liveness { who: zero() }),
            RuntimeCall::SessionCommitteeManagement(
                pallet_session_validator_management::Call::set_main_chain_scripts {
                    committee_candidate_address: MainchainAddress::default(),
                    d_parameter_policy_id: PolicyId::default(),
                    permissioned_candidates_policy_id: PolicyId::default(),
                },
            ),
            bridge_scripts(0),
            min_signer_threshold(1),
            tee_disabled(false),
            debits_enabled(true),
            RuntimeCall::Billing(pallet_billing::Call::governance_set_endpoint_price {
                endpoint_class: b"x".to_vec(),
                model: pallet_billing::types::PricingModel::FREE,
            }),
            set_delay(CallClass::Standard, DELAYS.standard - 1),
            set_delay(CallClass::Standard, DELAYS.standard + 1),
            note_stalled(MAX_EXEMPT_STALL_DELAY + 1, 1),
            note_stalled(1_000_000_000, 1),
        ];
        for call in root_calls {
            assert_eq!(
                signed(SUDO, sudo(call.clone())),
                Err(call_filtered()),
                "{call:?}"
            );
        }
    });
}

#[test]
fn relayed_signed_paths_meet_the_same_gate() {
    let mut signatories = vec![acct(Alice), acct(Bob)];
    signatories.sort();
    let multisig = pallet_multisig::Pallet::<Runtime>::multi_account_id(&signatories, 1);
    ext_with(multisig, Some(acct(GUARDIAN))).execute_with(|| {
        let res = signed(
            Alice,
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![acct(Bob)],
                call: Box::new(sudo(force_set_balance(acct(Bob), 1))),
            }),
        );
        assert_eq!(res, Err(call_filtered()));
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);

        // The same multisig schedules the call instead.
        let mint = force_set_balance(acct(Bob), 1);
        assert_ok!(signed(
            Alice,
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![acct(Bob)],
                call: Box::new(sudo(schedule_call(mint.clone()))),
            })
        ));
        assert_eq!(task(0).call_hash, BlakeTwo256::hash_of(&mint));
    });

    new_test_ext().execute_with(|| {
        // The batch is admitted; the sudo inside it is refused.
        assert_ok!(signed(
            SUDO,
            batch(vec![sudo(force_set_balance(acct(Bob), 1))])
        ));
        System::assert_last_event(
            pallet_utility::Event::BatchInterrupted {
                index: 0,
                error: call_filtered(),
            }
            .into(),
        );

        // A rescuer holding the sudo account through pallet-recovery is held
        // to the same gate as the key itself.
        pallet_recovery::Proxy::<Runtime>::insert(acct(Bob), acct(SUDO));
        let res = signed(
            Bob,
            RuntimeCall::Recovery(pallet_recovery::Call::as_recovered {
                account: acct(SUDO).into(),
                call: Box::new(sudo(force_set_balance(acct(Bob), 1))),
            }),
        );
        assert_eq!(res, Err(call_filtered()));
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
    });
}

#[test]
fn a_scheduled_call_executes_only_after_its_delay() {
    new_test_ext().execute_with(|| {
        let call = force_set_balance(acct(Bob), 1_000);
        let id = schedule(call.clone());
        assert_eq!(
            task(id),
            Task {
                call_hash: BlakeTwo256::hash_of(&call),
                class: CallClass::Standard,
                ready_at: 51,
                vetoable: true
            }
        );

        System::set_block_number(50);
        assert_eq!(
            enact(id, call.clone()),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);

        System::set_block_number(51);
        assert_ok!(enact(id, call));
        assert_eq!(Balances::free_balance(acct(Bob)), 1_000);
    });
}

#[test]
fn the_guardian_cancels_and_the_sudo_key_cannot() {
    new_test_ext().execute_with(|| {
        let call = force_set_balance(acct(Bob), 1);
        let id = schedule(call.clone());
        let cancel = || timelock(pallet_root_timelock::Call::cancel { id });

        assert_eq!(signed(SUDO, sudo(cancel())), Err(call_filtered()));
        assert_eq!(signed(SUDO, cancel()), Err(DispatchError::BadOrigin));
        assert_ok!(signed(GUARDIAN, cancel()));

        System::set_block_number(51);
        assert_eq!(
            enact(id, call),
            Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
        );
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
    });
}

#[test]
fn a_multisig_guardian_cancels_through_the_filter() {
    let mut signatories = vec![acct(Charlie), acct(Dave)];
    signatories.sort();
    let guardian = pallet_multisig::Pallet::<Runtime>::multi_account_id(&signatories, 1);
    ext_with(acct(SUDO), Some(guardian)).execute_with(|| {
        let id = schedule(force_set_balance(acct(Bob), 1));
        assert_ok!(signed(
            Charlie,
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![acct(Dave)],
                call: Box::new(timelock(pallet_root_timelock::Call::cancel { id })),
            })
        ));
        assert!(!Tasks::<Runtime>::contains_key(id));
    });
}

#[test]
fn exempt_calls_work_immediately() {
    new_test_ext().execute_with(|| {
        assert_ok!(signed(SUDO, sudo(note_stalled(30, 7))));
        assert_eq!(Grandpa::stalled(), Some((30, 7)));
        assert_ok!(signed(SUDO, sudo(note_stalled(MAX_EXEMPT_STALL_DELAY, 7))));
        assert_eq!(Grandpa::stalled(), Some((MAX_EXEMPT_STALL_DELAY, 7)));

        // Kill-switches: the stopping direction is immediate, the other waits.
        assert_eq!(
            signed(SUDO, sudo(tee_disabled(false))),
            Err(call_filtered())
        );
        assert_eq!(
            signed(SUDO, sudo(debits_enabled(true))),
            Err(call_filtered())
        );
        let restart = batch(vec![tee_disabled(false), debits_enabled(true)]);
        let id = schedule(restart.clone());
        System::set_block_number(51);
        assert_ok!(enact(id, restart));
        assert!(!pallet_tee_attestation::Disabled::<Runtime>::get());
        assert!(pallet_billing::DebitsEnabled::<Runtime>::get());
        assert_ok!(signed(
            SUDO,
            sudo(batch(vec![tee_disabled(true), debits_enabled(false)]))
        ));
        assert!(pallet_tee_attestation::Disabled::<Runtime>::get());
        assert!(!pallet_billing::DebitsEnabled::<Runtime>::get());

        // Approved treasury spends can be withdrawn at once.
        let local = RuntimeCall::Treasury(pallet_treasury::Call::spend_local {
            amount: 1_000,
            beneficiary: acct(Bob).into(),
        });
        let asset = RuntimeCall::Treasury(pallet_treasury::Call::spend {
            asset_kind: Box::new(()),
            amount: 1_000,
            beneficiary: Box::new(acct(Bob)),
            valid_from: None,
        });
        let both = batch(vec![local, asset]);
        let id = schedule(both.clone());
        System::set_block_number(101);
        assert_ok!(enact(id, both));
        assert_eq!(
            pallet_treasury::Approvals::<Runtime>::get().into_inner(),
            vec![0]
        );
        assert!(pallet_treasury::Spends::<Runtime>::contains_key(0));
        assert_ok!(signed(
            SUDO,
            sudo(batch(vec![
                RuntimeCall::Treasury(pallet_treasury::Call::remove_approval { proposal_id: 0 }),
                RuntimeCall::Treasury(pallet_treasury::Call::void_spend { index: 0 }),
            ]))
        ));
        assert!(pallet_treasury::Approvals::<Runtime>::get().is_empty());
        assert!(!pallet_treasury::Spends::<Runtime>::contains_key(0));
    });
}

#[test]
fn a_delay_change_waits_and_only_a_raise_can_be_co_signed() {
    new_test_ext().execute_with(|| {
        let fast_track = |id| {
            signed(
                GUARDIAN,
                timelock(pallet_root_timelock::Call::fast_track { id }),
            )
        };
        for change in [
            set_delay(CallClass::Standard, 10),
            set_delay(CallClass::Standard, 60),
        ] {
            assert_eq!(signed(SUDO, sudo(change)), Err(call_filtered()));
        }

        // A raise waits the recovery delay, and the guardian may co-sign it.
        let raise = set_delay(CallClass::Standard, 60);
        let alone = schedule(raise.clone());
        assert_eq!(
            (task(alone).class, task(alone).ready_at),
            (CallClass::Recovery, 1 + DELAYS.recovery)
        );
        let smaller_raise = set_delay(CallClass::Standard, 55);
        let stale = schedule(smaller_raise.clone());
        let co_signed = schedule(raise.clone());
        assert_ok!(fast_track(co_signed));
        assert_ok!(enact(co_signed, raise.clone()));
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get().standard, 60);
        // A raise that has since become a lowering cannot run.
        System::set_block_number(1 + DELAYS.recovery);
        assert_eq!(
            enact(stale, smaller_raise),
            Err(timelock_error(pallet_root_timelock::Error::ClassRaised))
        );
        assert_ok!(enact(alone, raise));

        // A lowering waits the delay it lowers.
        let now = System::block_number();
        let lower = set_delay(CallClass::Standard, 10);
        let id = schedule(lower.clone());
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::Standard, now + 60)
        );
        System::set_block_number(now + 59);
        assert_eq!(
            enact(id, lower.clone()),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
        System::set_block_number(now + 60);
        assert_ok!(enact(id, lower));
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get().standard, 10);

        let now = System::block_number();
        let id = schedule(set_delay(CallClass::Long, 100));
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::Long, now + 200)
        );

        // Lowering the recovery delay waits the standard delay and the
        // guardian cannot fast-track it.
        let id = schedule(set_delay(CallClass::Recovery, 1));
        assert_eq!(task(id).class, CallClass::Standard);
        assert_eq!(
            fast_track(id),
            Err(timelock_error(
                pallet_root_timelock::Error::NotFastTrackable
            ))
        );

        // A raise is bounded, even with the guardian's co-sign.
        let past_max = set_delay(CallClass::Long, RootTimelockMaxDelay::get() + 1);
        let id = schedule(past_max.clone());
        assert_ok!(fast_track(id));
        assert_eq!(
            enact(id, past_max),
            Err(timelock_error(pallet_root_timelock::Error::InvalidDelays))
        );
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get().long, 200);
    });
}

#[test]
fn a_runtime_upgrade_goes_through_the_delay() {
    new_test_ext().execute_with(|| {
        let code_hash = Hash::repeat_byte(7);
        let authorize = RuntimeCall::System(frame_system::Call::authorize_upgrade { code_hash });
        let set_code = |code: Vec<u8>| {
            RuntimeCall::System(frame_system::Call::set_code_without_checks { code })
        };
        assert_eq!(signed(SUDO, sudo(authorize.clone())), Err(call_filtered()));
        assert_eq!(
            signed(
                SUDO,
                sudo(RuntimeCall::System(frame_system::Call::set_code {
                    code: vec![1]
                }))
            ),
            Err(call_filtered())
        );
        assert_eq!(signed(SUDO, sudo(set_code(vec![1]))), Err(call_filtered()));

        let authorized = schedule(authorize.clone());
        let code = b"stand-in runtime".to_vec();
        let direct = schedule(set_code(code.clone()));
        System::set_block_number(50);
        assert_eq!(
            enact(authorized, authorize.clone()),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
        assert_eq!(
            private_value::<(Hash, bool)>(b"System", b"AuthorizedUpgrade"),
            None
        );

        System::set_block_number(51);
        assert_ok!(enact(authorized, authorize));
        assert_eq!(
            private_value::<(Hash, bool)>(b"System", b"AuthorizedUpgrade"),
            Some((code_hash, true))
        );
        assert_ok!(enact(direct, set_code(code.clone())));
        assert_eq!(
            sp_io::storage::get(sp_core::storage::well_known_keys::CODE).map(|c| c.to_vec()),
            Some(code)
        );
    });
}

#[test]
fn the_upgrade_ceremony_schedules_the_authorization_and_applies_unsigned() {
    new_test_ext().execute_with(|| {
        let code = b"next runtime".to_vec();
        let authorize = RuntimeCall::System(frame_system::Call::authorize_upgrade_without_checks {
            code_hash: BlakeTwo256::hash(&code),
        });
        let apply = || {
            RuntimeCall::System(frame_system::Call::apply_authorized_upgrade { code: code.clone() })
                .dispatch(RuntimeOrigin::none())
                .map(|_| ())
                .map_err(|e| e.error)
        };

        let id = schedule(authorize.clone());
        assert_eq!(
            apply(),
            Err(frame_system::Error::<Runtime>::NothingAuthorized.into())
        );
        System::set_block_number(1 + DELAYS.standard);
        assert_ok!(enact(id, authorize));
        assert_ok!(apply());
        assert_eq!(
            sp_io::storage::get(sp_core::storage::well_known_keys::CODE).map(|c| c.to_vec()),
            Some(code)
        );
    });
}

#[test]
fn recovery_levers_wait_the_short_delay_or_a_guardian_cosign() {
    new_test_ext().execute_with(|| {
        let lever =
            orinq(pallet_orinq_receipts::pallet::Call::set_core_eviction_enabled { enabled: true });
        assert_eq!(signed(SUDO, sudo(lever.clone())), Err(call_filtered()));

        let alone = schedule(lever.clone());
        assert_eq!(
            (task(alone).class, task(alone).ready_at),
            (CallClass::Recovery, 1 + DELAYS.recovery)
        );
        let cosigned = schedule(lever.clone());
        assert_eq!(
            enact(cosigned, lever.clone()),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
        assert_ok!(signed(
            GUARDIAN,
            timelock(pallet_root_timelock::Call::fast_track { id: cosigned })
        ));
        assert_ok!(enact(cosigned, lever));
        assert!(pallet_orinq_receipts::CoreEvictionEnabled::<Runtime>::get());
    });
}

#[test]
fn calls_are_classified_by_what_they_can_change() {
    new_test_ext().execute_with(|| {
        use CallClass::*;
        pallet_intent_settlement::MinSignerThreshold::<Runtime>::put(3);
        let mint = || force_set_balance(acct(Bob), 1);
        let cases = vec![
            (note_stalled(1, 1), Recovery),
            (note_stalled(MAX_EXEMPT_STALL_DELAY, 1), Recovery),
            // A stall longer than the exempt bound can hold a GRANDPA change
            // across a session boundary, freezing rotation.
            (
                note_stalled(MAX_EXEMPT_STALL_DELAY + 1, 1),
                AuthorityRecovery,
            ),
            // Levers that name consensus keys.
            (pin(1), AuthorityRecovery),
            (break_glass_keys(1), AuthorityRecovery),
            (
                orinq(pallet_orinq_receipts::pallet::Call::clear_pinned_committee {}),
                Recovery,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::set_break_glass_floor_enabled {
                        enabled: false,
                    },
                ),
                Recovery,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::set_core_eviction_enabled {
                        enabled: true,
                    },
                ),
                Recovery,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::set_contribution_window_enabled {
                        enabled: true,
                    },
                ),
                Recovery,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::set_slack_invariant_enabled {
                        enabled: true,
                    },
                ),
                Recovery,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::reset_candidate_liveness {
                        who: acct(Bob),
                    },
                ),
                Recovery,
            ),
            (mint(), Standard),
            // The attestation committee, which intent-settlement's deposit
            // attestations count, and the emission rates wait the standard
            // delay: `set_code` subsumes every lever, so the standard delay
            // and the guardian's veto are the bound against a stolen key, and
            // the long class binds only the dedicated levers.
            (
                orinq(pallet_orinq_receipts::pallet::Call::set_committee {
                    members: vec![acct(Bob)],
                    threshold: 1,
                }),
                Standard,
            ),
            (
                orinq(pallet_orinq_receipts::pallet::Call::join_committee { member: acct(Bob) }),
                Standard,
            ),
            (
                orinq(
                    pallet_orinq_receipts::pallet::Call::set_attestation_reward_per_signer {
                        value: u128::MAX,
                    },
                ),
                Standard,
            ),
            (
                RuntimeCall::System(frame_system::Call::set_code { code: vec![] }),
                Standard,
            ),
            (
                RuntimeCall::System(frame_system::Call::authorize_upgrade {
                    code_hash: Hash::zero(),
                }),
                Standard,
            ),
            // The guardian's co-signature rotates a stolen key before any
            // change the key scheduled can land.
            (set_key(acct(Bob)), AuthorityRecovery),
            (
                RuntimeCall::Recovery(pallet_recovery::Call::set_recovered {
                    lost: acct(Bob).into(),
                    rescuer: acct(Alice).into(),
                }),
                Standard,
            ),
            (set_delay(Standard, 1), Standard),
            (set_delay(Recovery, 1), Standard),
            // A raise, or keeping a delay, only slows Root down.
            (set_delay(Recovery, DELAYS.recovery), Recovery),
            (set_delay(Standard, DELAYS.standard + 1), Recovery),
            (set_delay(Long, RootTimelockMaxDelay::get()), Recovery),
            // Restarting what a kill-switch stopped lands the same day only
            // with the guardian's co-sign. Stopping is exempt; scheduled, it
            // waits like anything else.
            (tee_disabled(false), AuthorityRecovery),
            (debits_enabled(true), AuthorityRecovery),
            (tee_disabled(true), Standard),
            (debits_enabled(false), Standard),
            (min_signer_threshold(4), Standard),
            (min_signer_threshold(3), Standard),
            (bridge_scripts(1), Long),
            (min_signer_threshold(2), Long),
            (min_signer_threshold(0), Long),
            (set_delay(Long, 1), Long),
            (appoint(None), Long),
            (RuntimeCall::Sudo(pallet_sudo::Call::remove_key {}), Long),
            // Wrappers carry the longest class inside them.
            (batch(vec![pin(1), pin(1)]), AuthorityRecovery),
            (batch(vec![note_stalled(1, 1), pin(1)]), AuthorityRecovery),
            (batch(vec![pin(1), mint()]), Standard),
            (batch(vec![remark(), bridge_scripts(1)]), Long),
            (
                RuntimeCall::Utility(pallet_utility::Call::force_batch {
                    calls: vec![pin(1), bridge_scripts(1)],
                }),
                Long,
            ),
            (sudo(bridge_scripts(1)), Long),
            (with_weight(bridge_scripts(1)), Long),
            (dispatch_as_root(bridge_scripts(1)), Long),
            // A changed origin is never a recovery call.
            (dispatch_as_root(pin(1)), Standard),
            (
                RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
                    who: acct(Bob).into(),
                    call: Box::new(pin(1)),
                }),
                Standard,
            ),
        ];
        for (call, class) in cases {
            assert_eq!(TimelockClassifier::class_of(&call), class, "{call:?}");
        }
    });
}

#[test]
fn a_threshold_raise_that_became_a_lowering_cannot_run() {
    new_test_ext().execute_with(|| {
        pallet_intent_settlement::MinSignerThreshold::<Runtime>::put(1);
        let set_two = min_signer_threshold(2);
        let id = schedule(set_two.clone());
        assert_eq!(task(id).class, CallClass::Standard);
        pallet_intent_settlement::MinSignerThreshold::<Runtime>::put(3);
        System::set_block_number(51);
        assert_eq!(
            enact(id, set_two),
            Err(timelock_error(pallet_root_timelock::Error::ClassRaised))
        );
    });
}

#[test]
fn replacing_the_guardian_waits_the_long_delay_and_cannot_be_vetoed() {
    new_test_ext().execute_with(|| {
        let replace = appoint(Some(acct(Bob)));
        let id = schedule(replace.clone());
        assert_eq!(
            (task(id).class, task(id).ready_at, task(id).vetoable),
            (CallClass::Long, 1 + DELAYS.long, false)
        );
        assert_eq!(
            signed(
                GUARDIAN,
                timelock(pallet_root_timelock::Call::cancel { id })
            ),
            Err(timelock_error(pallet_root_timelock::Error::NotVetoable))
        );
        System::set_block_number(1 + DELAYS.long);
        assert_ok!(enact(id, replace));
        assert_eq!(Guardian::<Runtime>::get(), Some(acct(Bob)));
    });
}

/// The inner result of the last `Sudo.sudo` dispatch.
fn last_sudo_result() -> Result<(), DispatchError> {
    System::events()
        .into_iter()
        .rev()
        .find_map(|record| match record.event {
            RuntimeEvent::Sudo(pallet_sudo::Event::Sudid { sudo_result }) => Some(sudo_result),
            _ => None,
        })
        .expect("a sudo call ran")
}

#[test]
fn a_guardian_change_is_scheduled_only_on_its_own() {
    new_test_ext().execute_with(|| {
        let replace = || appoint(Some(acct(Bob)));
        let wrapped = vec![
            batch(vec![replace()]),
            RuntimeCall::Utility(pallet_utility::Call::batch_all {
                calls: vec![remark(), replace()],
            }),
            RuntimeCall::Utility(pallet_utility::Call::force_batch {
                calls: vec![replace()],
            }),
            batch(vec![batch(vec![replace()])]),
            with_weight(replace()),
            dispatch_as_root(replace()),
            sudo(replace()),
        ];
        for call in wrapped {
            assert_ok!(signed(SUDO, sudo(schedule_call(call.clone()))));
            assert_eq!(
                last_sudo_result(),
                Err(timelock_error(
                    pallet_root_timelock::Error::GuardianChangeNotAlone
                )),
                "{call:?}"
            );
        }
        assert_eq!(Tasks::<Runtime>::iter().count(), 0);

        // On its own it is scheduled, and cannot be vetoed.
        let id = schedule(replace());
        assert!(!task(id).vetoable);
    });
}

#[test]
fn a_fast_track_never_extends_or_revives_a_task() {
    new_test_ext().execute_with(|| {
        let lever =
            orinq(pallet_orinq_receipts::pallet::Call::set_core_eviction_enabled { enabled: true });
        let fast_track = |id| {
            signed(
                GUARDIAN,
                timelock(pallet_root_timelock::Call::fast_track { id }),
            )
        };
        let id = schedule(lever.clone());
        let ready_at = 1 + DELAYS.recovery;

        System::set_block_number(ready_at);
        assert_eq!(
            fast_track(id),
            Err(timelock_error(pallet_root_timelock::Error::AlreadyReady))
        );

        let expired = ready_at + RootTimelockEnactmentWindow::get() + 1;
        System::set_block_number(expired);
        assert_eq!(
            fast_track(id),
            Err(timelock_error(pallet_root_timelock::Error::AlreadyReady))
        );
        assert_eq!(task(id).ready_at, ready_at);
        assert_eq!(
            enact(id, lever),
            Err(timelock_error(pallet_root_timelock::Error::Expired))
        );
        assert!(!pallet_orinq_receipts::CoreEvictionEnabled::<Runtime>::get());
    });
}

#[test]
fn one_extrinsic_cannot_flood_the_guardian() {
    new_test_ext().execute_with(|| {
        let cap = RootTimelockMaxPendingTasks::get();
        let mint = force_set_balance(acct(Bob), 1_000 * FUND);
        let schedule_mint = schedule_call(mint.clone());
        assert_ok!(signed(
            SUDO,
            sudo(batch(vec![schedule_mint; cap as usize + 10]))
        ));
        assert_eq!(Tasks::<Runtime>::count(), cap);
        System::assert_has_event(
            pallet_utility::Event::BatchInterrupted {
                index: cap,
                error: timelock_error(pallet_root_timelock::Error::TooManyTasks),
            }
            .into(),
        );

        let veto = timelock(pallet_root_timelock::Call::cancel_all {});
        assert_eq!(veto.get_dispatch_info().class, DispatchClass::Operational);
        assert_ok!(signed(GUARDIAN, veto));
        assert_eq!(Tasks::<Runtime>::count(), 0);

        System::set_block_number(1 + DELAYS.standard);
        for id in 0..cap {
            assert_eq!(
                enact(id, mint.clone()),
                Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
            );
        }
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
    });
}

/// Call trees paired with how many calls the classifier visits in each, the
/// root included. It reads storage to classify every stall.
fn call_trees() -> [(RuntimeCall, u64); 2] {
    let ten_stalls = batch(vec![note_stalled(1, 1); 10]);
    [
        (batch(vec![note_stalled(1, 1); 1_000]), 1_001),
        (
            with_weight(dispatch_as_root(batch_all(vec![ten_stalls; 100]))),
            3 + 100 + 1_000,
        ),
    ]
}

#[test]
fn the_timelock_charges_for_every_call_its_classifier_visits() {
    new_test_ext().execute_with(|| {
        let read = RuntimeDbWeight::get().reads(1).ref_time();
        for (call, visited) in call_trees() {
            let floor = visited * read;
            let scheduling = sudo(schedule_call(call.clone()));
            assert!(
                scheduling.get_dispatch_info().weight.ref_time() >= floor,
                "schedule of {visited} calls declares {:?}",
                scheduling.get_dispatch_info().weight
            );
            // The enactments add their overhead to the call's own weight,
            // which `with_weight` lets Root declare as zero.
            let own = call.get_dispatch_info().weight.ref_time();
            for enacting in [
                timelock(pallet_root_timelock::Call::enact {
                    id: 0,
                    call: Box::new(call.clone()),
                }),
                enact_approved(call.clone()),
            ] {
                let overhead = enacting.get_dispatch_info().weight.ref_time() - own;
                assert!(overhead >= floor, "{visited} calls, overhead {overhead} ps");
            }
        }
    });
}

#[test]
fn a_walk_too_long_for_a_block_is_refused_before_it_runs() {
    new_test_ext().execute_with(|| {
        let scheduling = sudo(schedule_call(batch(vec![note_stalled(1, 1); 100_000])));
        assert_eq!(
            frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
                &scheduling.get_dispatch_info(),
                scheduling.encoded_size(),
            ),
            Err(sp_runtime::transaction_validity::InvalidTransaction::ExhaustsResources.into())
        );
    });
}

/// The weight prices each call the classifier visits as one database read and
/// a step. Timed against reads of the same state in the same run, so neither
/// the build profile nor the machine's load decides the outcome.
#[test]
fn classifying_costs_at_most_two_reads_per_call_visited() {
    new_test_ext().execute_with(|| {
        let visited = 10_001;
        let stalls = batch(vec![note_stalled(1, 1); visited - 1]);
        let timed = |run: &dyn Fn()| {
            let started = std::time::Instant::now();
            run();
            started.elapsed()
        };
        let (mut reads, mut walk) = (std::time::Duration::MAX, std::time::Duration::MAX);
        for _ in 0..5 {
            reads = reads.min(timed(&|| {
                for _ in 0..visited {
                    core::hint::black_box(Sidechain::slots_per_epoch());
                }
            }));
            walk = walk.min(timed(&|| {
                core::hint::black_box(TimelockClassifier::class_of(&stalls));
                core::hint::black_box(TimelockClassifier::wraps_guardian_change(&stalls));
            }));
        }
        assert!(
            walk <= 2 * reads,
            "{walk:?} to classify {visited} calls, {reads:?} to read once per call"
        );
    });
}

/// The session keys `select_authorities` would install for the next epoch.
fn next_committee() -> Option<Vec<opaque::SessionKeys>> {
    <Runtime as pallet_session_validator_management::Config>::select_authorities(
        AuthoritySelectionInputs {
            d_parameter: DParameter {
                num_permissioned_candidates: 0,
                num_registered_candidates: 0,
            },
            permissioned_candidates: vec![],
            registered_candidates: vec![],
            epoch_nonce: EpochNonce(vec![7; 32]),
        },
        ScEpochNumber(1),
    )
    .map(|committee| committee.into_iter().map(|(_, keys)| keys).collect())
}

fn pinned_keys(tag: u8) -> Vec<opaque::SessionKeys> {
    vec![(
        sp_core::sr25519::Public::from_raw([tag; 32]),
        sp_core::ed25519::Public::from_raw([tag; 32]),
    )
        .into()]
}

#[test]
fn a_pinned_committee_waits_the_standard_delay_unless_the_guardian_co_signs() {
    new_test_ext().execute_with(|| {
        assert_eq!(next_committee(), None);
        let installs = [pin(0xAA), break_glass_keys(0xAA)];
        let alone: Vec<TaskId> = installs.iter().map(|call| schedule(call.clone())).collect();
        for id in &alone {
            assert_eq!(
                (task(*id).class, task(*id).ready_at),
                (CallClass::AuthorityRecovery, 1 + DELAYS.standard)
            );
        }

        // The recovery delay alone no longer installs anyone.
        System::set_block_number(1 + DELAYS.recovery);
        for (id, call) in alone.iter().zip(&installs) {
            assert_eq!(
                enact(*id, call.clone()),
                Err(timelock_error(pallet_root_timelock::Error::NotReady))
            );
        }
        assert_eq!(next_committee(), None);

        // A guardian co-signature installs at once.
        let co_signed = schedule(pin(0xBB));
        assert_ok!(signed(
            GUARDIAN,
            timelock(pallet_root_timelock::Call::fast_track { id: co_signed })
        ));
        assert_ok!(enact(co_signed, pin(0xBB)));
        assert_eq!(next_committee(), Some(pinned_keys(0xBB)));

        // Without one, the standard delay.
        System::set_block_number(1 + DELAYS.standard);
        for (id, call) in alone.iter().zip(&installs) {
            assert_ok!(enact(*id, call.clone()));
        }
        assert_eq!(next_committee(), Some(pinned_keys(0xAA)));
    });
}

#[test]
fn without_a_guardian_the_sudo_key_withdraws_a_task() {
    ext_with(acct(SUDO), None).execute_with(|| {
        let abandoned = schedule(authorize_upgrade(0xA));
        let superseded = schedule(authorize_upgrade(0xB));
        assert_ok!(signed(
            SUDO,
            sudo(timelock(pallet_root_timelock::Call::cancel {
                id: abandoned
            }))
        ));
        assert_ok!(signed(
            SUDO,
            sudo(timelock(pallet_root_timelock::Call::cancel_all {}))
        ));
        System::set_block_number(1 + DELAYS.standard);
        for (id, tag) in [(abandoned, 0xA), (superseded, 0xB)] {
            assert_eq!(
                enact(id, authorize_upgrade(tag)),
                Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
            );
        }
        assert_eq!(
            private_value::<(Hash, bool)>(b"System", b"AuthorizedUpgrade"),
            None
        );

        // The sudo key withdraws a guardian appointment too. Once one lands
        // its veto ends, except over a pending guardian change.
        let appoint = appoint(Some(acct(GUARDIAN)));
        let withdrawn = schedule(appoint.clone());
        assert_ok!(signed(
            SUDO,
            sudo(timelock(pallet_root_timelock::Call::cancel {
                id: withdrawn
            }))
        ));
        assert_eq!(last_sudo_result(), Ok(()));
        assert!(!Tasks::<Runtime>::contains_key(withdrawn));
        let id = schedule(appoint.clone());
        System::set_block_number(task(id).ready_at);
        assert_ok!(enact(id, appoint));
        let later = schedule(authorize_upgrade(0xC));
        assert_eq!(
            signed(
                SUDO,
                sudo(timelock(pallet_root_timelock::Call::cancel { id: later }))
            ),
            Err(call_filtered())
        );
        assert_eq!(
            signed(
                SUDO,
                sudo(timelock(pallet_root_timelock::Call::cancel_all {}))
            ),
            Err(call_filtered())
        );
    });
}

/// Hands GRANDPA a new validator set at `block`, as a session change does.
fn grandpa_session(block: BlockNumber, seed: u8) {
    System::set_block_number(block);
    let validators: Vec<(AccountId, pallet_grandpa::AuthorityId)> = (0..3u8)
        .map(|i| {
            let byte = seed.wrapping_add(i);
            (
                AccountId::from([byte; 32]),
                sp_core::ed25519::Public::from_raw([byte; 32]).into(),
            )
        })
        .collect();
    let keys = || validators.iter().map(|(who, key)| (who, key.clone()));
    <Grandpa as OneSessionHandler<AccountId>>::on_new_session(true, keys(), keys());
    <Grandpa as Hooks<BlockNumber>>::on_finalize(block);
}

fn finalize_blocks(from: BlockNumber, to: BlockNumber) {
    for block in from..=to {
        System::set_block_number(block);
        <Grandpa as Hooks<BlockNumber>>::on_finalize(block);
    }
}

#[test]
fn an_exempt_stall_never_freezes_grandpa_rotation() {
    for slots in [60, 200, SESSION_SLOTS] {
        // Sessions with a block in every slot, and with half, three
        // quarters and nine tenths of the slots empty.
        for session in [slots, slots / 2, slots / 4, slots / 10] {
            ext_with_session(acct(SUDO), Some(acct(GUARDIAN)), slots).execute_with(|| {
                let stall = max_exempt_stall_delay();
                let mut block = 10;
                for seed in [10u8, 40, 70] {
                    // The longest exempt stall, fired before every boundary.
                    assert_ok!(signed(SUDO, sudo(note_stalled(stall, block - 1))));
                    let set_id = Grandpa::current_set_id();
                    grandpa_session(block, seed);
                    assert_eq!(
                        Grandpa::current_set_id(),
                        set_id + 1,
                        "{slots}-slot sessions of {session} blocks"
                    );
                    finalize_blocks(block + 1, block + session - 1);
                    assert_eq!(Grandpa::pending_change().map(|change| change.delay), None);
                    block += session;
                }
                let set_id = Grandpa::current_set_id();
                grandpa_session(block, 100);
                assert_eq!(Grandpa::current_set_id(), set_id + 1);
            });
        }
    }
}

#[test]
fn the_exempt_stall_bound_follows_the_session_length() {
    for (slots, bound) in [(SESSION_SLOTS, MAX_EXEMPT_STALL_DELAY), (200, 10), (60, 3)] {
        ext_with_session(acct(SUDO), Some(acct(GUARDIAN)), slots).execute_with(|| {
            assert_eq!(max_exempt_stall_delay(), bound, "{slots}-slot sessions");
            assert_eq!(
                signed(SUDO, sudo(note_stalled(bound + 1, 7))),
                Err(call_filtered())
            );
            assert_ok!(signed(SUDO, sudo(note_stalled(bound, 7))));
            assert_eq!(
                TimelockClassifier::class_of(&note_stalled(bound, 1)),
                CallClass::Recovery
            );
            assert_eq!(
                TimelockClassifier::class_of(&note_stalled(bound + 1, 1)),
                CallClass::AuthorityRecovery
            );
        });
    }
}

#[test]
fn a_stall_beyond_the_exempt_bound_waits_like_a_key_change() {
    new_test_ext().execute_with(|| {
        for delay in [MAX_EXEMPT_STALL_DELAY + 1, 1_000_000_000] {
            assert_eq!(
                signed(SUDO, sudo(note_stalled(delay, 1))),
                Err(call_filtered())
            );
        }
        assert_eq!(Grandpa::stalled(), None);
        let long_stall = note_stalled(1_000, 1);
        let id = schedule(long_stall.clone());
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::AuthorityRecovery, 1 + DELAYS.standard)
        );
        System::set_block_number(1 + DELAYS.recovery);
        assert_eq!(
            enact(id, long_stall),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
    });
}

#[test]
fn recovery_admin_calls_are_behind_the_delay() {
    new_test_ext().execute_with(|| {
        let hand_over = RuntimeCall::Recovery(pallet_recovery::Call::set_recovered {
            lost: acct(Bob).into(),
            rescuer: acct(Dave).into(),
        });
        assert_eq!(signed(SUDO, sudo(hand_over.clone())), Err(call_filtered()));
        let id = schedule(hand_over.clone());
        System::set_block_number(51);
        assert_ok!(enact(id, hand_over));
        assert_eq!(
            pallet_recovery::Proxy::<Runtime>::get(acct(Dave)),
            Some(acct(Bob))
        );
    });
}

#[test]
fn treasury_spends_in_one_enactment_are_bounded() {
    new_test_ext().execute_with(|| {
        // 15,000 MATRA at 6 decimals.
        assert_eq!(MaxSpend::get(), 15_000 * 1_000_000);
        let spend = |amount| {
            RuntimeCall::Treasury(pallet_treasury::Call::spend_local {
                amount,
                beneficiary: acct(Bob).into(),
            })
        };
        let over_cap = || -> Result<(), DispatchError> {
            Err(pallet_treasury::Error::<Runtime>::InsufficientPermission.into())
        };

        let over = spend(MaxSpend::get() + 1);
        // The cap covers the sum approved inside one enactment, so a batch
        // cannot split a larger spend across calls that each fit.
        let half = MaxSpend::get() / 2 + 1;
        let split = RuntimeCall::Utility(pallet_utility::Call::batch_all {
            calls: vec![spend(half), spend(half)],
        });
        let split_leniently = batch(vec![spend(half), spend(half)]);
        let at_cap = spend(MaxSpend::get());
        let ids: Vec<TaskId> = [&over, &split, &split_leniently, &at_cap]
            .into_iter()
            .map(|call| schedule(call.clone()))
            .collect();

        System::set_block_number(1 + DELAYS.standard);
        assert_eq!(enact(ids[0], over), over_cap());
        assert_eq!(enact(ids[1], split), over_cap());
        assert!(pallet_treasury::Approvals::<Runtime>::get().is_empty());

        assert_ok!(enact(ids[2], split_leniently));
        System::assert_has_event(
            pallet_utility::Event::BatchInterrupted {
                index: 1,
                error: over_cap().unwrap_err(),
            }
            .into(),
        );
        assert_eq!(pallet_treasury::Approvals::<Runtime>::get().len(), 1);

        assert_ok!(enact(ids[3], at_cap));
        assert_eq!(pallet_treasury::Approvals::<Runtime>::get().len(), 2);
    });
}

#[test]
fn mainnet_defaults() {
    assert_eq!(
        RootTimelockDefaultDelays::get(),
        DelayTable {
            recovery: DAYS,
            standard: 7 * DAYS,
            long: 30 * DAYS
        }
    );
    assert_eq!(RootTimelockMaxDelay::get(), 90 * DAYS);
    assert_eq!(RootTimelockEnactmentWindow::get(), 7 * DAYS);
    assert_eq!(RootTimelockMaxPendingTasks::get(), 64);
    assert_eq!(MAX_EXEMPT_STALL_DELAY, 30);
    assert!(TESTNET_TIMELOCK_DELAYS.is_valid(RootTimelockMaxDelay::get()));
}

/// The launch preflight reads the mainnet delays and their ceiling from the
/// runtime metadata, which is all it has of the runtime.
#[test]
fn metadata_declares_the_mainnet_delays_and_their_ceiling() {
    let pallet = Runtime::metadata_ir()
        .pallets
        .into_iter()
        .find(|pallet| pallet.name == "RootTimelock")
        .expect("RootTimelock is in the metadata");
    let constant = |name: &str| {
        pallet
            .constants
            .iter()
            .find(|constant| constant.name == name)
            .map(|constant| constant.value.clone())
    };
    assert_eq!(
        constant("DefaultDelays"),
        Some(RootTimelockDefaultDelays::get().encode())
    );
    assert_eq!(
        constant("MaxDelay"),
        Some(RootTimelockMaxDelay::get().encode())
    );
}

fn bare_ext() -> TestExternalities {
    frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds")
        .into()
}

#[test]
fn preprod_gets_the_testnet_delays_on_upgrade() {
    bare_ext().execute_with(|| {
        frame_system::BlockHash::<Runtime>::insert(0, PREPROD_GENESIS_HASH);
        assert!(!pallet_root_timelock::Delays::<Runtime>::exists());
        InitRootTimelock::on_runtime_upgrade();
        assert_eq!(
            pallet_root_timelock::Delays::<Runtime>::get(),
            TESTNET_TIMELOCK_DELAYS
        );
        assert!(pallet_root_timelock::Delays::<Runtime>::exists());
    });
}

#[test]
fn any_other_chain_gets_the_mainnet_defaults_stored() {
    bare_ext().execute_with(|| {
        frame_system::BlockHash::<Runtime>::insert(0, Hash::repeat_byte(1));
        InitRootTimelock::on_runtime_upgrade();
        assert!(pallet_root_timelock::Delays::<Runtime>::exists());
        assert_eq!(
            pallet_root_timelock::Delays::<Runtime>::get(),
            RootTimelockDefaultDelays::get()
        );
    });
}

#[test]
fn stored_delays_are_never_overwritten() {
    new_test_ext().execute_with(|| {
        frame_system::BlockHash::<Runtime>::insert(0, PREPROD_GENESIS_HASH);
        InitRootTimelock::on_runtime_upgrade();
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get(), DELAYS);
    });
}

/// `frame_system::Config::DbWeight` is `()` here and prices storage at zero.
#[test]
fn storing_the_delays_is_charged_at_rocksdb_cost() {
    bare_ext().execute_with(|| {
        frame_system::BlockHash::<Runtime>::insert(0, PREPROD_GENESIS_HASH);
        assert_eq!(
            InitRootTimelock::on_runtime_upgrade(),
            RuntimeDbWeight::get().reads_writes(2, 1)
        );
        assert_eq!(
            InitRootTimelock::on_runtime_upgrade(),
            RuntimeDbWeight::get().reads(1)
        );
    });
}

#[test]
fn the_sudo_key_cannot_declare_the_weight_of_an_exempt_call() {
    new_test_ext().execute_with(|| {
        let unchecked = |call: RuntimeCall| {
            RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                call: Box::new(call),
                weight: Weight::from_parts(u64::MAX / 4, 0),
            })
        };
        for exempt in [
            note_stalled(30, 7),
            tee_disabled(true),
            schedule_call(remark()),
            enact_approved(remark()),
        ] {
            assert_eq!(
                signed(SUDO, unchecked(exempt.clone())),
                Err(call_filtered()),
                "{exempt:?}"
            );
            assert_ok!(signed(SUDO, sudo(exempt)));
        }
    });
}

#[test]
fn the_guardian_co_signs_a_key_rotation() {
    new_test_ext().execute_with(|| {
        let rotate = set_key(acct(NEW_KEY));
        let id = schedule(rotate.clone());
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::AuthorityRecovery, 1 + DELAYS.standard)
        );
        assert_ok!(signed(
            GUARDIAN,
            timelock(pallet_root_timelock::Call::fast_track { id })
        ));
        assert_ok!(enact(id, rotate));
        assert_eq!(sudo_key(), Some(acct(NEW_KEY)));
    });
}

fn rotation() -> RuntimeCall {
    set_key(acct(NEW_KEY))
}

/// The services a live chain runs, which the kill-switches stop.
fn start_services() {
    assert_ok!(pallet_tee_attestation::Pallet::<Runtime>::set_disabled(
        RuntimeOrigin::root(),
        false
    ));
    assert_ok!(
        pallet_billing::Pallet::<Runtime>::governance_set_debits_enabled(
            RuntimeOrigin::root(),
            true
        )
    );
}

fn services_running() -> bool {
    !pallet_tee_attestation::Disabled::<Runtime>::get()
        && pallet_billing::DebitsEnabled::<Runtime>::get()
}

fn restart_services() -> RuntimeCall {
    batch_all(vec![tee_disabled(false), debits_enabled(true)])
}

/// The defenders' answer to a stolen sudo key, which the operators still
/// hold, one step at a time. A thief holding the key may act before any step.
const DEFENDER_STEPS: usize = 5;

fn defender_step(step: usize) {
    match step {
        // The guardian vetoes every vetoable task and co-signs the rotation
        // before it is submitted.
        0 => {
            assert_ok!(signed(
                GUARDIAN,
                batch_all(vec![cancel_all(), approve(&rotation())])
            ));
        }
        // The operators run it at once. It takes no place in the queue, so
        // no refill of the queue can hold it off. A thief that runs it first
        // only does what the defenders asked.
        1 => {
            if sudo_key() != Some(acct(NEW_KEY)) {
                assert_ok!(signed(SUDO, sudo(enact_approved(rotation()))));
                assert_eq!(last_sudo_result(), Ok(()));
            }
            assert_eq!(sudo_key(), Some(acct(NEW_KEY)));
        }
        // The guardian vetoes whatever the thief scheduled before the
        // rotation landed.
        2 => {
            assert_ok!(signed(GUARDIAN, cancel_all()));
        }
        // The new key withdraws any guardian change still pending.
        3 => {
            if let Some(change) = PendingGuardianChange::<Runtime>::get() {
                assert_ok!(signed(
                    NEW_KEY,
                    sudo(timelock(pallet_root_timelock::Call::cancel { id: change }))
                ));
                assert_eq!(last_sudo_result(), Ok(()));
            }
        }
        // With the guardian's co-sign, the new key restarts at once whatever
        // the thief stopped.
        _ => {
            if !services_running() {
                assert_ok!(signed(GUARDIAN, approve(&restart_services())));
                assert_ok!(signed(NEW_KEY, sudo(enact_approved(restart_services()))));
                assert_eq!(last_sudo_result(), Ok(()));
            }
        }
    }
}

fn rotate_out_stolen_key() {
    for step in 0..DEFENDER_STEPS {
        defender_step(step);
    }
}

/// Nothing the stolen key did survives the rotation.
fn assert_stolen_key_is_out(attacker: &AccountId) {
    assert!(services_running());
    assert_eq!(pallet_root_timelock::Delays::<Runtime>::get(), DELAYS);
    assert_eq!(Tasks::<Runtime>::count(), 0);
    assert_eq!(PendingGuardianChange::<Runtime>::get(), None);
    assert_eq!(Guardian::<Runtime>::get(), Some(acct(GUARDIAN)));
    assert_eq!(sudo_key(), Some(acct(NEW_KEY)));
    assert_eq!(
        signed(SUDO, sudo(schedule_call(remark()))),
        Err(pallet_sudo::Error::<Runtime>::RequireSudo.into())
    );
    System::set_block_number(
        System::block_number() + RootTimelockMaxDelay::get() + RootTimelockEnactmentWindow::get(),
    );
    assert_eq!(Guardian::<Runtime>::get(), Some(acct(GUARDIAN)));
    assert_eq!(Balances::free_balance(attacker), FUND);
    assert_eq!(pallet_root_timelock::Delays::<Runtime>::get(), DELAYS);
}

#[test]
fn a_flood_of_guardian_changes_leaves_room_for_the_rotation() {
    new_test_ext().execute_with(|| {
        start_services();
        let cap = RootTimelockMaxPendingTasks::get() as usize;
        let attacker = acct(Bob);
        let appoint = appoint(Some(attacker.clone()));
        let mint = force_set_balance(attacker.clone(), 1_000 * FUND);
        // One stolen-key extrinsic: a queue's worth of guardian changes, then
        // a queue's worth of mints.
        assert_ok!(signed(
            SUDO,
            sudo(RuntimeCall::Utility(pallet_utility::Call::force_batch {
                calls: [
                    vec![schedule_call(appoint.clone()); cap],
                    vec![schedule_call(mint.clone()); cap],
                ]
                .concat(),
            }))
        ));
        assert_eq!(PendingGuardianChange::<Runtime>::get(), Some(0));
        assert_eq!(Tasks::<Runtime>::count() as usize, 1 + cap);

        System::set_block_number(2);
        rotate_out_stolen_key();
        System::set_block_number(1 + DELAYS.long);
        assert_eq!(
            enact(0, appoint),
            Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
        );
        assert_stolen_key_is_out(&attacker);
    });
}

#[test]
fn a_refill_after_the_veto_cannot_hold_off_the_rotation() {
    new_test_ext().execute_with(|| {
        let cap = RootTimelockMaxPendingTasks::get() as usize;
        System::set_block_number(2);
        defender_step(0);
        // One thief extrinsic ordered after the veto refills every place.
        assert_ok!(signed(
            SUDO,
            sudo(batch(vec![schedule_call(remark()); cap]))
        ));
        assert_eq!(last_sudo_result(), Ok(()));
        assert_ok!(signed(SUDO, sudo(schedule_call(rotation()))));
        assert_eq!(
            last_sudo_result(),
            Err(timelock_error(pallet_root_timelock::Error::TooManyTasks))
        );
        // The co-signed rotation needs no place.
        defender_step(1);
        assert_eq!(Tasks::<Runtime>::count() as usize, cap);
    });
}

/// The signed-extrinsic envelope (address, signature, era, nonce, tip, length
/// prefix): constant across senders, so pool priority turns only on the call.
const ENVELOPE: usize = 105;

fn xt_len(call: &RuntimeCall) -> usize {
    call.encoded_size() + ENVELOPE
}

/// Fee params under which priority tracks declared weight, and balances that
/// outlast the run so `reconcile` never lowers them.
fn put_fee_params() {
    pallet_motra::Params::<Runtime>::put(pallet_motra::types::MotraParams {
        min_fee: 0,
        congestion_rate: 1_000_000,
        target_fullness: Perbill::from_percent(50),
        decay_rate_per_block: Perbill::one(),
        generation_per_matra_per_block: 0,
        max_balance: u128::MAX,
        max_congestion_step: 0,
        length_fee_per_byte: 0,
        congestion_smoothing: Perbill::zero(),
    });
    for who in [
        acct(SUDO),
        acct(GUARDIAN),
        acct(Bob),
        acct(Dave),
        acct(Ferdie),
    ] {
        pallet_motra::MotraBalances::<Runtime>::insert(who, u128::MAX / 2);
    }
}

/// The pool validity `ChargeMotra` assigns a signed call.
fn pool_validity(who: Keyring, call: &RuntimeCall) -> ValidTransaction {
    pallet_motra::fee::ChargeMotra::<Runtime>::new()
        .validate(&acct(who), call, &call.get_dispatch_info(), xt_len(call))
        .expect("the sender can pay")
}

fn pool_priority(who: Keyring, call: &RuntimeCall) -> TransactionPriority {
    pool_validity(who, call).priority
}

fn new_block() {
    frame_system::BlockWeight::<Runtime>::kill();
    frame_system::AllExtrinsicsLen::<Runtime>::kill();
}

/// A failing Operational extrinsic any funded account can send to fill a block.
fn stuffer() -> RuntimeCall {
    sudo(RuntimeCall::System(frame_system::Call::set_code {
        code: vec![],
    }))
}

/// A synthetic Operational call declaring `ref_time`, to close the block's
/// last sliver of budget exactly, so the veto's inclusion turns on priority
/// alone and not on a leftover gap.
fn sized_operational(ref_time: u64) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::with_weight {
        call: Box::new(cancel_all()),
        weight: Weight::from_parts(ref_time, 0),
    })
}

/// Applies each call into the block in pool-priority order, as the author
/// does, and reports whether the guardian's veto is taken in.
fn veto_survives(mut ordered: Vec<(TransactionPriority, RuntimeCall)>, veto: &RuntimeCall) -> bool {
    ordered.sort_by(|a, b| b.0.cmp(&a.0));
    new_block();
    let mut included = false;
    for (_, call) in &ordered {
        let info = call.get_dispatch_info();
        if frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, xt_len(call)).is_ok()
            && call == veto
        {
            included = true;
        }
    }
    included
}

#[test]
fn a_full_operational_block_of_failing_sudo_cannot_starve_a_guardian_cancel() {
    new_test_ext().execute_with(|| {
        put_fee_params();
        let thief_mint = force_set_balance(acct(Bob), FUND * 1000);
        let id = schedule(thief_mint.clone());
        let veto = cancel_all();
        let veto_ref = veto.get_dispatch_info().weight.ref_time();

        let weights = RuntimeBlockWeights::get();
        let op = weights.get(DispatchClass::Operational);
        let op_budget = op.max_total.expect("Operational has a budget").ref_time();
        let base = op.base_extrinsic.ref_time();

        // Failing Operational traffic that fills the class budget, then one
        // gap-closer sized so the block's remaining room falls a hair below the
        // veto's weight. Only its priority can then get the veto in.
        let per_stuffer = stuffer().get_dispatch_info().weight.ref_time().max(1);
        let big = (op_budget / (per_stuffer + base)) as usize;
        new_block();
        for _ in 0..big {
            assert!(
                frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
                    &stuffer().get_dispatch_info(),
                    xt_len(&stuffer())
                )
                .is_ok(),
                "a stuffer should fit while the block has room"
            );
        }
        let remaining = op_budget
            - frame_system::Pallet::<Runtime>::block_weight()
                .get(DispatchClass::Operational)
                .ref_time();

        let mut ordered: Vec<(TransactionPriority, RuntimeCall)> = (0..big)
            .map(|_| (pool_priority(Ferdie, &stuffer()), stuffer()))
            .collect();
        if remaining > base + veto_ref {
            let gap = sized_operational(remaining - base - (veto_ref - 1));
            ordered.push((pool_priority(Ferdie, &gap), gap));
        }
        ordered.push((pool_priority(GUARDIAN, &veto), veto.clone()));

        assert!(
            veto_survives(ordered, &veto),
            "the guardian's veto was crowded out of a full Operational block"
        );

        // Taken first, the veto lands and the thief's mint never enacts.
        assert_ok!(signed(GUARDIAN, veto));
        System::set_block_number(1 + DELAYS.standard);
        assert_eq!(
            enact(id, thief_mint),
            Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
        );
        assert_eq!(Balances::free_balance(acct(Bob)), FUND);
    });
}

#[test]
fn no_fee_can_outbid_the_guardians_veto() {
    new_test_ext().execute_with(|| {
        put_fee_params();
        let veto = cancel_all();
        assert_eq!(pool_priority(GUARDIAN, &veto), TransactionPriority::MAX);

        // A fee beyond the u64 priority range is capped one below the ceiling.
        pallet_motra::MotraBalances::<Runtime>::insert(acct(Bob), u128::MAX);
        pallet_motra::Params::<Runtime>::mutate(|p| p.congestion_rate = u128::MAX / 2);
        let paid = pool_priority(Bob, &stuffer());
        assert_eq!(paid, TransactionPriority::MAX - 1);
        assert!(paid < pool_priority(GUARDIAN, &veto));
    });
}

#[test]
fn a_veto_from_a_non_guardian_is_not_taken_first() {
    new_test_ext().execute_with(|| {
        put_fee_params();
        let veto = cancel_all();
        assert_eq!(pool_priority(GUARDIAN, &veto), TransactionPriority::MAX);
        assert!(pool_priority(Bob, &veto) < TransactionPriority::MAX);
        assert!(pool_validity(Bob, &veto).provides.is_empty());
    });
}

#[test]
fn a_multisig_guardian_wrapper_is_taken_first_and_bounded() {
    let mut signatories = vec![acct(Charlie), acct(Dave)];
    signatories.sort();
    let guardian = pallet_multisig::Pallet::<Runtime>::multi_account_id(&signatories, 2);
    let wrap = |call: RuntimeCall, max_weight: Weight, signer: Keyring| {
        let others: Vec<AccountId> = signatories
            .iter()
            .filter(|a| **a != acct(signer))
            .cloned()
            .collect();
        RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
            threshold: 2,
            other_signatories: others,
            maybe_timepoint: None,
            max_weight,
            call: Box::new(call),
        })
    };
    ext_with(acct(SUDO), Some(guardian)).execute_with(|| {
        put_fee_params();
        let veto = cancel_all();
        let honest = wrap(veto.clone(), veto.get_dispatch_info().weight, Charlie);
        assert_eq!(pool_priority(Charlie, &honest), TransactionPriority::MAX);
        assert!(!pool_validity(Charlie, &honest).provides.is_empty());

        // Each signatory holds its own taken-first slot.
        let from_dave = wrap(veto.clone(), veto.get_dispatch_info().weight, Dave);
        assert_ne!(
            pool_validity(Charlie, &honest).provides,
            pool_validity(Dave, &from_dave).provides
        );

        // Inflating the wrapper's declared weight forfeits the boost.
        let op_budget = RuntimeBlockWeights::get()
            .get(DispatchClass::Operational)
            .max_total
            .expect("Operational has a budget");
        let inflated = wrap(veto.clone(), op_budget, Charlie);
        assert!(pool_priority(Charlie, &inflated) < TransactionPriority::MAX);
    });
}

#[test]
fn one_extrinsic_cannot_freeze_governance_past_the_rotation() {
    new_test_ext().execute_with(|| {
        start_services();
        let max = RootTimelockMaxDelay::get();
        let raises = vec![
            set_delay(CallClass::Long, max),
            set_delay(CallClass::Standard, max),
            set_delay(CallClass::Recovery, max),
        ];
        let stop = vec![tee_disabled(true), debits_enabled(false)];
        assert_eq!(
            signed(SUDO, sudo(batch([raises.clone(), stop.clone()].concat()))),
            Err(call_filtered())
        );
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get(), DELAYS);

        // What the stolen key can do: stop the services at once, and
        // schedule the raises, which the guardian can veto.
        assert_ok!(signed(SUDO, sudo(batch(stop))));
        assert!(!services_running());
        let raise_all = batch_all(raises);
        let raising = schedule(raise_all.clone());
        assert_eq!(task(raising).class, CallClass::Recovery);

        System::set_block_number(2);
        rotate_out_stolen_key();
        assert!(services_running());
        System::set_block_number(1 + DELAYS.recovery);
        assert_eq!(
            enact(raising, raise_all),
            Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
        );

        // A security upgrade the new key schedules waits the standard delay.
        let upgrade = authorize_upgrade(7);
        let id = schedule_by(NEW_KEY, upgrade.clone());
        let ready_at = System::block_number() + DELAYS.standard;
        assert_eq!(task(id).ready_at, ready_at);
        System::set_block_number(ready_at);
        assert_ok!(enact(id, upgrade));
        assert_stolen_key_is_out(&thief());
    });
}

#[test]
fn a_task_scheduled_during_the_answer_never_lands() {
    new_test_ext().execute_with(|| {
        start_services();
        let mint = force_set_balance(thief(), 1_000 * FUND);
        System::set_block_number(2);
        defender_step(0);
        // The thief, still holding the key, schedules after the veto.
        let late = schedule(mint.clone());
        for step in 1..DEFENDER_STEPS {
            defender_step(step);
        }
        System::set_block_number(2 + DELAYS.standard);
        assert_eq!(
            enact(late, mint),
            Err(timelock_error(pallet_root_timelock::Error::UnknownTask))
        );
        assert_stolen_key_is_out(&thief());
    });
}

#[test]
fn a_stolen_2_of_3_key_is_rotated_out_through_its_own_custody() {
    let sorted = |mut accounts: Vec<AccountId>| {
        accounts.sort();
        accounts
    };
    let signers = sorted(vec![acct(Alice), acct(Bob), acct(Ferdie)]);
    let multisig = pallet_multisig::Pallet::<Runtime>::multi_account_id(&signers, 2);
    let others = |me: Keyring| {
        sorted(
            signers
                .iter()
                .filter(|a| **a != acct(me))
                .cloned()
                .collect(),
        )
    };
    let two_of_three = |call: RuntimeCall| {
        let max_weight = call.get_dispatch_info().weight;
        assert_ok!(signed(
            Alice,
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: others(Alice),
                maybe_timepoint: None,
                call: Box::new(call.clone()),
                max_weight,
            })
        ));
        assert_ok!(signed(
            Bob,
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: others(Bob),
                maybe_timepoint: Some(pallet_multisig::Pallet::<Runtime>::timepoint()),
                call: Box::new(call),
                max_weight,
            })
        ));
    };
    ext_with(multisig, Some(acct(GUARDIAN))).execute_with(|| {
        let cap = RootTimelockMaxPendingTasks::get() as usize;
        let attacker = AccountId::from([0xA7; 32]);
        // The thief holds two of the three signer keys.
        two_of_three(sudo(batch(vec![
            schedule_call(appoint(Some(
                attacker.clone()
            )));
            cap
        ])));
        assert_eq!(Tasks::<Runtime>::count(), 1);

        System::set_block_number(2);
        defender_step(0);
        // The thief refills the queue after the veto; the co-signed rotation
        // needs no place in it.
        two_of_three(sudo(batch(vec![schedule_call(remark()); cap])));
        assert_eq!(Tasks::<Runtime>::count() as usize, 1 + cap);
        two_of_three(sudo(enact_approved(rotation())));
        assert_eq!(last_sudo_result(), Ok(()));
        assert_eq!(sudo_key(), Some(acct(NEW_KEY)));
        assert_ok!(signed(GUARDIAN, cancel_all()));
        assert_ok!(signed(
            NEW_KEY,
            sudo(timelock(pallet_root_timelock::Call::cancel { id: 0 }))
        ));
        assert_eq!(last_sudo_result(), Ok(()));
        assert_eq!(Tasks::<Runtime>::count(), 0);
        assert_eq!(Guardian::<Runtime>::get(), Some(acct(GUARDIAN)));
    });
}

/// Merges `patch` into `base`, as a chain spec's genesis patch is applied.
fn merge_json(base: &mut serde_json::Value, patch: serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                merge_json(base.entry(key).or_insert(serde_json::Value::Null), value);
            }
        }
        (base, patch) => *base = patch,
    }
}

/// Builds genesis storage the way a node builds it from a chain spec.
fn build_chain_spec(patch: serde_json::Value) -> Result<(), String> {
    let mut genesis =
        serde_json::to_value(RuntimeGenesisConfig::default()).expect("the default serializes");
    merge_json(&mut genesis, patch);
    TestExternalities::default().execute_with(|| {
        <Runtime as sp_genesis_builder::runtime_decl_for_genesis_builder::GenesisBuilder<Block>>::build_state(
            serde_json::to_vec(&genesis).expect("genesis serializes"),
        )
        .map_err(|e| format!("{e:?}"))
    })
}

#[test]
fn a_chain_spec_must_name_a_guardian_apart_from_the_sudo_key() {
    // Keys no one derives from a public development seed.
    let operators = AccountId::from([0x5A; 32]);
    let custodians = AccountId::from([0x6B; 32]);
    let spec = |sudo: &AccountId, guardian: Option<AccountId>, unguarded: bool| {
        serde_json::json!({
            "sudo": { "key": sudo },
            "rootTimelock": { "delays": DELAYS, "guardian": guardian, "unguarded": unguarded },
        })
    };
    assert_eq!(
        build_chain_spec(spec(&operators, Some(custodians.clone()), false)),
        Ok(())
    );
    // A spec that names no guardian, as one that leaves the pallet out does.
    assert!(build_chain_spec(spec(&operators, None, false)).is_err());
    assert!(build_chain_spec(serde_json::json!({ "sudo": { "key": operators } })).is_err());
    // A guardian that is the sudo key vetoes nothing the key schedules.
    assert!(build_chain_spec(spec(&operators, Some(operators.clone()), false)).is_err());
    assert!(build_chain_spec(spec(&operators, Some(custodians), true)).is_err());

    // Anyone can sign as a development account: as guardian it would let
    // anyone veto every task, and co-sign a stolen sudo key's key rotation.
    for dev in Keyring::iter() {
        let refused = build_chain_spec(spec(&operators, Some(dev.to_account_id()), false));
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("development account")),
            "{dev}: {refused:?}"
        );
    }
    // A development chain, whose sudo key is one too, may use one.
    assert_eq!(
        build_chain_spec(spec(&acct(SUDO), Some(acct(GUARDIAN)), false)),
        Ok(())
    );
}

/// On an unguarded chain nothing can stop a stolen sudo key from withdrawing
/// every rotation scheduled to replace it, so only a chain whose sudo key
/// anyone may sign for, or which has none, may start without a guardian.
#[test]
fn only_a_development_chain_may_start_unguarded() {
    let unguarded = |sudo: Option<AccountId>| {
        serde_json::json!({
            "sudo": { "key": sudo },
            "rootTimelock": { "delays": DELAYS, "unguarded": true },
        })
    };
    let refused = build_chain_spec(unguarded(Some(AccountId::from([0x5A; 32]))));
    assert!(
        refused.as_ref().is_err_and(|e| e.contains("unguarded")),
        "{refused:?}"
    );
    for dev in Keyring::iter() {
        assert_eq!(
            build_chain_spec(unguarded(Some(dev.to_account_id()))),
            Ok(()),
            "{dev}"
        );
    }
    assert_eq!(build_chain_spec(unguarded(None)), Ok(()));
}

#[test]
fn the_benchmarking_preset_builds() {
    let preset = <Runtime as sp_genesis_builder::runtime_decl_for_genesis_builder::GenesisBuilder<Block>>::get_preset(&Some(
        sp_genesis_builder::PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
    ))
    .expect("the development preset exists");
    let patch = serde_json::from_slice(&preset).expect("the preset is JSON");
    assert_eq!(build_chain_spec(patch), Ok(()));
}

// ---------------------------------------------------------------------------
// Property: over random mixes of direct sudo attempts, scheduling, enacting,
// vetoes (one task or all), fast-tracks, pruning and time, the runtime agrees
// with a model that lets a non-exempt call take effect only through an
// enactment at or after `scheduled_at + delay(class)`. The model states the
// policy independently of the runtime's gate and classifier.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Target {
    Store { slot: u8, value: u8 },
    Mint { slot: u8, value: u8 },
    Lever { which: u8, on: bool },
    Bridge { tag: u8 },
    TeeDisabled { disabled: bool },
    Stall { value: u8 },
    Pin { tag: u8 },
    SetDelay { class: u8, blocks: BlockNumber },
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Wrapper {
    Plain,
    Batch,
    BatchAllAfterRemark,
    WithWeight,
    DispatchAsRoot,
    NestedSudo,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Path {
    Sudo,
    SudoUncheckedWeight,
    BatchedSudo,
    SudoAs,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Direct {
        path: Path,
        wrapper: Wrapper,
        target: Target,
    },
    Schedule {
        wrapper: Wrapper,
        target: Target,
    },
    Enact {
        pick: u8,
    },
    Cancel {
        pick: u8,
    },
    FastTrack {
        pick: u8,
    },
    CancelAll,
    Prune {
        pick: u8,
    },
    Advance {
        blocks: BlockNumber,
    },
    Approve {
        wrapper: Wrapper,
        target: Target,
    },
    EnactApproved {
        /// Submit the approved call, if there is one.
        approved: bool,
        wrapper: Wrapper,
        target: Target,
    },
}

fn class_index(i: u8) -> CallClass {
    [CallClass::Recovery, CallClass::Standard, CallClass::Long][i as usize % 3]
}

fn store_key(slot: u8) -> Vec<u8> {
    [b"root-timelock-pt/".as_slice(), &[slot]].concat()
}

fn mint_account(slot: u8) -> AccountId {
    AccountId::from([100 + slot; 32])
}

fn target_call(t: Target) -> RuntimeCall {
    match t {
        Target::Store { slot, value } => RuntimeCall::System(frame_system::Call::set_storage {
            items: vec![(store_key(slot), vec![value])],
        }),
        Target::Mint { slot, value } => {
            force_set_balance(mint_account(slot), 1_000 + Balance::from(value))
        }
        Target::Lever { which, on } => orinq(match which % 3 {
            0 => pallet_orinq_receipts::pallet::Call::set_core_eviction_enabled { enabled: on },
            1 => {
                pallet_orinq_receipts::pallet::Call::set_contribution_window_enabled { enabled: on }
            }
            _ => pallet_orinq_receipts::pallet::Call::set_slack_invariant_enabled { enabled: on },
        }),
        Target::Bridge { tag } => bridge_scripts(tag),
        Target::TeeDisabled { disabled } => tee_disabled(disabled),
        Target::Stall { value } => {
            note_stalled(BlockNumber::from(value) + 1, BlockNumber::from(value))
        }
        Target::Pin { tag } => pin(tag),
        Target::SetDelay { class, blocks } => set_delay(class_index(class), blocks),
    }
}

fn wrap(w: Wrapper, call: RuntimeCall) -> RuntimeCall {
    match w {
        Wrapper::Plain => call,
        Wrapper::Batch => batch(vec![call]),
        Wrapper::BatchAllAfterRemark => RuntimeCall::Utility(pallet_utility::Call::batch_all {
            calls: vec![remark(), call],
        }),
        Wrapper::WithWeight => with_weight(call),
        Wrapper::DispatchAsRoot => dispatch_as_root(call),
        Wrapper::NestedSudo => sudo(call),
    }
}

fn submit(path: Path, call: RuntimeCall) -> RuntimeCall {
    match path {
        Path::Sudo => sudo(call),
        Path::SudoUncheckedWeight => RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
            call: Box::new(call),
            weight: Weight::zero(),
        }),
        Path::BatchedSudo => batch(vec![sudo(call)]),
        Path::SudoAs => RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
            who: acct(Bob).into(),
            call: Box::new(call),
        }),
    }
}

struct PendingTask {
    wrapper: Wrapper,
    target: Target,
    class: CallClass,
    ready_at: BlockNumber,
}

struct Model {
    now: BlockNumber,
    delays: DelayTable<BlockNumber>,
    tasks: std::collections::BTreeMap<TaskId, PendingTask>,
    scheduled: Vec<TaskId>,
    next_id: TaskId,
    store: [Option<u8>; 3],
    mint: [Option<u8>; 3],
    levers: [bool; 3],
    bridge: Option<u8>,
    tee_disabled: bool,
    stalled: Option<(BlockNumber, BlockNumber)>,
    pin: Option<u8>,
    /// The guardian's approval, and the last block it may be used in.
    approval: Option<(Wrapper, Target, BlockNumber)>,
}

impl Model {
    fn new() -> Self {
        Self {
            now: 1,
            delays: DELAYS,
            tasks: Default::default(),
            scheduled: vec![],
            next_id: 0,
            store: [None; 3],
            mint: [None; 3],
            levers: [false; 3],
            bridge: None,
            tee_disabled: true,
            stalled: None,
            pin: None,
            approval: None,
        }
    }

    /// The policy: what may reach Root at once.
    fn exempt(&self, t: Target) -> bool {
        match t {
            Target::TeeDisabled { disabled } => disabled,
            Target::Stall { value } => BlockNumber::from(value) < MAX_EXEMPT_STALL_DELAY,
            _ => false,
        }
    }

    /// The policy: how long a scheduled call waits.
    fn class(&self, w: Wrapper, t: Target) -> CallClass {
        let own = match t {
            Target::Store { .. } | Target::Mint { .. } => CallClass::Standard,
            Target::TeeDisabled { disabled: true } => CallClass::Standard,
            Target::TeeDisabled { disabled: false } => CallClass::AuthorityRecovery,
            Target::Lever { .. } => CallClass::Recovery,
            Target::Stall { value } if BlockNumber::from(value) < MAX_EXEMPT_STALL_DELAY => {
                CallClass::Recovery
            }
            Target::Stall { .. } | Target::Pin { .. } => CallClass::AuthorityRecovery,
            Target::Bridge { .. } => CallClass::Long,
            Target::SetDelay { class, blocks } if blocks >= self.delays.of(class_index(class)) => {
                CallClass::Recovery
            }
            Target::SetDelay { class, .. } if class_index(class) == CallClass::Long => {
                CallClass::Long
            }
            Target::SetDelay { .. } => CallClass::Standard,
        };
        match w {
            Wrapper::BatchAllAfterRemark | Wrapper::DispatchAsRoot => own.max(CallClass::Standard),
            _ => own,
        }
    }

    /// Applies `t`'s effect; false when the call itself would fail.
    fn apply(&mut self, t: Target) -> bool {
        match t {
            Target::Store { slot, value } => self.store[slot as usize] = Some(value),
            Target::Mint { slot, value } => self.mint[slot as usize] = Some(value),
            Target::Lever { which, on } => self.levers[which as usize % 3] = on,
            Target::Bridge { tag } => self.bridge = Some(tag),
            Target::TeeDisabled { disabled } => self.tee_disabled = disabled,
            Target::Stall { value } => {
                self.stalled = Some((BlockNumber::from(value) + 1, BlockNumber::from(value)))
            }
            Target::Pin { tag } => self.pin = Some(tag),
            Target::SetDelay { class, blocks } => {
                let Some(delays) = self
                    .delays
                    .with(class_index(class), blocks)
                    .filter(|delays| delays.is_valid(RootTimelockMaxDelay::get()))
                else {
                    return false;
                };
                self.delays = delays;
            }
        }
        true
    }

    fn pick(&self, pick: u8) -> Option<TaskId> {
        (!self.scheduled.is_empty()).then(|| self.scheduled[pick as usize % self.scheduled.len()])
    }

    fn step(&mut self, action: Action) {
        use pallet_root_timelock::Error as E;
        match action {
            Action::Direct {
                path,
                wrapper,
                target,
            } => {
                let result = signed(SUDO, submit(path, wrap(wrapper, target_call(target))));
                let admitted = matches!(path, Path::Sudo | Path::BatchedSudo)
                    && matches!(wrapper, Wrapper::Plain | Wrapper::Batch)
                    && self.exempt(target);
                // A signed batch is admitted even when the sudo inside it is not.
                if admitted || path == Path::BatchedSudo {
                    assert_ok!(result);
                } else {
                    assert_eq!(result, Err(call_filtered()));
                }
                if admitted {
                    self.apply(target);
                }
            }
            Action::Schedule { wrapper, target } => {
                let call = wrap(wrapper, target_call(target));
                let id = schedule(call.clone());
                assert_eq!(id, self.next_id);
                let class = self.class(wrapper, target);
                let ready_at = self.now + self.delays.of(class);
                assert_eq!(
                    task(id),
                    Task {
                        call_hash: BlakeTwo256::hash_of(&call),
                        class,
                        ready_at,
                        vetoable: true
                    }
                );
                self.tasks.insert(
                    id,
                    PendingTask {
                        wrapper,
                        target,
                        class,
                        ready_at,
                    },
                );
                self.scheduled.push(id);
                self.next_id += 1;
            }
            Action::Enact { pick } => {
                let Some(id) = self.pick(pick) else { return };
                let Some(pending) = self.tasks.get(&id) else {
                    assert_eq!(enact(id, remark()), Err(timelock_error(E::UnknownTask)));
                    return;
                };
                let (wrapper, target, class, ready_at) = (
                    pending.wrapper,
                    pending.target,
                    pending.class,
                    pending.ready_at,
                );
                let result = enact(id, wrap(wrapper, target_call(target)));
                if self.now < ready_at {
                    assert_eq!(result, Err(timelock_error(E::NotReady)));
                } else if self.now > ready_at + RootTimelockEnactmentWindow::get() {
                    assert_eq!(result, Err(timelock_error(E::Expired)));
                } else if self.class(wrapper, target) > class {
                    assert_eq!(result, Err(timelock_error(E::ClassRaised)));
                } else if self.apply(target) {
                    assert_ok!(result);
                    self.tasks.remove(&id);
                } else if matches!(
                    wrapper,
                    Wrapper::Batch | Wrapper::DispatchAsRoot | Wrapper::NestedSudo
                ) {
                    // These wrappers report an inner failure as an event.
                    assert_ok!(result);
                    self.tasks.remove(&id);
                } else {
                    assert_eq!(result, Err(timelock_error(E::InvalidDelays)));
                }
            }
            Action::Cancel { pick } => {
                let Some(id) = self.pick(pick) else { return };
                let result = signed(
                    GUARDIAN,
                    timelock(pallet_root_timelock::Call::cancel { id }),
                );
                match self.tasks.remove(&id) {
                    Some(_) => {
                        assert_ok!(result);
                    }
                    None => assert_eq!(result, Err(timelock_error(E::UnknownTask))),
                }
            }
            Action::FastTrack { pick } => {
                let Some(id) = self.pick(pick) else { return };
                let result = signed(
                    GUARDIAN,
                    timelock(pallet_root_timelock::Call::fast_track { id }),
                );
                match self.tasks.get_mut(&id) {
                    Some(pending)
                        if !matches!(
                            pending.class,
                            CallClass::Recovery | CallClass::AuthorityRecovery
                        ) =>
                    {
                        assert_eq!(result, Err(timelock_error(E::NotFastTrackable)))
                    }
                    Some(pending) if self.now >= pending.ready_at => {
                        assert_eq!(result, Err(timelock_error(E::AlreadyReady)))
                    }
                    Some(pending) => {
                        assert_ok!(result);
                        pending.ready_at = self.now;
                    }
                    None => assert_eq!(result, Err(timelock_error(E::UnknownTask))),
                }
            }
            Action::CancelAll => {
                assert_ok!(signed(
                    GUARDIAN,
                    timelock(pallet_root_timelock::Call::cancel_all {})
                ));
                self.tasks.clear();
            }
            Action::Prune { pick } => {
                let Some(id) = self.pick(pick) else { return };
                let result = signed(ENACTOR, timelock(pallet_root_timelock::Call::prune { id }));
                match self.tasks.get(&id) {
                    None => assert_eq!(result, Err(timelock_error(E::UnknownTask))),
                    Some(pending)
                        if self.now > pending.ready_at + RootTimelockEnactmentWindow::get() =>
                    {
                        assert_ok!(result);
                        self.tasks.remove(&id);
                    }
                    Some(_) => assert_eq!(result, Err(timelock_error(E::NotExpired))),
                }
            }
            Action::Advance { blocks } => {
                self.now += blocks;
                System::set_block_number(self.now);
            }
            Action::Approve { wrapper, target } => {
                assert_ok!(signed(
                    GUARDIAN,
                    approve(&wrap(wrapper, target_call(target)))
                ));
                self.approval = Some((
                    wrapper,
                    target,
                    self.now + RootTimelockEnactmentWindow::get(),
                ));
            }
            Action::EnactApproved {
                approved,
                wrapper,
                target,
            } => {
                let (wrapper, target) = match self.approval {
                    Some((wrapper, target, _)) if approved => (wrapper, target),
                    _ => (wrapper, target),
                };
                let call = wrap(wrapper, target_call(target));
                assert_ok!(signed(SUDO, sudo(enact_approved(call.clone()))));
                let result = last_sudo_result();
                let Some((approved_wrapper, approved_target, until)) = self.approval else {
                    assert_eq!(result, Err(timelock_error(E::NotApproved)));
                    return;
                };
                if wrap(approved_wrapper, target_call(approved_target)) != call {
                    assert_eq!(result, Err(timelock_error(E::NotApproved)));
                } else if self.now > until {
                    assert_eq!(result, Err(timelock_error(E::Expired)));
                } else if !matches!(
                    self.class(wrapper, target),
                    CallClass::Recovery | CallClass::AuthorityRecovery
                ) {
                    assert_eq!(result, Err(timelock_error(E::NotFastTrackable)));
                } else if self.apply(target)
                    || matches!(
                        wrapper,
                        Wrapper::Batch | Wrapper::DispatchAsRoot | Wrapper::NestedSudo
                    )
                {
                    assert_eq!(result, Ok(()));
                    self.approval = None;
                } else {
                    assert_eq!(result, Err(timelock_error(E::InvalidDelays)));
                }
            }
        }
    }

    fn check(&self) {
        for slot in 0..3u8 {
            assert_eq!(
                unhashed::get_raw(&store_key(slot)),
                self.store[slot as usize].map(|v| vec![v])
            );
            assert_eq!(
                Balances::free_balance(mint_account(slot)),
                self.mint[slot as usize].map_or(0, |v| 1_000 + Balance::from(v))
            );
        }
        assert_eq!(
            pallet_orinq_receipts::CoreEvictionEnabled::<Runtime>::get(),
            self.levers[0]
        );
        assert_eq!(
            pallet_orinq_receipts::ContributionWindowEnabled::<Runtime>::get(),
            self.levers[1]
        );
        assert_eq!(
            pallet_orinq_receipts::SlackInvariantEnabled::<Runtime>::get(),
            self.levers[2]
        );
        assert_eq!(
            pallet_native_token_management::MainChainScriptsConfiguration::<Runtime>::get()
                .map(|s| s.native_token_policy_id),
            self.bridge.map(|tag| PolicyId([tag; 28]))
        );
        assert_eq!(
            pallet_tee_attestation::Disabled::<Runtime>::get(),
            self.tee_disabled
        );
        assert_eq!(Grandpa::stalled(), self.stalled);
        assert_eq!(
            pallet_orinq_receipts::PinnedCommittee::<Runtime>::get()
                .map(|(members, _)| members[0].aura[0]),
            self.pin
        );
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get(), self.delays);
        let pending: Vec<(TaskId, BlockNumber)> =
            self.tasks.iter().map(|(id, t)| (*id, t.ready_at)).collect();
        let mut stored: Vec<(TaskId, BlockNumber)> = Tasks::<Runtime>::iter()
            .map(|(id, t)| (id, t.ready_at))
            .collect();
        stored.sort();
        assert_eq!(stored, pending);
        assert_eq!(
            pallet_root_timelock::Approval::<Runtime>::get(),
            self.approval.map(|(wrapper, target, until)| (
                BlakeTwo256::hash_of(&wrap(wrapper, target_call(target))),
                until
            ))
        );
    }
}

fn target_strategy() -> impl Strategy<Value = Target> {
    prop_oneof![
        (0u8..3, any::<u8>()).prop_map(|(slot, value)| Target::Store { slot, value }),
        (0u8..3, any::<u8>()).prop_map(|(slot, value)| Target::Mint { slot, value }),
        (0u8..3, any::<bool>()).prop_map(|(which, on)| Target::Lever { which, on }),
        any::<u8>().prop_map(|tag| Target::Bridge { tag }),
        any::<bool>().prop_map(|disabled| Target::TeeDisabled { disabled }),
        any::<u8>().prop_map(|value| Target::Stall { value }),
        any::<u8>().prop_map(|tag| Target::Pin { tag }),
        (
            0u8..3,
            prop_oneof![
                1..=250u32,
                Just(RootTimelockMaxDelay::get()),
                Just(RootTimelockMaxDelay::get() + 1)
            ]
        )
            .prop_map(|(class, blocks)| Target::SetDelay { class, blocks }),
    ]
}

fn wrapper_strategy() -> impl Strategy<Value = Wrapper> {
    prop::sample::select(vec![
        Wrapper::Plain,
        Wrapper::Batch,
        Wrapper::BatchAllAfterRemark,
        Wrapper::WithWeight,
        Wrapper::DispatchAsRoot,
        Wrapper::NestedSudo,
    ])
}

fn action_strategy() -> impl Strategy<Value = Action> {
    let path = prop::sample::select(vec![
        Path::Sudo,
        Path::SudoUncheckedWeight,
        Path::BatchedSudo,
        Path::SudoAs,
    ]);
    prop_oneof![
        3 => (path, wrapper_strategy(), target_strategy())
            .prop_map(|(path, wrapper, target)| Action::Direct { path, wrapper, target }),
        3 => (wrapper_strategy(), target_strategy()).prop_map(|(wrapper, target)| Action::Schedule { wrapper, target }),
        3 => any::<u8>().prop_map(|pick| Action::Enact { pick }),
        1 => any::<u8>().prop_map(|pick| Action::Cancel { pick }),
        1 => any::<u8>().prop_map(|pick| Action::FastTrack { pick }),
        1 => Just(Action::CancelAll),
        1 => any::<u8>().prop_map(|pick| Action::Prune { pick }),
        3 => prop_oneof![
            8 => 0..=60u32,
            1 => Just(RootTimelockEnactmentWindow::get()),
            1 => Just(RootTimelockMaxDelay::get()),
        ]
        .prop_map(|blocks| Action::Advance { blocks }),
        1 => (wrapper_strategy(), target_strategy())
            .prop_map(|(wrapper, target)| Action::Approve { wrapper, target }),
        2 => (any::<bool>(), wrapper_strategy(), target_strategy()).prop_map(
            |(approved, wrapper, target)| Action::EnactApproved { approved, wrapper, target }
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn no_non_exempt_call_takes_effect_before_its_delay(
        actions in prop::collection::vec(action_strategy(), 1..48)
    ) {
        new_test_ext().execute_with(|| {
            let mut model = Model::new();
            for action in actions {
                model.step(action);
                model.check();
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Property: whatever the stolen key does before each step of the defenders'
// answer (floods of scheduled calls and guardian changes, delay raises,
// stalls, kill-switches, withdrawals, running the approved rotation itself),
// the answer rotates the key out, and nothing the stolen key scheduled,
// appointed, raised or stopped outlasts it.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Stolen {
    Appoint { remove: bool },
    RotateToThief,
    Mint,
    Bridge,
    Pin,
    RemoveKey,
    NestedAppoint,
    LowerStandard,
    RaiseLong,
}

#[derive(Clone, Copy, Debug)]
enum BurstCall {
    Schedule { what: Stolen, copies: u8 },
    Raise { class: u8, to_max: bool },
    Stall,
    KillSwitches,
    WithdrawGuardianChange,
    RunTheApprovedRotation,
}

#[derive(Clone, Copy, Debug)]
enum Grouping {
    OneExtrinsicEach,
    Batch,
    ForceBatch,
}

fn thief() -> AccountId {
    acct(Bob)
}

fn stolen_call(what: Stolen) -> RuntimeCall {
    match what {
        Stolen::Appoint { remove } => appoint((!remove).then(thief)),
        Stolen::RotateToThief => set_key(thief()),
        Stolen::Mint => force_set_balance(thief(), 1_000 * FUND),
        Stolen::Bridge => bridge_scripts(0xEE),
        Stolen::Pin => pin(0xEE),
        Stolen::RemoveKey => RuntimeCall::Sudo(pallet_sudo::Call::remove_key {}),
        Stolen::NestedAppoint => schedule_call(appoint(Some(thief()))),
        Stolen::LowerStandard => set_delay(CallClass::Standard, 1),
        Stolen::RaiseLong => set_delay(CallClass::Long, RootTimelockMaxDelay::get()),
    }
}

fn burst_calls(call: BurstCall) -> Vec<RuntimeCall> {
    match call {
        BurstCall::Schedule { what, copies } => {
            vec![schedule_call(stolen_call(what)); usize::from(copies)]
        }
        BurstCall::Raise { class, to_max } => {
            let class = class_index(class);
            let blocks = if to_max {
                RootTimelockMaxDelay::get()
            } else {
                pallet_root_timelock::Delays::<Runtime>::get().of(class) + 1
            };
            vec![set_delay(class, blocks)]
        }
        BurstCall::Stall => vec![note_stalled(max_exempt_stall_delay(), 0)],
        BurstCall::KillSwitches => vec![tee_disabled(true), debits_enabled(false)],
        BurstCall::WithdrawGuardianChange => vec![timelock(pallet_root_timelock::Call::cancel {
            id: PendingGuardianChange::<Runtime>::get().unwrap_or(TaskId::MAX),
        })],
        BurstCall::RunTheApprovedRotation => vec![enact_approved(rotation())],
    }
}

fn stolen_strategy() -> impl Strategy<Value = Stolen> {
    prop_oneof![
        3 => any::<bool>().prop_map(|remove| Stolen::Appoint { remove }),
        1 => Just(Stolen::RotateToThief),
        2 => Just(Stolen::Mint),
        1 => Just(Stolen::Bridge),
        1 => Just(Stolen::Pin),
        1 => Just(Stolen::RemoveKey),
        1 => Just(Stolen::NestedAppoint),
        1 => Just(Stolen::LowerStandard),
        1 => Just(Stolen::RaiseLong),
    ]
}

fn burst_call_strategy() -> impl Strategy<Value = BurstCall> {
    prop_oneof![
        4 => (stolen_strategy(), prop_oneof![1..=3u8, 60..=70u8])
            .prop_map(|(what, copies)| BurstCall::Schedule { what, copies }),
        2 => (0u8..3, any::<bool>()).prop_map(|(class, to_max)| BurstCall::Raise { class, to_max }),
        1 => Just(BurstCall::Stall),
        1 => Just(BurstCall::KillSwitches),
        1 => Just(BurstCall::WithdrawGuardianChange),
        1 => Just(BurstCall::RunTheApprovedRotation),
    ]
}

fn grouping_strategy() -> impl Strategy<Value = Grouping> {
    prop::sample::select(vec![
        Grouping::OneExtrinsicEach,
        Grouping::Batch,
        Grouping::ForceBatch,
    ])
}

/// One turn of stolen-key extrinsics. Once the key is rotated they are
/// refused, and a thief's extrinsic may be refused before that too; only what
/// lands matters.
fn thief_acts(turn: Vec<(Grouping, Vec<BurstCall>)>) {
    for (grouping, calls) in turn {
        let calls: Vec<RuntimeCall> = calls.into_iter().flat_map(burst_calls).collect();
        let extrinsics = match grouping {
            Grouping::OneExtrinsicEach => calls.into_iter().map(sudo).collect(),
            Grouping::Batch => vec![sudo(batch(calls))],
            Grouping::ForceBatch => vec![sudo(RuntimeCall::Utility(
                pallet_utility::Call::force_batch { calls },
            ))],
        };
        for extrinsic in extrinsics {
            let _refused_or_landed = signed(SUDO, extrinsic);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn the_defenders_rotate_the_key_whatever_the_thief_does_between_their_steps(
        turns in prop::collection::vec(
            prop::collection::vec(
                (grouping_strategy(), prop::collection::vec(burst_call_strategy(), 1..6)),
                0..3,
            ),
            DEFENDER_STEPS,
        )
    ) {
        new_test_ext().execute_with(|| {
            start_services();
            for (step, turn) in turns.into_iter().enumerate() {
                thief_acts(turn);
                System::set_block_number(2);
                defender_step(step);
            }
            assert_stolen_key_is_out(&thief());
        });
    }
}
