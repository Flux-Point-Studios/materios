//! Root behind a delay: the sudo key reaches Root at once only for the
//! safety-only exempt calls and `RootTimelock::schedule`; everything else
//! waits its class's delay in `RootTimelock`, where the guardian can veto it.

use crate::migrations::{InitRootTimelock, PREPROD_GENESIS_HASH};
use crate::root_gate::{TimelockClassifier, MAX_EXEMPT_STALL_DELAY};
use crate::*;
use frame_support::{
    assert_ok,
    dispatch::{DispatchClass, GetDispatchInfo},
    storage::unhashed,
    traits::{Hooks, OnRuntimeUpgrade, OneSessionHandler},
};
use pallet_orinq_receipts::types::PinnedMember;
use pallet_root_timelock::{CallClass, ClassifyCall, DelayTable, Task, TaskId, Tasks};
use proptest::prelude::*;
use sidechain_domain::{AssetName, DParameter, EpochNonce, MainchainAddress, PolicyId};
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring::{self as Keyring, Alice, Bob, Charlie, Dave};
use sp_runtime::{
    traits::{Dispatchable, Hash as _},
    BuildStorage, DispatchError,
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

fn acct(k: Keyring) -> AccountId {
    k.to_account_id()
}

fn ext_with(sudo_key: AccountId, guardian: Option<AccountId>) -> TestExternalities {
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
    pallet_root_timelock::GenesisConfig::<Runtime> {
        delays: DELAYS,
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
    let id = pallet_root_timelock::NextTaskId::<Runtime>::get();
    assert_ok!(signed(
        SUDO,
        sudo(timelock(pallet_root_timelock::Call::schedule {
            call: Box::new(call)
        }))
    ));
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
            RuntimeCall::Sudo(pallet_sudo::Call::set_key {
                new: acct(Bob).into(),
            }),
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
            sudo(timelock(pallet_root_timelock::Call::set_guardian {
                guardian: Some(acct(Alice)),
            })),
            sudo(timelock(pallet_root_timelock::Call::cancel { id: 0 })),
            sudo(timelock(pallet_root_timelock::Call::fast_track { id: 0 })),
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
                call: Box::new(sudo(timelock(pallet_root_timelock::Call::schedule {
                    call: Box::new(mint.clone()),
                }))),
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
fn lowering_a_delay_waits_the_current_delay_and_raising_is_immediate() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            signed(SUDO, sudo(set_delay(CallClass::Standard, 10))),
            Err(call_filtered())
        );
        assert_ok!(signed(SUDO, sudo(set_delay(CallClass::Standard, 60))));
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get().standard, 60);

        let lower = set_delay(CallClass::Standard, 10);
        let id = schedule(lower.clone());
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::Standard, 61)
        );
        System::set_block_number(60);
        assert_eq!(
            enact(id, lower.clone()),
            Err(timelock_error(pallet_root_timelock::Error::NotReady))
        );
        System::set_block_number(61);
        assert_ok!(enact(id, lower));
        assert_eq!(pallet_root_timelock::Delays::<Runtime>::get().standard, 10);

        let id = schedule(set_delay(CallClass::Long, 100));
        assert_eq!(
            (task(id).class, task(id).ready_at),
            (CallClass::Long, 61 + 200)
        );

        // Lowering the recovery delay waits the standard delay and the
        // guardian cannot fast-track it.
        let id = schedule(set_delay(CallClass::Recovery, 1));
        assert_eq!(task(id).class, CallClass::Standard);
        assert_eq!(
            signed(
                GUARDIAN,
                timelock(pallet_root_timelock::Call::fast_track { id })
            ),
            Err(timelock_error(
                pallet_root_timelock::Error::NotFastTrackable
            ))
        );

        // Raising is bounded, so a stolen key cannot freeze governance forever.
        assert_ok!(signed(
            SUDO,
            sudo(set_delay(CallClass::Long, RootTimelockMaxDelay::get() + 1))
        ));
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
            (
                RuntimeCall::Sudo(pallet_sudo::Call::set_key {
                    new: acct(Bob).into(),
                }),
                Standard,
            ),
            (
                RuntimeCall::Recovery(pallet_recovery::Call::set_recovered {
                    lost: acct(Bob).into(),
                    rescuer: acct(Alice).into(),
                }),
                Standard,
            ),
            (set_delay(Standard, 1), Standard),
            (set_delay(Recovery, 1), Standard),
            (min_signer_threshold(4), Standard),
            (min_signer_threshold(3), Standard),
            (bridge_scripts(1), Long),
            (min_signer_threshold(2), Long),
            (min_signer_threshold(0), Long),
            (set_delay(Long, 1), Long),
            (
                timelock(pallet_root_timelock::Call::set_guardian { guardian: None }),
                Long,
            ),
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
        let replace = timelock(pallet_root_timelock::Call::set_guardian {
            guardian: Some(acct(Bob)),
        });
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
        assert_eq!(
            pallet_root_timelock::Guardian::<Runtime>::get(),
            Some(acct(Bob))
        );
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
        let replace = || {
            timelock(pallet_root_timelock::Call::set_guardian {
                guardian: Some(acct(Bob)),
            })
        };
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
            assert_ok!(signed(
                SUDO,
                sudo(timelock(pallet_root_timelock::Call::schedule {
                    call: Box::new(call.clone())
                }))
            ));
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
        let schedule_mint = timelock(pallet_root_timelock::Call::schedule {
            call: Box::new(mint.clone()),
        });
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

        // A guardian appointment cannot be withdrawn, and once it lands the
        // sudo key's veto ends.
        let appoint = timelock(pallet_root_timelock::Call::set_guardian {
            guardian: Some(acct(GUARDIAN)),
        });
        let id = schedule(appoint.clone());
        assert_ok!(signed(
            SUDO,
            sudo(timelock(pallet_root_timelock::Call::cancel { id }))
        ));
        assert_eq!(
            last_sudo_result(),
            Err(timelock_error(pallet_root_timelock::Error::NotVetoable))
        );
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
    new_test_ext().execute_with(|| {
        // The shortest session the exempt bound is sized for.
        let session = 2 * MAX_EXEMPT_STALL_DELAY;
        let mut block = 10;
        for seed in [10u8, 40, 70] {
            // The longest exempt stall, fired before every boundary.
            assert_ok!(signed(
                SUDO,
                sudo(note_stalled(MAX_EXEMPT_STALL_DELAY, block - 1))
            ));
            let set_id = Grandpa::current_set_id();
            grandpa_session(block, seed);
            assert_eq!(Grandpa::current_set_id(), set_id + 1);
            finalize_blocks(block + 1, block + session - 1);
            assert_eq!(Grandpa::pending_change().map(|change| change.delay), None);
            block += session;
        }
        let set_id = Grandpa::current_set_id();
        grandpa_session(block, 100);
        assert_eq!(Grandpa::current_set_id(), set_id + 1);
    });
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
    assert_eq!(MAX_EXEMPT_STALL_DELAY, 100);
    assert!(TESTNET_TIMELOCK_DELAYS.is_valid(RootTimelockMaxDelay::get()));
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
        }
    }

    /// The policy: what may reach Root at once.
    fn exempt(&self, t: Target) -> bool {
        match t {
            Target::TeeDisabled { disabled } => disabled,
            Target::Stall { value } => BlockNumber::from(value) < MAX_EXEMPT_STALL_DELAY,
            Target::SetDelay { class, blocks } => blocks >= self.delays.of(class_index(class)),
            _ => false,
        }
    }

    /// The policy: how long a scheduled call waits.
    fn class(w: Wrapper, t: Target) -> CallClass {
        let own = match t {
            Target::Store { .. } | Target::Mint { .. } | Target::TeeDisabled { .. } => {
                CallClass::Standard
            }
            Target::Lever { .. } => CallClass::Recovery,
            Target::Stall { value } if BlockNumber::from(value) < MAX_EXEMPT_STALL_DELAY => {
                CallClass::Recovery
            }
            Target::Stall { .. } | Target::Pin { .. } => CallClass::AuthorityRecovery,
            Target::Bridge { .. } => CallClass::Long,
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
                let admitted = path != Path::SudoAs
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
                let class = Self::class(wrapper, target);
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
                let (wrapper, target, ready_at) =
                    (pending.wrapper, pending.target, pending.ready_at);
                let result = enact(id, wrap(wrapper, target_call(target)));
                if self.now < ready_at {
                    assert_eq!(result, Err(timelock_error(E::NotReady)));
                } else if self.now > ready_at + RootTimelockEnactmentWindow::get() {
                    assert_eq!(result, Err(timelock_error(E::Expired)));
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
