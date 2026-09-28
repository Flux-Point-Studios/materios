use crate::{
    mock::*, Call, CallClass, DelayTable, Delays, Error, Event, GenesisConfig, Guardian,
    PendingGuardianChange, Task, Tasks,
};
use frame_support::{assert_noop, assert_ok, storage::unhashed};
use sp_runtime::{traits::Hash, DispatchError};

const KEY: &[u8] = b"timelock-test-key";

fn set_storage_call(value: &[u8]) -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::set_storage {
        items: vec![(KEY.to_vec(), value.to_vec())],
    })
}

fn recovery_call() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark {
        remark: b"recover".to_vec(),
    })
}

fn long_call() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::kill_storage {
        keys: vec![KEY.to_vec()],
    })
}

fn guardian_change(guardian: Option<u64>) -> RuntimeCall {
    RuntimeCall::RootTimelock(Call::set_guardian { guardian })
}

fn schedule(call: RuntimeCall) -> u32 {
    let id = crate::NextTaskId::<Test>::get();
    assert_ok!(RootTimelock::schedule(
        RuntimeOrigin::root(),
        Box::new(call)
    ));
    id
}

fn enact(id: u32, call: RuntimeCall) -> Result<(), DispatchError> {
    RootTimelock::enact(RuntimeOrigin::signed(ANYONE), id, Box::new(call))
        .map(|_| ())
        .map_err(|e| e.error)
}

fn stored() -> Option<Vec<u8>> {
    unhashed::get_raw(KEY)
}

#[test]
fn only_root_can_schedule() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            RootTimelock::schedule(
                RuntimeOrigin::signed(ANYONE),
                Box::new(set_storage_call(b"v"))
            ),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::schedule(
                RuntimeOrigin::signed(GUARDIAN),
                Box::new(set_storage_call(b"v"))
            ),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn scheduled_call_runs_only_after_its_delay() {
    new_test_ext().execute_with(|| {
        let call = set_storage_call(b"v");
        let id = schedule(call.clone());
        let ready_at = 1 + 10;
        System::assert_last_event(
            Event::Scheduled {
                id,
                call_hash: <Test as frame_system::Config>::Hashing::hash_of(&call),
                class: CallClass::Standard,
                ready_at,
            }
            .into(),
        );

        System::set_block_number(ready_at - 1);
        assert_noop!(enact(id, call.clone()), Error::<Test>::NotReady);
        assert_eq!(stored(), None);

        System::set_block_number(ready_at);
        assert_ok!(enact(id, call.clone()));
        assert_eq!(stored(), Some(b"v".to_vec()));
        assert!(Tasks::<Test>::get(id).is_none());
        System::assert_last_event(Event::Enacted { id }.into());
        assert_noop!(enact(id, call), Error::<Test>::UnknownTask);
    });
}

#[test]
fn each_class_waits_its_own_delay() {
    new_test_ext().execute_with(|| {
        let recovery = schedule(recovery_call());
        let long = schedule(long_call());
        assert_eq!(
            Tasks::<Test>::get(recovery).map(|t| (t.class, t.ready_at)),
            Some((CallClass::Recovery, 3))
        );
        assert_eq!(
            Tasks::<Test>::get(long).map(|t| (t.class, t.ready_at)),
            Some((CallClass::Long, 31))
        );

        System::set_block_number(30);
        assert_noop!(enact(long, long_call()), Error::<Test>::NotReady);
        System::set_block_number(31);
        assert_ok!(enact(long, long_call()));
    });
}

#[test]
fn enact_requires_the_scheduled_call() {
    new_test_ext().execute_with(|| {
        let id = schedule(set_storage_call(b"v"));
        System::set_block_number(20);
        assert_noop!(
            enact(id, set_storage_call(b"other")),
            Error::<Test>::CallHashMismatch
        );
        assert_noop!(
            RootTimelock::enact(RuntimeOrigin::root(), id, Box::new(set_storage_call(b"v"))),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn an_unenacted_task_expires_after_the_window() {
    new_test_ext().execute_with(|| {
        let last_chance = schedule(set_storage_call(b"v"));
        let too_late = schedule(set_storage_call(b"v"));
        System::set_block_number(11 + 5);
        assert_ok!(enact(last_chance, set_storage_call(b"v")));
        System::set_block_number(11 + 5 + 1);
        assert_noop!(
            enact(too_late, set_storage_call(b"v")),
            Error::<Test>::Expired
        );
    });
}

#[test]
fn a_failing_call_keeps_its_task_for_a_retry() {
    new_test_ext().execute_with(|| {
        let needs_signed =
            RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });
        let id = schedule(needs_signed.clone());
        System::set_block_number(11);
        assert_noop!(enact(id, needs_signed), DispatchError::BadOrigin);
        assert!(Tasks::<Test>::get(id).is_some());
    });
}

#[test]
fn a_call_whose_class_rose_since_scheduling_cannot_run() {
    new_test_ext().execute_with(|| {
        let id = schedule(recovery_call());
        RemarkIsLong::set(&true);
        System::set_block_number(3);
        assert_noop!(enact(id, recovery_call()), Error::<Test>::ClassRaised);
        RemarkIsLong::set(&false);
        assert_ok!(enact(id, recovery_call()));
    });
}

#[test]
fn only_the_guardian_can_cancel() {
    new_test_ext().execute_with(|| {
        let id = schedule(set_storage_call(b"a"));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(ANYONE), id),
            DispatchError::BadOrigin
        );
        // Root is what a compromised sudo key holds; letting it cancel would
        // let that key veto its own replacement forever.
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::root(), id),
            DispatchError::BadOrigin
        );

        assert_ok!(RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), id));
        System::assert_last_event(Event::Cancelled { id }.into());

        System::set_block_number(20);
        assert_noop!(
            enact(id, set_storage_call(b"a")),
            Error::<Test>::UnknownTask
        );
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), id),
            Error::<Test>::UnknownTask
        );
        assert_eq!(stored(), None);
    });
}

#[test]
fn without_a_guardian_root_withdraws_a_task() {
    new_test_ext().execute_with(|| {
        Guardian::<Test>::kill();
        let abandoned = schedule(set_storage_call(b"a"));
        let others = [schedule(set_storage_call(b"b")), schedule(long_call())];
        let withdrawn = schedule(guardian_change(Some(ANYONE)));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), abandoned),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel_all(RuntimeOrigin::signed(GUARDIAN)),
            DispatchError::BadOrigin
        );

        assert_ok!(RootTimelock::cancel(RuntimeOrigin::root(), abandoned));
        System::assert_last_event(Event::Cancelled { id: abandoned }.into());
        assert_ok!(RootTimelock::cancel(RuntimeOrigin::root(), withdrawn));
        let replacement = schedule(guardian_change(Some(GUARDIAN)));
        assert_ok!(RootTimelock::cancel_all(RuntimeOrigin::root()));
        for id in others {
            assert!(Tasks::<Test>::get(id).is_none());
        }
        assert!(Tasks::<Test>::get(replacement).is_some());

        System::set_block_number(31);
        assert_ok!(enact(replacement, guardian_change(Some(GUARDIAN))));
        let after = schedule(set_storage_call(b"c"));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::root(), after),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel_all(RuntimeOrigin::root()),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn root_withdraws_a_pending_guardian_change_and_nothing_else() {
    new_test_ext().execute_with(|| {
        let change = schedule(guardian_change(Some(66)));
        let task = schedule(set_storage_call(b"a"));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::root(), task),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel_all(RuntimeOrigin::root()),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), change),
            Error::<Test>::NotVetoable
        );
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(ANYONE), change),
            DispatchError::BadOrigin
        );

        assert_ok!(RootTimelock::cancel(RuntimeOrigin::root(), change));
        System::assert_last_event(Event::Cancelled { id: change }.into());
        assert_eq!(PendingGuardianChange::<Test>::get(), None);
        System::set_block_number(31);
        assert_noop!(
            enact(change, guardian_change(Some(66))),
            Error::<Test>::UnknownTask
        );
        assert_eq!(Guardian::<Test>::get(), Some(GUARDIAN));
        assert!(Tasks::<Test>::get(task).is_some());
    });
}

#[test]
fn one_guardian_change_is_pending_at_a_time_and_takes_no_vetoable_place() {
    new_test_ext().execute_with(|| {
        let pending = schedule(guardian_change(Some(66)));
        assert_eq!(PendingGuardianChange::<Test>::get(), Some(pending));
        assert_noop!(
            RootTimelock::schedule(RuntimeOrigin::root(), Box::new(guardian_change(Some(67)))),
            Error::<Test>::TooManyTasks
        );
        for _ in 0..MAX_PENDING {
            schedule(set_storage_call(b"a"));
        }
        assert_noop!(
            RootTimelock::schedule(RuntimeOrigin::root(), Box::new(set_storage_call(b"a"))),
            Error::<Test>::TooManyTasks
        );

        // The guardian's veto frees every vetoable place.
        assert_ok!(RootTimelock::cancel_all(RuntimeOrigin::signed(GUARDIAN)));
        assert_eq!(Tasks::<Test>::count(), 1);
        schedule(set_storage_call(b"rotate"));
    });
}

#[test]
fn enacting_or_pruning_a_guardian_change_frees_its_place() {
    new_test_ext().execute_with(|| {
        let enacted = schedule(guardian_change(Some(66)));
        assert_eq!(PendingGuardianChange::<Test>::get(), Some(enacted));
        System::set_block_number(31);
        assert_ok!(enact(enacted, guardian_change(Some(66))));
        assert_eq!(PendingGuardianChange::<Test>::get(), None);

        // Ready at 61, enactable through 66.
        let expired = schedule(guardian_change(Some(67)));
        assert_eq!(PendingGuardianChange::<Test>::get(), Some(expired));
        System::set_block_number(67);
        assert_ok!(RootTimelock::prune(RuntimeOrigin::signed(ANYONE), expired));
        assert_eq!(PendingGuardianChange::<Test>::get(), None);
        let next = schedule(guardian_change(Some(68)));
        assert_eq!(PendingGuardianChange::<Test>::get(), Some(next));
    });
}

#[test]
fn cancel_all_vetoes_every_vetoable_task_in_one_call() {
    new_test_ext().execute_with(|| {
        let vetoable = [
            schedule(set_storage_call(b"a")),
            schedule(recovery_call()),
            schedule(long_call()),
        ];
        let replacement = schedule(guardian_change(Some(ANYONE)));
        assert_noop!(
            RootTimelock::cancel_all(RuntimeOrigin::signed(ANYONE)),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel_all(RuntimeOrigin::root()),
            DispatchError::BadOrigin
        );

        assert_ok!(RootTimelock::cancel_all(RuntimeOrigin::signed(GUARDIAN)));
        for id in vetoable {
            assert!(Tasks::<Test>::get(id).is_none());
            System::assert_has_event(Event::Cancelled { id }.into());
        }
        assert_eq!(Tasks::<Test>::count(), 1);
        assert!(Tasks::<Test>::get(replacement).is_some());
    });
}

#[test]
fn the_queue_is_bounded_and_pruning_frees_a_place() {
    new_test_ext().execute_with(|| {
        let first = schedule(set_storage_call(b"a"));
        for _ in 1..MAX_PENDING {
            schedule(set_storage_call(b"a"));
        }
        assert_noop!(
            RootTimelock::schedule(RuntimeOrigin::root(), Box::new(set_storage_call(b"a"))),
            Error::<Test>::TooManyTasks
        );

        // Ready at 11, enactable through 16: pruning waits for expiry.
        System::set_block_number(16);
        assert_noop!(
            RootTimelock::prune(RuntimeOrigin::signed(ANYONE), first),
            Error::<Test>::NotExpired
        );
        assert_noop!(
            RootTimelock::prune(RuntimeOrigin::root(), first),
            DispatchError::BadOrigin
        );
        System::set_block_number(17);
        assert_ok!(RootTimelock::prune(RuntimeOrigin::signed(ANYONE), first));
        System::assert_last_event(Event::Pruned { id: first }.into());
        assert!(Tasks::<Test>::get(first).is_none());
        assert_noop!(
            RootTimelock::prune(RuntimeOrigin::signed(ANYONE), first),
            Error::<Test>::UnknownTask
        );

        schedule(set_storage_call(b"a"));
        assert_eq!(Tasks::<Test>::count(), MAX_PENDING);
        assert_ok!(RootTimelock::cancel_all(RuntimeOrigin::signed(GUARDIAN)));
        assert_eq!(Tasks::<Test>::count(), 0);
        schedule(set_storage_call(b"a"));
    });
}

#[test]
fn an_authority_recovery_call_waits_the_standard_delay_unless_co_signed() {
    new_test_ext().execute_with(|| {
        let install = || RuntimeCall::System(frame_system::Call::set_heap_pages { pages: 1 });
        let alone = schedule(install());
        let co_signed = schedule(install());
        assert_eq!(
            Tasks::<Test>::get(alone).map(|t| (t.class, t.ready_at)),
            Some((CallClass::AuthorityRecovery, 11))
        );

        System::set_block_number(3);
        assert_noop!(enact(alone, install()), Error::<Test>::NotReady);
        assert_ok!(RootTimelock::fast_track(
            RuntimeOrigin::signed(GUARDIAN),
            co_signed
        ));
        assert_ok!(enact(co_signed, install()));

        System::set_block_number(10);
        assert_noop!(enact(alone, install()), Error::<Test>::NotReady);
        System::set_block_number(11);
        assert_ok!(enact(alone, install()));
    });
}

#[test]
fn the_guardian_cannot_veto_its_own_replacement() {
    new_test_ext().execute_with(|| {
        let call = guardian_change(Some(ANYONE));
        let id = schedule(call.clone());
        let task = Tasks::<Test>::get(id).expect("scheduled");
        assert_eq!((task.class, task.vetoable), (CallClass::Long, false));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), id),
            Error::<Test>::NotVetoable
        );

        System::set_block_number(31);
        assert_ok!(enact(id, call));
        assert_eq!(Guardian::<Test>::get(), Some(ANYONE));
    });
}

#[test]
fn a_guardian_change_is_scheduled_only_on_its_own() {
    new_test_ext().execute_with(|| {
        let wrapped = RuntimeCall::System(frame_system::Call::kill_prefix {
            prefix: KEY.to_vec(),
            subkeys: 0,
        });
        assert_noop!(
            RootTimelock::schedule(RuntimeOrigin::root(), Box::new(wrapped)),
            Error::<Test>::GuardianChangeNotAlone
        );
        assert_eq!(crate::NextTaskId::<Test>::get(), 0);
    });
}

#[test]
fn a_fast_track_never_extends_or_revives_a_task() {
    new_test_ext().execute_with(|| {
        let fast_track = |id| RootTimelock::fast_track(RuntimeOrigin::signed(GUARDIAN), id);
        let ready = schedule(recovery_call());
        let expired = schedule(recovery_call());
        let ready_at = 1 + 2;

        System::set_block_number(ready_at);
        assert_noop!(fast_track(ready), Error::<Test>::AlreadyReady);

        System::set_block_number(ready_at + 5 + 1);
        assert_noop!(fast_track(expired), Error::<Test>::AlreadyReady);
        assert_eq!(
            Tasks::<Test>::get(expired).map(|t| t.ready_at),
            Some(ready_at)
        );
        assert_noop!(enact(expired, recovery_call()), Error::<Test>::Expired);
    });
}

#[test]
fn guardian_fast_tracks_recovery_calls_only() {
    new_test_ext().execute_with(|| {
        let recovery = schedule(recovery_call());
        let standard = schedule(set_storage_call(b"v"));

        assert_noop!(
            RootTimelock::fast_track(RuntimeOrigin::root(), recovery),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::fast_track(RuntimeOrigin::signed(ANYONE), recovery),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::fast_track(RuntimeOrigin::signed(GUARDIAN), standard),
            Error::<Test>::NotFastTrackable
        );

        assert_ok!(RootTimelock::fast_track(
            RuntimeOrigin::signed(GUARDIAN),
            recovery
        ));
        System::assert_last_event(Event::FastTracked { id: recovery }.into());
        assert_ok!(enact(recovery, recovery_call()));
        assert_noop!(
            enact(standard, set_storage_call(b"v")),
            Error::<Test>::NotReady
        );
    });
}

#[test]
fn set_delay_keeps_the_table_valid() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::signed(GUARDIAN), CallClass::Long, 40),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::root(), CallClass::Recovery, 0),
            Error::<Test>::InvalidDelays
        );
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::root(), CallClass::Standard, 31),
            Error::<Test>::InvalidDelays
        );
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::root(), CallClass::Long, 9),
            Error::<Test>::InvalidDelays
        );
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::root(), CallClass::Long, MAX_DELAY + 1),
            Error::<Test>::InvalidDelays
        );
        // It waits the standard delay and has none of its own to set.
        assert_noop!(
            RootTimelock::set_delay(RuntimeOrigin::root(), CallClass::AuthorityRecovery, 20),
            Error::<Test>::InvalidDelays
        );

        assert_ok!(RootTimelock::set_delay(
            RuntimeOrigin::root(),
            CallClass::Long,
            MAX_DELAY
        ));
        System::assert_last_event(
            Event::DelaySet {
                class: CallClass::Long,
                blocks: MAX_DELAY,
            }
            .into(),
        );
        assert_ok!(RootTimelock::set_delay(
            RuntimeOrigin::root(),
            CallClass::Standard,
            3
        ));
        assert_eq!(
            Delays::<Test>::get(),
            DelayTable {
                recovery: 2,
                standard: 3,
                long: MAX_DELAY
            }
        );

        let id = schedule(set_storage_call(b"v"));
        assert_eq!(Tasks::<Test>::get(id).map(|t| t.ready_at), Some(4));
    });
}

#[test]
fn a_delay_change_does_not_move_pending_tasks() {
    new_test_ext().execute_with(|| {
        let id = schedule(set_storage_call(b"v"));
        assert_ok!(RootTimelock::set_delay(
            RuntimeOrigin::root(),
            CallClass::Standard,
            2
        ));
        System::set_block_number(5);
        assert_noop!(enact(id, set_storage_call(b"v")), Error::<Test>::NotReady);
    });
}

#[test]
fn set_guardian_replaces_and_clears() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            RootTimelock::set_guardian(RuntimeOrigin::signed(GUARDIAN), Some(ANYONE)),
            DispatchError::BadOrigin
        );
        assert_ok!(RootTimelock::set_guardian(
            RuntimeOrigin::root(),
            Some(ANYONE)
        ));
        assert_eq!(Guardian::<Test>::get(), Some(ANYONE));
        System::assert_last_event(
            Event::GuardianSet {
                guardian: Some(ANYONE),
            }
            .into(),
        );
        assert_ok!(RootTimelock::set_guardian(RuntimeOrigin::root(), None));
        assert_eq!(Guardian::<Test>::get(), None);
    });
}

#[test]
fn task_ids_are_unique_across_cancellations() {
    new_test_ext().execute_with(|| {
        let a = schedule(set_storage_call(b"v"));
        assert_ok!(RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), a));
        let b = schedule(set_storage_call(b"v"));
        assert_ne!(a, b);
        assert_eq!(
            Tasks::<Test>::get(b),
            Some(Task {
                call_hash: <Test as frame_system::Config>::Hashing::hash_of(&set_storage_call(
                    b"v"
                )),
                class: CallClass::Standard,
                ready_at: 11,
                vetoable: true,
            })
        );
    });
}

#[test]
fn own_calls_wait_the_class_they_protect() {
    let class = |call: Call<Test>| call.class();
    assert_eq!(
        class(Call::set_guardian { guardian: None }),
        CallClass::Long
    );
    assert_eq!(
        class(Call::set_delay {
            class: CallClass::Long,
            blocks: 1
        }),
        CallClass::Long
    );
    assert_eq!(
        class(Call::set_delay {
            class: CallClass::Standard,
            blocks: 1
        }),
        CallClass::Standard
    );
    // Lowering the recovery delay must not become fast-trackable.
    assert_eq!(
        class(Call::set_delay {
            class: CallClass::Recovery,
            blocks: 1
        }),
        CallClass::Standard
    );
    assert_eq!(
        class(Call::schedule {
            call: Box::new(recovery_call())
        }),
        CallClass::Standard
    );
}

#[test]
fn genesis_and_defaults() {
    new_test_ext().execute_with(|| {
        assert_eq!(Delays::<Test>::get(), TestDelays::get());
        assert_eq!(Guardian::<Test>::get(), Some(GUARDIAN));
    });
    sp_io::TestExternalities::default().execute_with(|| {
        assert_eq!(Delays::<Test>::get(), TestDelays::get());
        assert_eq!(Guardian::<Test>::get(), None);
    });
}

#[test]
#[should_panic(
    expected = "root-timelock genesis delays must be non-zero, ordered and at most MaxDelay"
)]
fn genesis_rejects_a_delay_above_the_maximum() {
    genesis_ext(DelayTable {
        recovery: 2,
        standard: 10,
        long: MAX_DELAY + 1,
    });
}

#[test]
fn authority_recovery_waits_the_standard_delay() {
    let table = DelayTable {
        recovery: 1u32,
        standard: 2,
        long: 3,
    };
    assert_eq!(table.of(CallClass::AuthorityRecovery), 2);
    assert_eq!(table.with(CallClass::AuthorityRecovery, 5), None);
    assert_eq!(
        table.with(CallClass::Standard, 3),
        Some(DelayTable {
            recovery: 1,
            standard: 3,
            long: 3
        })
    );
    assert!(CallClass::Recovery < CallClass::AuthorityRecovery);
    assert!(CallClass::AuthorityRecovery < CallClass::Standard);
}

#[test]
fn delay_table_validity() {
    let valid = |t: DelayTable<u32>| t.is_valid(5);
    assert!(valid(DelayTable {
        recovery: 1,
        standard: 1,
        long: 1
    }));
    assert!(valid(DelayTable {
        recovery: 1,
        standard: 2,
        long: 5
    }));
    assert!(!valid(DelayTable {
        recovery: 0,
        standard: 1,
        long: 1
    }));
    assert!(!valid(DelayTable {
        recovery: 2,
        standard: 1,
        long: 3
    }));
    assert!(!valid(DelayTable {
        recovery: 1,
        standard: 3,
        long: 2
    }));
    assert!(!valid(DelayTable {
        recovery: 1,
        standard: 2,
        long: 6
    }));
}

#[test]
fn a_genesis_names_a_guardian_or_says_it_has_none() {
    let genesis = |guardian, unguarded| GenesisConfig::<Test> {
        delays: TestDelays::get(),
        guardian,
        unguarded,
    };
    assert_eq!(genesis(Some(GUARDIAN), false).ensure_guarded(), Ok(()));
    assert_eq!(genesis(None, true).ensure_guarded(), Ok(()));
    assert!(genesis(None, false).ensure_guarded().is_err());
    assert!(GenesisConfig::<Test>::default().ensure_guarded().is_err());
    assert!(genesis(Some(GUARDIAN), true).ensure_guarded().is_err());
}

#[cfg(feature = "try-runtime")]
#[test]
fn try_state_bounds_the_vetoable_queue_and_tracks_the_guardian_change() {
    use frame_support::traits::Hooks;
    new_test_ext().execute_with(|| {
        let check = || <RootTimelock as Hooks<u64>>::try_state(System::block_number());
        let change = schedule(guardian_change(Some(66)));
        for _ in 0..MAX_PENDING {
            schedule(set_storage_call(b"a"));
        }
        assert_ok!(check());

        PendingGuardianChange::<Test>::kill();
        assert!(check().is_err());
        PendingGuardianChange::<Test>::put(change + 1);
        assert!(check().is_err());
        PendingGuardianChange::<Test>::put(change);
        assert_ok!(check());
    });
}
