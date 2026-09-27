use crate::{mock::*, Call, CallClass, DelayTable, Delays, Error, Event, Guardian, Task, Tasks};
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
fn without_a_guardian_nobody_cancels() {
    new_test_ext().execute_with(|| {
        Guardian::<Test>::kill();
        let id = schedule(set_storage_call(b"a"));
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::signed(GUARDIAN), id),
            DispatchError::BadOrigin
        );
        assert_noop!(
            RootTimelock::cancel(RuntimeOrigin::root(), id),
            DispatchError::BadOrigin
        );
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
