//! Paid Operational-class calls. Operational weight may take the whole block,
//! beyond Normal's share, so `ChargeMotra` admits a paid Operational call only
//! on a path the runtime names for its signer, and R counts what it consumes.

use crate::*;
use frame_support::{
    assert_ok,
    dispatch::{DispatchClass, GetDispatchInfo},
    traits::{GetCallMetadata, Hooks},
    BoundedBTreeSet,
};
use pallet_motra::fee::ChargeMotra;
use parity_scale_codec::{Decode, Encode};
use sp_keyring::Sr25519Keyring::{self as Keyring, Alice, Bob, Charlie, Dave, Eve, Ferdie};
use sp_runtime::{
    traits::{Dispatchable, Hash as _, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionPriority, TransactionValidity},
    BuildStorage,
};
use std::collections::{BTreeMap, BTreeSet};

const SUDO: Keyring = Alice;
const MEMBER: Keyring = Bob;
const GUARDIAN: Keyring = Charlie;
const RESCUER: Keyring = Dave;
const ATTACKER: Keyring = Ferdie;
/// Signed envelope: address, signature, era, nonce and length prefix.
const ENVELOPE: usize = 105;

type Key = (String, String);

#[derive(Clone, Copy, Debug)]
enum Payer {
    /// Any funded signer: permissionless settlement keepers and watchers.
    Anyone,
    /// An attestation committee member.
    Member,
    /// The guardian, taken first.
    Guardian,
    /// Any signer, only while the runtime upgrade it carries is authorized.
    Authorized,
    /// No signer: Root reaches these through its own paths.
    Nobody,
}

/// Every Operational-class call in the runtime, as decoded with zeroed
/// arguments, and who may pay to send it signed.
const OPERATIONAL: &[(&str, &str, Payer)] = &[
    ("System", "set_heap_pages", Payer::Nobody),
    ("System", "set_code", Payer::Nobody),
    ("System", "set_code_without_checks", Payer::Nobody),
    ("System", "set_storage", Payer::Nobody),
    ("System", "kill_storage", Payer::Nobody),
    ("System", "kill_prefix", Payer::Nobody),
    ("System", "authorize_upgrade", Payer::Nobody),
    ("System", "authorize_upgrade_without_checks", Payer::Nobody),
    ("System", "apply_authorized_upgrade", Payer::Authorized),
    ("Utility", "batch", Payer::Nobody),
    ("Utility", "batch_all", Payer::Nobody),
    ("Utility", "force_batch", Payer::Nobody),
    ("Treasury", "remove_approval", Payer::Nobody),
    ("IntentSettlement", "attest_intent", Payer::Member),
    ("IntentSettlement", "request_voucher", Payer::Member),
    ("IntentSettlement", "settle_claim", Payer::Member),
    ("IntentSettlement", "expire_policy_mirror", Payer::Member),
    ("IntentSettlement", "credit_deposit", Payer::Member),
    ("IntentSettlement", "set_pool_utilization", Payer::Nobody),
    (
        "IntentSettlement",
        "set_min_signer_threshold",
        Payer::Nobody,
    ),
    ("IntentSettlement", "settle_batch_atomic", Payer::Member),
    ("IntentSettlement", "attest_batch_intents", Payer::Member),
    ("IntentSettlement", "request_batch_vouchers", Payer::Member),
    ("IntentSettlement", "request_settle", Payer::Anyone),
    ("IntentSettlement", "attest_settle", Payer::Member),
    ("IntentSettlement", "request_batch_settle", Payer::Anyone),
    ("IntentSettlement", "attest_batch_settle", Payer::Member),
    ("IntentSettlement", "request_expire_policy", Payer::Anyone),
    ("IntentSettlement", "attest_expire_policy", Payer::Member),
    ("IntentSettlement", "post_settlement_bond", Payer::Anyone),
    (
        "IntentSettlement",
        "slash_bad_settlement_evidence",
        Payer::Anyone,
    ),
    ("IntentSettlement", "release_settlement_bond", Payer::Anyone),
    (
        "IntentSettlement",
        "supersede_settlement_request",
        Payer::Member,
    ),
    ("RootTimelock", "cancel", Payer::Guardian),
    ("RootTimelock", "fast_track", Payer::Guardian),
    ("RootTimelock", "cancel_all", Payer::Guardian),
    ("RootTimelock", "approve", Payer::Guardian),
];

/// Calls whose arguments include an uninhabited type, so no extrinsic can
/// carry them.
const UNCONSTRUCTIBLE: &[(&str, &str)] = &[
    ("Grandpa", "report_equivocation"),
    ("Grandpa", "report_equivocation_unsigned"),
];

/// Every call that carries another call; its class is the class of what it
/// carries, so each is decided by the path it dispatches under.
const WRAPPERS: &[(&str, &str)] = &[
    ("Sudo", "sudo"),
    ("Sudo", "sudo_unchecked_weight"),
    ("Sudo", "sudo_as"),
    ("Multisig", "as_multi_threshold_1"),
    ("Multisig", "as_multi"),
    ("Utility", "batch"),
    ("Utility", "as_derivative"),
    ("Utility", "batch_all"),
    ("Utility", "dispatch_as"),
    ("Utility", "force_batch"),
    ("Utility", "with_weight"),
    ("Recovery", "as_recovered"),
    ("RootTimelock", "schedule"),
    ("RootTimelock", "enact"),
    ("RootTimelock", "enact_approved"),
];

fn acct(who: Keyring) -> AccountId {
    who.to_account_id()
}

fn ext(guardian: Option<Keyring>) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("system genesis");
    pallet_balances::GenesisConfig::<Runtime> {
        balances: Keyring::iter()
            .map(|who| (acct(who), 1_000_000_000_000))
            .collect(),
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");
    pallet_sudo::GenesisConfig::<Runtime> {
        key: Some(acct(SUDO)),
    }
    .assimilate_storage(&mut storage)
    .expect("sudo genesis");
    pallet_root_timelock::GenesisConfig::<Runtime> {
        delays: pallet_root_timelock::DelayTable {
            recovery: 5,
            standard: 50,
            long: 200,
        },
        unguarded: guardian.is_none(),
        guardian: guardian.map(acct),
    }
    .assimilate_storage(&mut storage)
    .expect("root-timelock genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| {
        System::set_block_number(1);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.max_balance = u128::MAX;
            p.decay_rate_per_block = Perbill::one();
            p.generation_per_matra_per_block = 0;
        });
        for who in Keyring::iter() {
            pallet_motra::MotraBalances::<Runtime>::insert(acct(who), u128::MAX / 4);
        }
        let members: BoundedBTreeSet<
            AccountId,
            <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
        > = [acct(MEMBER), acct(Eve)]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .try_into()
            .expect("committee bound");
        pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(members);
        pallet_orinq_receipts::AttestationThreshold::<Runtime>::put(1);
    });
    ext
}

fn len(call: &RuntimeCall) -> usize {
    call.encoded_size() + ENVELOPE
}

fn validity(who: Keyring, call: &RuntimeCall) -> TransactionValidity {
    ChargeMotra::<Runtime>::new().validate(&acct(who), call, &call.get_dispatch_info(), len(call))
}

/// Invalid as a call in the pool, and again before dispatch.
fn refused(who: Keyring, call: &RuntimeCall) -> bool {
    validity(who, call) == Err(InvalidTransaction::Call.into())
        && ChargeMotra::<Runtime>::new()
            .pre_dispatch(&acct(who), call, &call.get_dispatch_info(), len(call))
            .err()
            == Some(InvalidTransaction::Call.into())
}

fn new_block() {
    frame_system::BlockWeight::<Runtime>::kill();
    frame_system::AllExtrinsicsLen::<Runtime>::kill();
}

/// Takes a signed call into the block as the author does: pool validity,
/// block admission, payment, dispatch and both post-dispatch refunds.
fn apply(who: Keyring, call: &RuntimeCall) -> bool {
    let info = call.get_dispatch_info();
    let len = len(call);
    if validity(who, call).is_err()
        || frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, len).is_err()
    {
        return false;
    }
    let pre = ChargeMotra::<Runtime>::new()
        .pre_dispatch(&acct(who), call, &info, len)
        .expect("valid in the pool, valid before dispatch");
    let (post, result) = match call.clone().dispatch(RuntimeOrigin::signed(acct(who))) {
        Ok(post) => (post, Ok(())),
        Err(e) => (e.post_info, Err(e.error)),
    };
    assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(
        None, &info, &post, len, &result
    ));
    assert_ok!(ChargeMotra::<Runtime>::post_dispatch(
        Some(pre),
        &info,
        &post,
        len,
        &result
    ));
    true
}

/// Every constructible call variant in the runtime, decoded with zeroed
/// arguments and keyed by pallet and call; the variants that carry another
/// call; and the variants that cannot be decoded at all.
fn sweep() -> (BTreeMap<Key, RuntimeCall>, BTreeSet<Key>, BTreeSet<Key>) {
    use scale_info::{PortableRegistry, Registry, TypeDef};
    let mut registry = Registry::new();
    let call_id = registry
        .register_type(&scale_info::meta_type::<RuntimeCall>())
        .id;
    let registry = PortableRegistry::from(registry);
    let variants = |id: u32| match &registry.resolve(id).expect("registered").type_def {
        TypeDef::Variant(def) => def.variants.clone(),
        other => panic!("type {id} is not an enum: {other:?}"),
    };
    let carries_call = |id: u32| {
        id == call_id
            || matches!(
                &registry.resolve(id).expect("registered").type_def,
                TypeDef::Sequence(seq) if seq.type_param.id == call_id
            )
    };
    let (mut calls, mut wrappers, mut unconstructible) =
        (BTreeMap::new(), BTreeSet::new(), BTreeSet::new());
    for pallet in variants(call_id) {
        for call in variants(pallet.fields[0].ty.id) {
            let key = (pallet.name.to_string(), call.name.to_string());
            if call.fields.iter().any(|field| carries_call(field.ty.id)) {
                wrappers.insert(key.clone());
            }
            let mut bytes = vec![pallet.index, call.index];
            bytes.resize(4096, 0);
            match RuntimeCall::decode(&mut &bytes[..]) {
                Ok(decoded) => {
                    calls.insert(key, decoded);
                }
                Err(_) => {
                    unconstructible.insert(key);
                }
            }
        }
    }
    (calls, wrappers, unconstructible)
}

fn zeroed_operational() -> BTreeMap<Key, RuntimeCall> {
    sweep()
        .0
        .into_iter()
        .filter(|(_, call)| call.get_dispatch_info().class == DispatchClass::Operational)
        .collect()
}

fn keys(list: &[(&str, &str)]) -> BTreeSet<Key> {
    list.iter()
        .map(|(pallet, call)| (pallet.to_string(), call.to_string()))
        .collect()
}

fn kill_prefix(subkeys: u32) -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::kill_prefix {
        prefix: vec![],
        subkeys,
    })
}

/// The Operational room one extrinsic can declare after its signed base.
fn operational_room() -> u64 {
    let op = RuntimeBlockWeights::get()
        .get(DispatchClass::Operational)
        .clone();
    op.max_total.expect("Operational budget").ref_time() - op.base_extrinsic.ref_time()
}

/// `kill_prefix` sized to fill a block on its own.
fn block_filling_kill_prefix() -> RuntimeCall {
    let weight = |n| kill_prefix(n).get_dispatch_info().weight.ref_time();
    kill_prefix(((operational_room() - weight(0)) / (weight(1) - weight(0))) as u32)
}

fn cancel_all() -> RuntimeCall {
    RuntimeCall::RootTimelock(pallet_root_timelock::Call::cancel_all {})
}

fn remove_approval() -> RuntimeCall {
    RuntimeCall::Treasury(pallet_treasury::Call::remove_approval { proposal_id: 0 })
}

fn sudo(call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::Sudo(pallet_sudo::Call::sudo {
        call: Box::new(call),
    })
}

fn batch(calls: Vec<RuntimeCall>) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::batch { calls })
}

fn with_weight(call: RuntimeCall, ref_time: u64) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::with_weight {
        call: Box::new(call),
        weight: Weight::from_parts(ref_time, 0),
    })
}

fn as_recovered(account: Keyring, call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::Recovery(pallet_recovery::Call::as_recovered {
        account: acct(account).into(),
        call: Box::new(call),
    })
}

fn enact(id: pallet_root_timelock::TaskId, call: RuntimeCall) -> RuntimeCall {
    RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact {
        id,
        call: Box::new(call),
    })
}

fn zeroed<T: Decode>() -> T {
    T::decode(&mut &[0u8; 4096][..]).expect("decodes from zeroes")
}

fn attest_settle() -> RuntimeCall {
    RuntimeCall::IntentSettlement(pallet_intent_settlement::Call::attest_settle {
        claim_id: Default::default(),
        signatures: vec![],
    })
}

fn request_batch_settle(entries: u32) -> RuntimeCall {
    let entry: pallet_intent_settlement::SettleAttestedBatchEntry = zeroed();
    RuntimeCall::IntentSettlement(pallet_intent_settlement::Call::request_batch_settle {
        entries: vec![entry; entries as usize]
            .try_into()
            .expect("within MaxSettleBatch"),
        bond_amount: IntentSettlementMinSettlementBond::get(),
    })
}

fn transfer() -> RuntimeCall {
    RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
        dest: acct(Eve).into(),
        value: 1,
    })
}

fn remark() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
}

/// Every Operational vector an unprivileged funded signer can try, each at
/// the largest declaration that fits a block where the call chooses it.
fn attacker_vectors() -> Vec<RuntimeCall> {
    let fill = block_filling_kill_prefix();
    let room = operational_room();
    let per_item = |n: u32| {
        RuntimeCall::System(frame_system::Call::set_storage {
            items: vec![(vec![], vec![]); n as usize],
        })
        .get_dispatch_info()
        .weight
        .ref_time()
    };
    let items = ((room - per_item(0)) / (per_item(1) - per_item(0))) as usize;
    // Block-filling vectors first, so any one admitted leaves no room.
    let mut vectors = vec![
        fill.clone(),
        RuntimeCall::System(frame_system::Call::set_storage {
            items: vec![(vec![], vec![]); items],
        }),
        RuntimeCall::System(frame_system::Call::kill_storage {
            keys: vec![vec![]; items],
        }),
        with_weight(cancel_all(), room),
        with_weight(fill.clone(), 0),
        sudo(fill.clone()),
        RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
            call: Box::new(cancel_all()),
            weight: Weight::from_parts(room, 0),
        }),
        RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
            who: acct(SUDO).into(),
            call: Box::new(fill.clone()),
        }),
        batch(vec![fill.clone()]),
        RuntimeCall::Utility(pallet_utility::Call::batch_all {
            calls: vec![fill.clone()],
        }),
        RuntimeCall::Utility(pallet_utility::Call::force_batch {
            calls: vec![fill.clone()],
        }),
        RuntimeCall::Utility(pallet_utility::Call::as_derivative {
            index: 0,
            call: Box::new(fill.clone()),
        }),
        RuntimeCall::Utility(pallet_utility::Call::dispatch_as {
            as_origin: Box::new(frame_system::RawOrigin::Root.into()),
            call: Box::new(fill.clone()),
        }),
        RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
            other_signatories: vec![acct(SUDO)],
            call: Box::new(fill.clone()),
        }),
        as_recovered(SUDO, fill.clone()),
        enact(0, fill.clone()),
        RuntimeCall::RootTimelock(pallet_root_timelock::Call::enact_approved {
            call: Box::new(fill),
        }),
    ];
    vectors.extend(zeroed_operational().into_values());
    vectors
}

#[test]
fn operational_sweep_names_every_operational_call_and_wrapper() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let (_, wrappers, unconstructible) = sweep();
        assert_eq!(unconstructible, keys(UNCONSTRUCTIBLE));
        let decided: BTreeSet<Key> = OPERATIONAL
            .iter()
            .map(|(pallet, call, _)| (pallet.to_string(), call.to_string()))
            .collect();
        assert_eq!(
            zeroed_operational().into_keys().collect::<BTreeSet<_>>(),
            decided,
            "an Operational call was added or removed; decide who may pay for it"
        );
        assert_eq!(
            wrappers,
            keys(WRAPPERS),
            "a call-carrying wrapper was added or removed; decide its path"
        );
    });
}

#[test]
fn operational_calls_are_paid_only_on_their_named_paths() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let calls = zeroed_operational();
        for (pallet, name, payer) in OPERATIONAL {
            let call = &calls[&(pallet.to_string(), name.to_string())];
            let context = format!("{pallet}::{name} ({payer:?})");
            match payer {
                Payer::Anyone => {
                    let valid = validity(ATTACKER, call).expect(&context);
                    assert!(valid.priority < TransactionPriority::MAX - 1, "{context}");
                }
                Payer::Member => {
                    assert!(refused(ATTACKER, call), "{context}: non-member admitted");
                    let valid = validity(MEMBER, call).expect(&context);
                    assert!(valid.priority < TransactionPriority::MAX - 1, "{context}");
                }
                Payer::Guardian => {
                    assert!(refused(ATTACKER, call), "{context}: non-guardian admitted");
                    assert_eq!(
                        validity(GUARDIAN, call).expect(&context).priority,
                        TransactionPriority::MAX,
                        "{context}"
                    );
                }
                Payer::Authorized => {
                    assert!(refused(ATTACKER, call), "{context}: nothing is authorized");
                }
                Payer::Nobody => {
                    for who in [ATTACKER, MEMBER, SUDO, GUARDIAN] {
                        assert!(refused(who, call), "{context}: {who:?} admitted");
                    }
                }
            }
        }
    });
}

#[test]
fn operational_signed_upgrade_is_paid_only_while_authorized() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let code = b"next runtime".to_vec();
        let apply = |code: &[u8]| {
            RuntimeCall::System(frame_system::Call::apply_authorized_upgrade {
                code: code.to_vec(),
            })
        };
        assert!(refused(ATTACKER, &apply(&code)), "nothing is authorized");
        assert_ok!(
            RuntimeCall::System(frame_system::Call::authorize_upgrade_without_checks {
                code_hash: BlakeTwo256::hash(&code),
            })
            .dispatch(RuntimeOrigin::root())
        );
        assert_ok!(validity(ATTACKER, &apply(&code)));
        assert!(
            refused(ATTACKER, &apply(b"other runtime")),
            "only the authorized code"
        );
    });
}

#[test]
fn operational_with_weight_cancel_all_from_a_non_guardian_is_invalid() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let stuffer = with_weight(cancel_all(), operational_room());
        assert_eq!(
            stuffer.get_dispatch_info().class,
            DispatchClass::Operational
        );
        assert_eq!(
            validity(ATTACKER, &stuffer),
            Err(InvalidTransaction::Call.into())
        );
        assert!(refused(ATTACKER, &stuffer));
        assert!(
            refused(GUARDIAN, &stuffer),
            "the veto is the bare call only"
        );
    });
}

#[test]
fn operational_kill_prefix_stuffing_is_invalid() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let stuffer = block_filling_kill_prefix();
        assert!(stuffer.get_dispatch_info().weight.ref_time() * 10 > operational_room() * 9);
        let failures = Motra::insufficient_motra_failures();
        assert!(refused(ATTACKER, &stuffer));
        assert!(refused(ATTACKER, &batch(vec![stuffer.clone()])));
        assert!(refused(ATTACKER, &sudo(stuffer)));
        assert_eq!(
            Motra::insufficient_motra_failures(),
            failures,
            "refused before payment"
        );
    });
}

#[test]
fn operational_vectors_leave_room_for_normal_transfers() {
    ext(Some(GUARDIAN)).execute_with(|| {
        new_block();
        let mut admitted = BTreeSet::new();
        for call in attacker_vectors() {
            let name = call.get_call_metadata().function_name;
            if apply(ATTACKER, &call) {
                admitted.insert(name.to_string());
            } else {
                assert!(
                    validity(ATTACKER, &call).is_ok() || refused(ATTACKER, &call),
                    "{name} must be refused as a call"
                );
            }
        }
        let info = transfer().get_dispatch_info();
        assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
            &info,
            len(&transfer())
        ));
        let keepers: BTreeSet<String> = OPERATIONAL
            .iter()
            .filter(|(_, _, payer)| matches!(payer, Payer::Anyone))
            .map(|(_, name, _)| name.to_string())
            .collect();
        assert_eq!(admitted, keepers, "only bounded keeper calls are admitted");
    });
}

#[test]
fn operational_wrappers_admit_only_the_paths_they_dispatch_under() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let fill = block_filling_kill_prefix();
        // Root's own exempt calls, signed by the sudo key alone.
        assert_ok!(validity(SUDO, &sudo(remove_approval())));
        assert!(refused(ATTACKER, &sudo(remove_approval())));
        assert!(refused(SUDO, &sudo(fill.clone())), "not exempt");
        assert!(
            refused(SUDO, &sudo(cancel_all())),
            "a guarded chain's sudo key cannot veto"
        );
        assert!(refused(
            SUDO,
            &RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                call: Box::new(remove_approval()),
                weight: Weight::zero(),
            })
        ));
        // Same-origin batches: every inner call on its own path.
        assert_ok!(validity(
            MEMBER,
            &batch(vec![attest_settle(), attest_settle()])
        ));
        assert!(refused(ATTACKER, &batch(vec![attest_settle()])));
        assert!(refused(MEMBER, &batch(vec![attest_settle(), fill.clone()])));
        assert!(refused(MEMBER, &batch(vec![])));
        // Derived and multisig origins are judged as the account they become.
        assert_ok!(validity(
            ATTACKER,
            &RuntimeCall::Utility(pallet_utility::Call::as_derivative {
                index: 0,
                call: Box::new(request_batch_settle(0)),
            })
        ));
        assert!(refused(
            MEMBER,
            &RuntimeCall::Utility(pallet_utility::Call::as_derivative {
                index: 0,
                call: Box::new(attest_settle()),
            })
        ));
        // A rescuer acts as the account it recovered, here the sudo key.
        assert!(refused(
            RESCUER,
            &as_recovered(SUDO, sudo(remove_approval()))
        ));
        pallet_recovery::Proxy::<Runtime>::insert(acct(RESCUER), acct(SUDO));
        assert_ok!(validity(
            RESCUER,
            &as_recovered(SUDO, sudo(remove_approval()))
        ));
        assert!(refused(RESCUER, &as_recovered(SUDO, fill.clone())));
        assert!(refused(
            ATTACKER,
            &as_recovered(SUDO, sudo(remove_approval()))
        ));
        // Anyone enacts a ready task, and nothing else.
        let task = sudo(RuntimeCall::RootTimelock(
            pallet_root_timelock::Call::schedule {
                call: Box::new(remove_approval()),
            },
        ));
        let id = pallet_root_timelock::NextTaskId::<Runtime>::get();
        assert_ok!(task.dispatch(RuntimeOrigin::signed(acct(SUDO))));
        assert!(
            refused(ATTACKER, &enact(id, remove_approval())),
            "not ready"
        );
        System::set_block_number(1 + 50);
        assert_ok!(validity(ATTACKER, &enact(id, remove_approval())));
        assert!(refused(ATTACKER, &enact(id, fill.clone())), "wrong call");
        assert!(
            refused(ATTACKER, &enact(id + 1, remove_approval())),
            "unknown task"
        );
    });
    ext(None).execute_with(|| {
        assert_ok!(validity(SUDO, &sudo(cancel_all())));
        assert!(refused(ATTACKER, &sudo(cancel_all())));
    });
}

/// R after a block that consumed `consumed` as Normal weight alone, from the
/// current R; the current block's state is left untouched.
fn rate_after_normal(consumed: Weight) -> u128 {
    let (params, block) = (Motra::params(), frame_system::BlockWeight::<Runtime>::get());
    frame_system::BlockWeight::<Runtime>::kill();
    frame_system::BlockWeight::<Runtime>::mutate(|w| w.set(consumed, DispatchClass::Normal));
    Motra::on_finalize(System::block_number());
    let rate = Motra::params().congestion_rate;
    pallet_motra::Params::<Runtime>::put(params);
    frame_system::BlockWeight::<Runtime>::put(block);
    rate
}

#[test]
fn operational_duty_traffic_raises_r_like_equal_normal_traffic() {
    ext(Some(GUARDIAN)).execute_with(|| {
        let max_normal = RuntimeBlockWeights::get()
            .get(DispatchClass::Normal)
            .max_total
            .expect("Normal budget");
        for share in [30u64, 70, 90] {
            let target = max_normal.ref_time() * share / 100;
            new_block();
            while frame_system::Pallet::<Runtime>::block_weight()
                .get(DispatchClass::Operational)
                .ref_time()
                < target
            {
                assert!(apply(MEMBER, &attest_settle()), "duty fits");
            }
            let consumed =
                *frame_system::Pallet::<Runtime>::block_weight().get(DispatchClass::Operational);
            let expected = rate_after_normal(consumed);
            Motra::on_finalize(System::block_number());
            assert_eq!(
                Motra::params().congestion_rate,
                expected,
                "{share}% of Normal capacity in Operational duties"
            );
        }
        assert!(Motra::params().congestion_rate > 0);
    });
}

#[test]
fn operational_guardian_veto_is_taken_first_without_moving_r() {
    for veto in [false, true] {
        ext(Some(GUARDIAN)).execute_with(|| {
            let max_normal = RuntimeBlockWeights::get()
                .get(DispatchClass::Normal)
                .max_total
                .expect("Normal budget");
            new_block();
            while frame_system::Pallet::<Runtime>::block_weight()
                .get(DispatchClass::Operational)
                .ref_time()
                < max_normal.ref_time() * 3 / 5
            {
                assert!(apply(MEMBER, &attest_settle()));
            }
            let duties =
                *frame_system::Pallet::<Runtime>::block_weight().get(DispatchClass::Operational);
            if veto {
                assert_eq!(
                    validity(GUARDIAN, &cancel_all()).expect("veto").priority,
                    TransactionPriority::MAX
                );
                assert!(apply(GUARDIAN, &cancel_all()), "the veto lands");
                assert!(frame_system::Pallet::<Runtime>::block_weight()
                    .total()
                    .any_gt(duties));
            }
            let expected = rate_after_normal(duties);
            Motra::on_finalize(System::block_number());
            assert_eq!(
                Motra::params().congestion_rate,
                expected,
                "a guardian veto moved R (veto: {veto})"
            );
        });
    }
}

/// Fills `blocks` blocks from R=0 with `call` signed by `who`, admitting as
/// many copies as the author would. Returns R after each block, the total fee
/// paid and the shares of the block's weight and length the copies take.
fn ramp(who: Keyring, call: &RuntimeCall, blocks: u32) -> (Vec<u128>, u128, Perbill, Perbill) {
    pallet_motra::Params::<Runtime>::mutate(|p| p.congestion_rate = 0);
    let info = call.get_dispatch_info();
    let len = len(call);
    new_block();
    let mut copies = 0u128;
    while frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, len).is_ok() {
        copies += 1;
    }
    let (full, full_len) = (
        frame_system::BlockWeight::<Runtime>::get(),
        frame_system::AllExtrinsicsLen::<Runtime>::get(),
    );
    let weight_share = Perbill::from_rational(
        full.total().ref_time(),
        RuntimeBlockWeights::get().max_block.ref_time(),
    );
    let length_share = Perbill::from_rational(
        full_len.unwrap_or_default(),
        *RuntimeBlockLength::get()
            .max
            .get(DispatchClass::Operational),
    );
    let (mut rates, mut cost) = (Vec::new(), 0u128);
    for block in 0..blocks {
        frame_system::BlockWeight::<Runtime>::put(full.clone());
        frame_system::AllExtrinsicsLen::<Runtime>::set(full_len);
        let burned = Motra::total_burned();
        ChargeMotra::<Runtime>::new()
            .pre_dispatch(&acct(who), call, &info, len)
            .expect("admitted and paid");
        cost += (Motra::total_burned() - burned) * copies;
        Motra::on_finalize(block);
        rates.push(Motra::params().congestion_rate);
    }
    (rates, cost, weight_share, length_share)
}

/// A remark whose signed extrinsic takes the whole Normal length budget.
fn length_filling_remark() -> RuntimeCall {
    let budget = *RuntimeBlockLength::get().max.get(DispatchClass::Normal) as usize;
    let mut payload = budget - ENVELOPE;
    loop {
        let call = RuntimeCall::System(frame_system::Call::remark {
            remark: vec![0; payload],
        });
        match len(&call) {
            l if l > budget => payload -= l - budget,
            _ => return call,
        }
    }
}

#[test]
fn stuffers_of_weight_or_length_ramp_r_like_the_remark_ramp() {
    ext(Some(GUARDIAN)).execute_with(|| {
        const BLOCKS: u32 = 1_000;
        let (remark_rates, remark_cost, _, _) = ramp(ATTACKER, &remark(), BLOCKS);
        let max_batch = <Runtime as pallet_intent_settlement::Config>::MaxSettleBatch::get();
        let big_remark = length_filling_remark();
        assert_eq!(
            len(&big_remark) as u32,
            *RuntimeBlockLength::get().max.get(DispatchClass::Normal)
        );
        for (name, stuffer) in [
            ("request_batch_settle(0)", request_batch_settle(0)),
            ("request_batch_settle(max)", request_batch_settle(max_batch)),
            ("length-filling remark", big_remark),
        ] {
            let (rates, cost, weight, length) = ramp(ATTACKER, &stuffer, BLOCKS);
            eprintln!(
                "{name}: {} bytes, weight share {weight:?}, length share {length:?}, final R {}, cost {cost}; remark ramp: final R {}, cost {remark_cost}",
                len(&stuffer),
                rates[rates.len() - 1],
                remark_rates[remark_rates.len() - 1]
            );
            for (block, (rate, remark_rate)) in rates.iter().zip(&remark_rates).enumerate() {
                assert!(
                    rate >= remark_rate,
                    "{name}, block {block}: R {rate} below the remark ramp's {remark_rate}"
                );
            }
            // The remark ramp also pays for its 3% of length work; a stuffer
            // bound by one dimension pays within 10% of it, or more.
            assert!(
                cost * 10 >= remark_cost * 9 && cost <= remark_cost * 10,
                "{name}: ramp cost {cost} vs remark ramp {remark_cost}"
            );
        }
    });
}
