//! Storage access is priced at RocksDB cost, and every dispatchable and hook
//! fits the block budget it is charged against.

use crate::*;
use frame_support::{
    dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo, Pays},
    traits::Get,
    weights::{constants::RocksDbWeight, RuntimeDbWeight},
};
use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::{PortableRegistry, Registry, TypeDef, TypeDefPrimitive};
use sp_runtime::BuildStorage;

fn genesis() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("system genesis")
        .into()
}

#[test]
fn storage_access_is_priced_at_rocksdb_cost() {
    let configured = <<Runtime as frame_system::Config>::DbWeight as Get<RuntimeDbWeight>>::get();
    let rocksdb = RocksDbWeight::get();
    assert_eq!(
        (configured.read, configured.write),
        (rocksdb.read, rocksdb.write)
    );
}

/// The weights that priced storage at RocksDB cost before the runtime did.
#[test]
fn motra_and_runtime_storage_prices_are_unchanged() {
    use pallet_motra::weights::WeightInfo;
    type Motra = <Runtime as pallet_motra::Config>::WeightInfo;
    let ref_time = |w: Weight| (w.ref_time(), w.proof_size());
    assert_eq!(
        ref_time(pallet_motra::checkpoint_weight::<Runtime>()),
        (148_885_000, 3_533)
    );
    for (name, weight, expected) in [
        ("fee_path", Motra::fee_path(), (1_186_852_000, 30_847)),
        ("claim_motra", Motra::claim_motra(), (1_047_014_000, 29_346)),
        ("set_delegatee", Motra::set_delegatee(), (1_148_657_000, 29_346)),
        ("reconcile", Motra::reconcile(), (1_048_197_000, 29_346)),
    ] {
        assert_eq!(ref_time(weight), expected, "{name}");
    }
    assert_eq!(
        ref_time(crate::motra_duty::threshold_read()),
        (25_000_000, 1_489)
    );
    assert_eq!(
        ref_time(<root_gate::TimelockClassifier as pallet_root_timelock::ClassifyCall<
            RuntimeCall,
        >>::weight(&RuntimeCall::System(
            frame_system::Call::remark { remark: vec![] }
        ))),
        (30_000_000, 0)
    );
}

/// How a call's worst case is reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Envelope {
    /// Every argument that drives the weight is bounded; the audit encodes
    /// each at its bound.
    Bounded,
    /// The caller sizes the work: nested calls, a caller-supplied weight or
    /// count, or an unbounded list. No finite worst case exists, so
    /// admission must refuse an oversized one; the audit encodes the
    /// smallest.
    CallerSized,
}

const CALLER_SIZED: &[&str] = &[
    "System.set_storage",
    "System.kill_storage",
    "System.kill_prefix",
    "Balances.upgrade_accounts",
    "Sudo.sudo",
    "Sudo.sudo_unchecked_weight",
    "Sudo.sudo_as",
    "Multisig.as_multi_threshold_1",
    "Multisig.as_multi",
    "Multisig.approve_as_multi",
    "Utility.batch",
    "Utility.as_derivative",
    "Utility.batch_all",
    "Utility.dispatch_as",
    "Utility.force_batch",
    "Utility.with_weight",
    "Recovery.as_recovered",
    "RootTimelock.schedule",
    "RootTimelock.enact",
    "RootTimelock.enact_approved",
];

/// The worst-case length of each top-level list argument. A list whose
/// length does not enter the call's weight is encoded empty.
fn list_length(path: &str) -> u32 {
    let normal_length = *RuntimeBlockLength::get().max.get(DispatchClass::Normal);
    match path {
        // The longest remark a signed Normal extrinsic can carry.
        "System.remark.remark" | "System.remark_with_event.remark" => {
            let envelope = signed_length(&RuntimeCall::System(frame_system::Call::remark {
                remark: vec![0; normal_length as usize],
            })) as u32
                - normal_length;
            normal_length - envelope
        }
        "System.set_code.code"
        | "System.set_code_without_checks.code"
        | "System.apply_authorized_upgrade.code"
        | "System.kill_prefix.prefix"
        | "PalletSession.set_keys.proof"
        | "SessionCommitteeManagement.set_main_chain_scripts.committee_candidate_address"
        | "NativeTokenManagement.set_main_chain_scripts.native_token_asset_name"
        | "NativeTokenManagement.set_main_chain_scripts.illiquid_supply_validator_address"
        | "IntentSettlement.request_voucher.voucher"
        | "IntentSettlement.request_voucher.fairness_proof"
        | "Billing.pay_request.endpoint_class"
        | "Billing.governance_set_endpoint_price.endpoint_class" => 0,
        "System.set_storage.items"
        | "System.kill_storage.keys"
        | "Balances.upgrade_accounts.who"
        | "Utility.batch.calls"
        | "Utility.batch_all.calls"
        | "Utility.force_batch.calls" => 0,
        "OrinqReceipts.set_committee.members" | "OrinqReceipts.set_break_glass_aura_keys.keys" => {
            <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize::get()
        }
        "OrinqReceipts.set_pinned_committee.members" | "SessionCommitteeManagement.set.validators" => {
            MaxValidators::get()
        }
        "Recovery.create_recovery.friends" => {
            <Runtime as pallet_recovery::Config>::MaxFriends::get()
        }
        "Billing.prune_paid_requests.ids" => BillingMaxPruneBatch::get(),
        "TeeAttestation.submit_evidence.entry" => {
            pallet_tee_attestation::types::MAX_EVIDENCE_PAYLOAD_BYTES
        }
        p if p.starts_with("Multisig.") && p.ends_with(".other_signatories") => {
            <<Runtime as pallet_multisig::Config>::MaxSignatories as Get<u32>>::get() - 1
        }
        p if p.starts_with("IntentSettlement.") && p.ends_with(".signatures") => {
            IntentSettlementMaxCommittee::get()
        }
        "IntentSettlement.settle_batch_atomic.entries"
        | "IntentSettlement.request_batch_settle.entries"
        | "IntentSettlement.attest_batch_settle.claim_ids" => IntentSettlementMaxSettleBatch::get(),
        "IntentSettlement.attest_batch_intents.intent_ids" => IntentSettlementMaxAttestBatch::get(),
        "IntentSettlement.request_batch_vouchers.entries" => IntentSettlementMaxVoucherBatch::get(),
        "IntentSettlement.submit_batch_intents.entries" => IntentSettlementMaxSubmitBatch::get(),
        other => panic!("decide the worst-case length of {other}"),
    }
}

/// The SCALE encoding of type `id` at its worst case: top-level lists at
/// `list_length(path)`, nested lists empty, a nested call as an empty
/// remark, and every other value zero.
fn worst_case(registry: &PortableRegistry, id: u32, path: Option<&str>) -> Result<Vec<u8>, String> {
    let ty = registry.resolve(id).expect("registered type");
    if ty.path.segments.last().map(String::as_str) == Some("RuntimeCall") {
        return Ok(RuntimeCall::System(frame_system::Call::remark { remark: vec![] }).encode());
    }
    let mut out = Vec::new();
    match &ty.type_def {
        TypeDef::Composite(c) => {
            for field in &c.fields {
                out.extend(worst_case(registry, field.ty.id, path)?);
            }
        }
        TypeDef::Variant(v) => {
            let variant = v
                .variants
                .iter()
                .min_by_key(|v| v.fields.len())
                .ok_or("uninhabited")?;
            out.push(variant.index);
            for field in &variant.fields {
                out.extend(worst_case(registry, field.ty.id, None)?);
            }
        }
        TypeDef::Sequence(s) => {
            let count = path.map_or(0, list_length);
            out.extend(Compact(count).encode());
            let item = worst_case(registry, s.type_param.id, None)?;
            for _ in 0..count {
                out.extend(&item);
            }
        }
        TypeDef::Array(a) => {
            let item = worst_case(registry, a.type_param.id, None)?;
            for _ in 0..a.len {
                out.extend(&item);
            }
        }
        TypeDef::Tuple(t) => {
            for field in &t.fields {
                out.extend(worst_case(registry, field.id, None)?);
            }
        }
        TypeDef::Compact(_) => out.push(0),
        TypeDef::Primitive(p) => out.resize(
            match p {
                TypeDefPrimitive::Bool | TypeDefPrimitive::U8 | TypeDefPrimitive::I8 => 1,
                TypeDefPrimitive::U16 | TypeDefPrimitive::I16 => 2,
                TypeDefPrimitive::Char | TypeDefPrimitive::U32 | TypeDefPrimitive::I32 => 4,
                TypeDefPrimitive::U64 | TypeDefPrimitive::I64 => 8,
                TypeDefPrimitive::U128 | TypeDefPrimitive::I128 => 16,
                TypeDefPrimitive::U256 | TypeDefPrimitive::I256 => 32,
                TypeDefPrimitive::Str => 1,
            },
            0,
        ),
        TypeDef::BitSequence(_) => return Err("bit sequence".into()),
    }
    Ok(out)
}

/// One call variant at its worst case.
struct Audited {
    name: String,
    call: RuntimeCall,
    envelope: Envelope,
}

/// Every constructible call variant, at its worst case.
fn audited_calls() -> Vec<Audited> {
    let mut registry = Registry::new();
    let root = registry
        .register_type(&scale_info::meta_type::<RuntimeCall>())
        .id;
    let registry = PortableRegistry::from(registry);
    let variants = |id: u32| match &registry.resolve(id).expect("registered").type_def {
        TypeDef::Variant(def) => def.variants.clone(),
        other => panic!("type {id} is not an enum: {other:?}"),
    };
    let mut audited = Vec::new();
    for pallet in variants(root) {
        'call: for call in variants(pallet.fields[0].ty.id) {
            let name = format!("{}.{}", pallet.name, call.name);
            let mut bytes = vec![pallet.index, call.index];
            for field in &call.fields {
                let path = format!("{name}.{}", field.name.as_deref().unwrap_or_default());
                match worst_case(&registry, field.ty.id, Some(&path)) {
                    Ok(value) => bytes.extend(value),
                    Err(_) => {
                        assert!(
                            name.starts_with("Grandpa.report_equivocation"),
                            "{name} cannot be encoded"
                        );
                        continue 'call;
                    }
                }
            }
            let call = RuntimeCall::decode(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("{name} does not decode: {e}"));
            let envelope = if CALLER_SIZED.contains(&name.as_str()) {
                Envelope::CallerSized
            } else {
                Envelope::Bounded
            };
            audited.push(Audited { name, call, envelope });
        }
    }
    audited
}

fn signed_length(call: &RuntimeCall) -> usize {
    let extra: SignedExtra = (
        frame_system::CheckNonZeroSender::new(),
        frame_system::CheckSpecVersion::new(),
        frame_system::CheckTxVersion::new(),
        frame_system::CheckGenesis::new(),
        frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
        frame_system::CheckNonce::from(0),
        frame_system::CheckWeight::new(),
        pallet_motra::fee::ChargeMotra::new(),
    );
    UncheckedExtrinsic::new_signed(
        call.clone(),
        AccountId::new([1; 32]).into(),
        MultiSignature::Sr25519(sp_core::sr25519::Signature::from_raw([0; 64])),
        extra,
    )
    .encoded_size()
}

/// The most one extrinsic of `class` may declare.
fn call_limit(class: DispatchClass) -> Weight {
    let limits = RuntimeBlockWeights::get();
    match class {
        DispatchClass::Mandatory => limits.max_block,
        class => limits.get(class).max_extrinsic.expect("per-call limit"),
    }
}

#[test]
fn every_call_fits_its_class_limit() {
    genesis().execute_with(|| {
        let (mut worst, mut refused) = ((0f64, String::new()), Vec::new());
        for Audited { name, call, envelope } in audited_calls() {
            let info = call.get_dispatch_info();
            let length = signed_length(&call);
            let limit = call_limit(info.class);
            let share = info.weight.ref_time() as f64 / limit.ref_time() as f64;
            eprintln!(
                "AUDIT {}",
                serde_json::json!({
                    "call": name,
                    "class": format!("{:?}", info.class),
                    "pays": info.pays_fee == Pays::Yes,
                    "envelope": format!("{envelope:?}"),
                    "ref_time": info.weight.ref_time(),
                    "proof_size": info.weight.proof_size(),
                    "signed_length": length,
                    "limit": limit.ref_time(),
                })
            );
            if !info.weight.all_lte(limit)
                || (info.class != DispatchClass::Mandatory
                    && frame_system::CheckWeight::<Runtime>::do_validate(&info, length).is_err())
            {
                refused.push(format!("{name}: {:?} {:?}, {length} bytes", info.class, info.weight));
            }
            if share > worst.0 {
                worst = (share, name);
            }
        }
        eprintln!("WORST {:.6}% {}", worst.0 * 100.0, worst.1);
        assert!(refused.is_empty(), "un-includable at their worst case: {refused:#?}");
    });
}

#[test]
fn every_caller_sized_call_is_refused_above_its_class_limit() {
    genesis().execute_with(|| {
        let names: Vec<_> = audited_calls()
            .into_iter()
            .filter(|a| a.envelope == Envelope::CallerSized)
            .map(|a| a.name)
            .collect();
        assert_eq!(names.len(), CALLER_SIZED.len(), "stale caller-sized list");
        for class in [DispatchClass::Normal, DispatchClass::Operational] {
            let limit = call_limit(class);
            for over in [Weight::from_parts(1, 0), Weight::from_parts(0, 1)] {
                let info = DispatchInfo {
                    weight: limit.saturating_add(over),
                    class,
                    pays_fee: Pays::Yes,
                };
                assert_eq!(
                    frame_system::CheckWeight::<Runtime>::do_validate(&info, 128),
                    Err(sp_runtime::transaction_validity::InvalidTransaction::ExhaustsResources
                        .into())
                );
            }
        }
    });
}

/// Each block of a chain whose committee takes every seat, played as the
/// author makes it from epoch 1000: its consumed weight once its inherents
/// are in, before any transaction.
fn full_committee_blocks(slots: u64) -> Vec<(u64, frame_system::ConsumedWeight)> {
    use super::committee_inherent::{
        cardano, chain, epoch_start, genesis_header, in_seating_order, inherent_data, propose,
    };
    use sp_api::runtime_decl_for_core::Core;
    use sp_block_builder::runtime_decl_for_block_builder::BlockBuilder;
    use sp_runtime::traits::Block as _;
    let committee = in_seating_order(
        (0..MAX_VALIDATORS)
            .map(|seat| super::authority(&format!("Seat{seat}")))
            .collect(),
    );
    let listed = cardano(&committee);
    chain(&committee).execute_with(|| {
        let mut parent = genesis_header();
        (epoch_start(1_000)..epoch_start(1_000) + slots)
            .map(|slot| {
                let (header, inherents) = propose(&parent, slot, &inherent_data(slot, Some(&listed)))
                    .deconstruct();
                <Runtime as Core<Block>>::initialize_block(&header);
                for inherent in inherents {
                    <Runtime as BlockBuilder<Block>>::apply_extrinsic(inherent)
                        .expect("valid inherent")
                        .expect("inherent dispatches");
                }
                let consumed = frame_system::BlockWeight::<Runtime>::get();
                parent = <Runtime as BlockBuilder<Block>>::finalize_block();
                (slot, consumed)
            })
            .collect()
    })
}

#[test]
fn one_call_may_declare_its_class_budget_less_the_initialization_reservation() {
    let limits = RuntimeBlockWeights::get();
    let reserved = AVERAGE_ON_INITIALIZE_RATIO * limits.max_block;
    for class in [DispatchClass::Normal, DispatchClass::Operational] {
        let budget = limits.get(class);
        assert_eq!(
            budget.max_extrinsic,
            Some(
                budget
                    .max_total
                    .expect("class budget")
                    .saturating_sub(reserved)
                    .saturating_sub(budget.base_extrinsic)
            ),
            "{class:?}"
        );
    }
}

/// Session rotation reserves the whole block, as partner-chains' session
/// pallet declares it; everything else a block runs before its first
/// transaction stays within the initialization reservation.
#[test]
fn every_block_of_a_full_committee_initializes_within_its_reservation() {
    let max_block = RuntimeBlockWeights::get().max_block;
    let reserved = AVERAGE_ON_INITIALIZE_RATIO * max_block;
    let blocks = full_committee_blocks(3 * super::committee_inherent::SLOTS_PER_EPOCH);
    let mut rotations = 0;
    let mut worst = Weight::zero();
    for (slot, consumed) in &blocks {
        assert_eq!(consumed.get(DispatchClass::Normal), &Weight::zero());
        assert_eq!(consumed.get(DispatchClass::Operational), &Weight::zero());
        let mut initialization = consumed.total();
        if initialization.ref_time() >= max_block.ref_time() {
            rotations += 1;
            initialization = initialization.saturating_sub(max_block);
        }
        assert!(
            initialization.all_lte(reserved),
            "slot {slot} initializes with {initialization:?}, over {reserved:?}"
        );
        worst = worst.max(initialization);
    }
    assert_eq!(rotations, 2, "a rotation opens each epoch after the first block's");
    eprintln!(
        "INITIALIZATION worst {worst:?} = {:.4}% of the block, reservation {reserved:?}",
        worst.ref_time() as f64 * 100.0 / max_block.ref_time() as f64
    );
}

#[test]
fn no_pallet_takes_idle_time() {
    use frame_support::traits::OnIdle;
    genesis().execute_with(|| {
        let max_block = RuntimeBlockWeights::get().max_block;
        assert_eq!(AllPalletsWithSystem::on_idle(5, max_block), Weight::zero());
    });
}

/// The treasury spends every 100,800 blocks, at most `MaxApprovals`
/// proposals at a time.
#[test]
fn the_treasury_spend_period_fits_a_block() {
    use pallet_treasury::WeightInfo;
    let spend = <Runtime as pallet_treasury::Config>::WeightInfo::on_initialize_proposals(
        MaxApprovals::get(),
    );
    let max_block = RuntimeBlockWeights::get().max_block;
    eprintln!(
        "TREASURY {spend:?} = {:.2}% of the block",
        spend.ref_time() as f64 * 100.0 / max_block.ref_time() as f64
    );
    assert!(spend.all_lte(max_block));
}

/// Each Operational call a signer may pay for has bounded arguments and fits
/// the Operational per-call limit at every cap.
#[test]
fn every_paid_operational_call_is_bounded_and_fits_its_class() {
    use super::motra_operational::{Payer, OPERATIONAL};
    genesis().execute_with(|| {
        let audited = audited_calls();
        for (pallet, call, payer) in OPERATIONAL {
            if matches!(payer, Payer::Nobody) {
                continue;
            }
            let name = format!("{pallet}.{call}");
            let entry = audited
                .iter()
                .find(|a| a.name == name)
                .unwrap_or_else(|| panic!("{name} is not in the audit"));
            assert_eq!(entry.envelope, Envelope::Bounded, "{name}");
            let info = entry.call.get_dispatch_info();
            assert_eq!(info.class, DispatchClass::Operational, "{name}");
            assert!(
                info.weight.all_lte(call_limit(DispatchClass::Operational)),
                "{name}: {:?}",
                info.weight
            );
        }
    });
}

/// A pure batch of attestations is a feeless duty. The widest one that fits
/// the Normal per-call limit is admitted, and one more attestation is
/// refused before it can take any weight.
#[test]
fn the_widest_duty_batch_fits_and_a_wider_one_is_refused() {
    genesis().execute_with(|| {
        let attest = RuntimeCall::OrinqReceipts(
            pallet_orinq_receipts::Call::attest_availability_cert {
                receipt_id: sp_core::H256::zero(),
                claimed_hash: [0; 32],
            },
        );
        let batch = |width: usize| {
            RuntimeCall::Utility(pallet_utility::Call::batch {
                calls: vec![attest.clone(); width],
            })
        };
        let limit = call_limit(DispatchClass::Normal);
        let widest = (1..)
            .take_while(|width| batch(*width).get_dispatch_info().weight.all_lte(limit))
            .last()
            .expect("one attestation fits");
        for (width, admitted) in [(widest, true), (widest + 1, false)] {
            let call = batch(width);
            let info = call.get_dispatch_info();
            assert_eq!(info.class, DispatchClass::Normal);
            assert_eq!(
                frame_system::CheckWeight::<Runtime>::do_validate(&info, signed_length(&call))
                    .is_ok(),
                admitted,
                "{width} attestations"
            );
        }
        eprintln!("DUTY widest pure attestation batch: {widest}");
    });
}
