use crate::Runtime;
use frame_support::dispatch::GetDispatchInfo;
use frame_support::traits::Get;
use frame_support::weights::constants::RocksDbWeight;
use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::{meta_type, PortableRegistry, Registry, TypeDef, TypeDefPrimitive};

fn argument(
    registry: &PortableRegistry,
    id: u32,
    path: &str,
    depth: u32,
) -> Result<Vec<u8>, String> {
    assert!(depth < 32, "recursive argument: {path}");
    let ty = registry.resolve(id).expect("registered type");
    if ty.path.segments.last().map(String::as_str) == Some("RuntimeCall") {
        return Ok(
            crate::RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() }).encode(),
        );
    }
    let mut out = Vec::new();
    match &ty.type_def {
        TypeDef::Composite(c) => {
            for field in &c.fields {
                out.extend(argument(registry, field.ty.id, path, depth + 1)?);
            }
        }
        TypeDef::Variant(v) => {
            let variant = v
                .variants
                .iter()
                .min_by_key(|v| v.fields.len())
                .ok_or_else(|| format!("uninhabited {path}"))?;
            out.push(variant.index);
            for field in &variant.fields {
                out.extend(argument(registry, field.ty.id, path, depth + 1)?);
            }
        }
        TypeDef::Sequence(s) => {
            let count = match path {
                "SessionCommitteeManagement.set.validators" => crate::MaxValidators::get(),
                "OrinqReceipts.set_committee.members" => {
                    <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize::get()
                }
                "OrinqReceipts.set_break_glass_aura_keys.keys" => {
                    <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize::get()
                }
                "OrinqReceipts.set_pinned_committee.members" => crate::MaxValidators::get(),
                "Recovery.create_recovery.friends" => {
                    <Runtime as pallet_recovery::Config>::MaxFriends::get()
                }
                "Billing.prune_paid_requests.ids" => crate::BillingMaxPruneBatch::get(),
                "TeeAttestation.submit_evidence.entry" => {
                    pallet_tee_attestation::types::MAX_EVIDENCE_PAYLOAD_BYTES
                }
                "System.remark.remark" | "System.remark_with_event.remark" => 3_932_000,
                p if p.starts_with("Multisig.") && p.ends_with(".other_signatories") => {
                    <<Runtime as pallet_multisig::Config>::MaxSignatories as Get<u32>>::get() - 1
                }
                p if p.starts_with("IntentSettlement.") && p.ends_with(".signatures") => {
                    crate::IntentSettlementMaxCommittee::get()
                }
                "IntentSettlement.settle_batch_atomic.entries"
                | "IntentSettlement.request_batch_settle.entries"
                | "IntentSettlement.attest_batch_settle.claim_ids" => {
                    crate::IntentSettlementMaxSettleBatch::get()
                }
                "IntentSettlement.attest_batch_intents.intent_ids" => {
                    crate::IntentSettlementMaxAttestBatch::get()
                }
                "IntentSettlement.request_batch_vouchers.entries" => {
                    crate::IntentSettlementMaxVoucherBatch::get()
                }
                "IntentSettlement.submit_batch_intents.entries" => {
                    crate::IntentSettlementMaxSubmitBatch::get()
                }
                _ => 0,
            };
            out.extend(Compact(count).encode());
            let item = argument(registry, s.type_param.id, "", depth + 1)?;
            for _ in 0..count {
                out.extend(&item);
            }
        }
        TypeDef::Array(a) => {
            let item = argument(registry, a.type_param.id, "", depth + 1)?;
            for _ in 0..a.len {
                out.extend(&item);
            }
        }
        TypeDef::Tuple(t) => {
            for field in &t.fields {
                out.extend(argument(registry, field.id, path, depth + 1)?);
            }
        }
        TypeDef::Compact(_) => out.push(0),
        TypeDef::Primitive(p) => {
            let size = match p {
                TypeDefPrimitive::Bool | TypeDefPrimitive::U8 | TypeDefPrimitive::I8 => 1,
                TypeDefPrimitive::U16 | TypeDefPrimitive::I16 => 2,
                TypeDefPrimitive::Char | TypeDefPrimitive::U32 | TypeDefPrimitive::I32 => 4,
                TypeDefPrimitive::U64 | TypeDefPrimitive::I64 => 8,
                TypeDefPrimitive::U128 | TypeDefPrimitive::I128 => 16,
                TypeDefPrimitive::U256 | TypeDefPrimitive::I256 => 32,
                TypeDefPrimitive::Str => 1,
            };
            out.resize(size, 0);
        }
        TypeDef::BitSequence(_) => return Err(format!("unsupported bit sequence {path}")),
    }
    Ok(out)
}

#[test]
fn dbweight_call_inventory() {
    use sp_runtime::BuildStorage;
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into();
    ext.execute_with(call_inventory);
}

fn call_inventory() {
    let baseline: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!("dbweight-baseline.json")).expect("baseline inventory");
    let mut seen = std::collections::BTreeSet::new();
    let mut registry = Registry::new();
    let root = registry
        .register_type(&meta_type::<crate::RuntimeCall>())
        .id;
    let registry: PortableRegistry = registry.into();
    let TypeDef::Variant(pallets) = &registry.resolve(root).expect("runtime call").type_def else {
        panic!("runtime call enum")
    };
    for pallet in &pallets.variants {
        let TypeDef::Variant(calls) = &registry
            .resolve(pallet.fields[0].ty.id)
            .expect("pallet call")
            .type_def
        else {
            panic!("pallet call enum")
        };
        for call in &calls.variants {
            let name = format!("{}.{}", pallet.name, call.name);
            let mut bytes = vec![pallet.index, call.index];
            let mut uninhabited = false;
            for field in &call.fields {
                let path = format!("{name}.{}", field.name.as_deref().unwrap_or(""));
                match argument(&registry, field.ty.id, &path, 0) {
                    Ok(value) => bytes.extend(value),
                    Err(reason) => {
                        assert!(
                            matches!(
                                name.as_str(),
                                "Grandpa.report_equivocation"
                                    | "Grandpa.report_equivocation_unsigned"
                            ),
                            "unaudited call {name}: {reason}"
                        );
                        eprintln!("AUDIT_UNAVAILABLE {name} {reason}");
                        uninhabited = true;
                        break;
                    }
                }
            }
            if uninhabited {
                continue;
            }
            assert!(
                baseline.contains_key(&name),
                "new dispatchable needs a weight audit: {name}"
            );
            let fields: Vec<_> = call
                .fields
                .iter()
                .map(|field| (&field.name, &field.type_name))
                .collect();
            assert_eq!(
                baseline[&name]["fields"],
                serde_json::to_value(fields).expect("call fields"),
                "{name}: changed parameters need a weight audit"
            );
            seen.insert(name.clone());
            let decoded = crate::RuntimeCall::decode(&mut &bytes[..])
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let info = decoded.get_dispatch_info();
            let extra: crate::SignedExtra = (
                frame_system::CheckNonZeroSender::new(),
                frame_system::CheckSpecVersion::new(),
                frame_system::CheckTxVersion::new(),
                frame_system::CheckGenesis::new(),
                frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
                frame_system::CheckNonce::from(0),
                frame_system::CheckWeight::new(),
                pallet_motra::fee::ChargeMotra::new(),
            );
            let signed = crate::UncheckedExtrinsic::new_signed(
                decoded,
                crate::AccountId::new([1; 32]).into(),
                sp_runtime::MultiSignature::Sr25519(sp_core::sr25519::Signature::from_raw([0; 64])),
                extra,
            );
            eprintln!(
                "AUDIT {name} {:?} {} {} {} {}",
                info.class,
                info.weight.ref_time(),
                info.weight.proof_size(),
                bytes.len(),
                signed.encoded_size()
            );
            let limits = crate::RuntimeBlockWeights::get();
            let class = limits.get(info.class);
            let limit = class.max_extrinsic.unwrap_or_else(|| limits.max_block);
            assert!(
                info.weight.all_lte(limit),
                "{name}: {:?} exceeds {limit:?}",
                info.weight
            );
            assert!(
                frame_system::CheckWeight::<Runtime>::do_validate(&info, signed.encoded_size())
                    .is_ok(),
                "{name} fails admission"
            );
        }
    }
    assert_eq!(
        seen,
        baseline.into_keys().collect(),
        "removed dispatchable or stale inventory"
    );
}

#[test]
fn runtime_database_weight_is_rocksdb() {
    let actual = <<Runtime as frame_system::Config>::DbWeight as frame_support::traits::Get<
        frame_support::weights::RuntimeDbWeight,
    >>::get();
    let expected = RocksDbWeight::get();
    assert_eq!(actual.read, expected.read);
    assert_eq!(actual.write, expected.write);
}

#[test]
fn remark_weights_fit_the_full_encoded_length_ceiling() {
    use frame_support::dispatch::DispatchClass;
    let length = *crate::RuntimeBlockLength::get()
        .max
        .get(DispatchClass::Normal) as usize;
    let limit = crate::RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic
        .expect("normal call limit");
    // Every valid signed payload is smaller because its envelope also consumes length.
    for call in [
        frame_system::Call::remark {
            remark: vec![0; length],
        },
        frame_system::Call::remark_with_event {
            remark: vec![0; length],
        },
    ] {
        let info = crate::RuntimeCall::System(call).get_dispatch_info();
        assert_eq!(info.class, DispatchClass::Normal);
        assert!(info.weight.all_lte(limit));
    }
}

#[test]
fn single_call_limits_match_class_budget() {
    use frame_support::dispatch::DispatchClass;
    let limits = crate::RuntimeBlockWeights::get();
    for class in [DispatchClass::Normal, DispatchClass::Operational] {
        let budget = limits.get(class);
        assert_eq!(
            budget.max_extrinsic,
            Some(
                budget
                    .max_total
                    .expect("class budget")
                    .saturating_sub(budget.base_extrinsic)
            )
        );
    }
}

#[test]
fn oversized_weight_is_rejected_before_dispatch_for_both_signed_classes() {
    use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
    use sp_runtime::{transaction_validity::InvalidTransaction, BuildStorage};
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into();
    ext.execute_with(|| {
        for class in [DispatchClass::Normal, DispatchClass::Operational] {
            let limit = crate::RuntimeBlockWeights::get()
                .get(class)
                .max_extrinsic
                .expect("call limit");
            for weight in [
                limit.saturating_add(frame_support::weights::Weight::from_parts(1, 0)),
                limit.saturating_add(frame_support::weights::Weight::from_parts(0, 1)),
            ] {
                let info = DispatchInfo {
                    weight,
                    class,
                    pays_fee: Pays::Yes,
                };
                assert_eq!(
                    frame_system::CheckWeight::<Runtime>::do_validate(&info, 128),
                    Err(InvalidTransaction::ExhaustsResources.into())
                );
            }
        }
    });
}

#[test]
fn hook_budget_audit_exposes_session_rotation_overrun() {
    use crate::*;
    use frame_support::traits::OnInitialize;
    use sp_runtime::BuildStorage;
    let mut committee: Vec<_> = (0..MAX_VALIDATORS)
        .map(|i| super::authority(&format!("WeightAudit{i}")))
        .collect();
    committee.sort_by(|a, b| a.0.cmp(&b.0));
    let mut ext: sp_io::TestExternalities = RuntimeGenesisConfig {
        sidechain: pallet_sidechain::GenesisConfig {
            slots_per_epoch: sidechain_slots::SlotsPerEpoch(10),
            ..Default::default()
        },
        session_committee_management: pallet_session_validator_management::GenesisConfig {
            initial_authorities: committee.clone(),
            main_chain_scripts: Default::default(),
        },
        ..Default::default()
    }
    .build_storage()
    .expect("committee genesis")
    .into();
    ext.execute_with(|| {
        System::set_block_number(2);
        pallet_aura::CurrentSlot::<Runtime>::put(sp_consensus_aura::Slot::from(10));
        pallet_session_validator_management::NextCommittee::<Runtime>::put(
            pallet_session_validator_management::CommitteeInfo {
                epoch: sidechain_domain::ScEpochNumber(1),
                committee: committee.try_into().expect("committee bound"),
            });
        let charged = AllPalletsWithSystem::on_initialize(2)
            .saturating_add(BlockExecutionWeight::get());
        let cap = RuntimeBlockWeights::get().max_block;
        assert!(charged.ref_time() > cap.ref_time(), "re-audit the resolved rotation blocker");
        eprintln!("HOOK_AUDIT rotation charged={charged:?}, block={cap:?}; inherents/finalize still additional");
    });
}

#[test]
fn hook_budget_audit_exposes_unbounded_receipt_migration() {
    use frame_support::{traits::OnRuntimeUpgrade, BoundedBTreeSet};
    use sp_runtime::BuildStorage;
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into();
    ext.execute_with(|| {
        for i in 0..20_001 {
            pallet_orinq_receipts::Attestations::<Runtime>::insert(
                sp_core::H256::from_low_u64_be(i),
                (
                    sp_core::H256::zero(),
                    BoundedBTreeSet::<
                        crate::AccountId,
                        <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
                    >::new(),
                ),
            );
        }
    });
    ext.commit_all().expect("backend migration fixture");
    ext.execute_with(|| {
        let charged = crate::OrinqReceipts::on_runtime_upgrade();
        assert!(
            charged.ref_time() > crate::RuntimeBlockWeights::get().max_block.ref_time(),
            "re-audit the resolved receipt migration blocker"
        );
        assert_eq!(
            pallet_orinq_receipts::Attestations::<Runtime>::iter_keys().count(),
            0
        );
        eprintln!("HOOK_AUDIT receipt migration 20001 rows charged={charged:?}");
    });
}

#[test]
fn hook_budget_audit_exposes_maximum_reward_era_overrun() {
    use frame_support::traits::OnInitialize;
    use sp_runtime::BuildStorage;
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into();
    ext.execute_with(|| {
        for i in 0u32..14_400 {
            let mut account = [0; 32];
            account[..4].copy_from_slice(&i.to_le_bytes());
            pallet_orinq_receipts::BlocksAuthored::<Runtime>::insert(
                crate::AccountId::new(account),
                1,
            );
        }
    });
    ext.commit_all().expect("reward era fixture");
    ext.execute_with(|| {
        let charged = crate::OrinqReceipts::on_initialize(14_400);
        assert!(
            charged.ref_time() > crate::RuntimeBlockWeights::get().max_block.ref_time(),
            "re-audit the resolved reward era blocker"
        );
        assert_eq!(
            pallet_orinq_receipts::BlocksAuthored::<Runtime>::iter_keys().count(),
            0
        );
        eprintln!("HOOK_AUDIT reward era 14400 authors charged={charged:?}");
    });
}
