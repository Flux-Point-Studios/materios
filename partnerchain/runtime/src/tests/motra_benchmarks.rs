use crate::*;
use frame_support::{
    dispatch::{DispatchClass, GetDispatchInfo},
    traits::StorageInfoTrait,
    weights::constants::RocksDbWeight,
};
use serde_json::Value;

fn samples() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../pallets/motra/benchmarking/reconciliation-samples.json"
    ))
    .expect("benchmark samples")
}

fn median_time(sample: &Value) -> u64 {
    let mut times: Vec<_> = sample["time_results"]
        .as_array()
        .expect("time samples")
        .iter()
        .map(|row| row["extrinsic_time"].as_u64().expect("time"))
        .collect();
    times.sort_unstable();
    times[times.len() / 2] * 1_000
}

fn reconciliation_proof(fee: bool) -> u64 {
    let mut bounds = vec![
        ("System", "Account", 1),
        ("Motra", "Params", 1),
        ("Motra", "MotraBalances", 2),
        ("Motra", "LastTouched", 2),
        ("Motra", "AccrualCheckpoint", 1),
        ("Motra", "Delegatees", 1),
        ("Motra", "TotalIssued", 1),
        ("Motra", "LegacyAccrualStart", 1),
    ];
    if fee {
        bounds.push(("Motra", "TotalBurned", 1));
    }
    let entries = [System::storage_info(), Motra::storage_info()].concat();
    bounds
        .into_iter()
        .map(|(pallet, name, count)| {
            let info = entries
                .iter()
                .find(|info| {
                    info.pallet_name == pallet.as_bytes() && info.storage_name == name.as_bytes()
                })
                .expect("storage info");
            let layers = if info.max_values == Some(1) { 3 } else { 7 };
            count * (u64::from(info.max_size.expect("bounded storage")) + layers * 495)
        })
        .sum()
}

#[test]
fn benchmark_reconciliation_and_fee_weights_match_samples_and_storage_bounds() {
    let fee = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .base_extrinsic
        .saturating_sub(ExtrinsicBaseWeight::get());
    for sample in samples() {
        let name = sample["benchmark"].as_str().expect("benchmark name");
        let rows = sample["db_results"].as_array().expect("DB samples");
        let reads = rows
            .iter()
            .map(|r| r["reads"].as_u64().expect("reads"))
            .max()
            .expect("DB sample");
        let writes = rows
            .iter()
            .map(|r| r["writes"].as_u64().expect("writes"))
            .max()
            .expect("DB sample");
        // Existing checkpoints and legacy fallback are mutually exclusive. The
        // extra read prices the fallback even on the longer two-clock path.
        let legacy = u64::from(name != "reconcile_legacy");
        let expected = Weight::from_parts(
            median_time(&sample),
            reconciliation_proof(name == "fee_path"),
        )
        .saturating_add(RocksDbWeight::get().reads_writes(reads + legacy, writes));
        let actual = match name {
            "fee_path" => fee,
            "claim_motra" => {
                RuntimeCall::Motra(pallet_motra::Call::claim_motra {})
                    .get_dispatch_info()
                    .weight
            }
            "set_delegatee" => {
                RuntimeCall::Motra(pallet_motra::Call::set_delegatee { delegatee: None })
                    .get_dispatch_info()
                    .weight
            }
            _ => pallet_motra::reconciliation_weight::<Runtime>(),
        };
        if matches!(name, "fee_path" | "claim_motra" | "set_delegatee") {
            assert_eq!(
                actual, expected,
                "{name} must use the measured execution and DB counts"
            );
        } else {
            assert!(
                actual.all_gte(expected),
                "{name}: {actual:?} < {expected:?}"
            );
        }
        eprintln!("{name}: execution={} ps, DB={reads}r/{writes}w (+{legacy} legacy read), declared={actual:?}", median_time(&sample));
    }
}

#[test]
fn benchmark_checkpoint_weight_matches_committed_samples() {
    let values: Vec<Value> = serde_json::from_str(include_str!(
        "../../../pallets/motra/benchmarking/checkpoint-samples.json"
    ))
    .expect("checkpoint samples");
    let sample = &values[0];
    for row in sample["db_results"].as_array().expect("DB samples") {
        assert_eq!(row["reads"], 1);
        assert_eq!(row["writes"], 1);
    }
    assert_eq!(
        pallet_motra::checkpoint_weight::<Runtime>(),
        Weight::from_parts(median_time(sample), 3_533)
            .saturating_add(RocksDbWeight::get().reads_writes(1, 1))
    );
}

#[test]
fn benchmark_attestation_proof_bounds_sum_independent_storage() {
    use pallet_orinq_receipts::weights::WeightInfo;
    type W = <Runtime as pallet_orinq_receipts::Config>::WeightInfo;
    let entries = [System::storage_info(), OrinqReceipts::storage_info()].concat();
    let bound = |name: &str, count: u64| {
        let info = entries
            .iter()
            .find(|entry| entry.storage_name == name.as_bytes())
            .expect("receipt storage info");
        count
            * (u64::from(info.max_size.expect("bounded receipt storage"))
                + if info.max_values == Some(1) {
                    3 * 495
                } else {
                    7 * 495
                })
    };
    let common = bound("CommitteeMembers", 1)
        + bound("Receipts", 1)
        + bound("BlockHash", 1)
        + bound("AttestationThreshold", 1);
    assert_eq!(
        W::attest_non_threshold().proof_size(),
        common + bound("Attestations", 1)
    );
    assert_eq!(
        W::attest_bad_hash().proof_size(),
        common
            + bound("BadAttestStrikes", 1)
            + bound("BadAttestSlashThreshold", 1)
            + bound("Account", 2)
            + bound("AttestorBonds", 1)
    );
    for n in [1, 3, 96] {
        let proof = common
            + bound("Attestations", 1)
            + bound("Account", u64::from(n) + 2)
            + bound("ReceiptFeeEscrow", 1)
            + bound("AttestationRewardPerSigner", 1)
            + bound("EraCapBase", 1)
            + bound("EraCapBaselineAttestorCount", 1)
            + bound("TotalAttestationRewards", 1)
            + bound("AttestationRewardsPaidInEra", 1)
            + bound("AttestationRewards", u64::from(n))
            + bound("ReceiptsCertifiedInEra", 1)
            + bound("ReceiptSubmittedAt", 1);
        assert_eq!(W::attest_threshold(n).proof_size(), proof);
    }
}

#[test]
fn benchmark_maximum_dormant_claim_batch_fits_its_declared_execution_budget() {
    use frame_support::assert_ok;
    use parity_scale_codec::Encode;
    use sp_runtime::{
        traits::{Dispatchable, SignedExtension},
        BuildStorage,
    };
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into();
    ext.execute_with(|| {
        let signer = sp_keyring::Sr25519Keyring::Dave.to_account_id();
        let claim = RuntimeCall::Motra(pallet_motra::Call::claim_motra {});
        let wrapped = RuntimeCall::Utility(pallet_utility::Call::as_derivative { index: 0, call: Box::new(claim.clone()) });
        let limits = RuntimeBlockWeights::get();
        let limit = limits.get(DispatchClass::Normal);
        use pallet_utility::WeightInfo;
        let count = (1u32..10_000).take_while(|n| wrapped.get_dispatch_info().weight.saturating_mul(u64::from(*n))
            .saturating_add(<Runtime as pallet_utility::Config>::WeightInfo::batch(*n))
            .all_lte(limit.max_total.expect("normal cap").saturating_sub(limit.base_extrinsic)))
            .last().expect("claims fit");
        System::set_block_number(1);
        for index in 0..count {
            let who = Utility::derivative_account_id(signer.clone(), index as u16);
            let delegatee = Utility::derivative_account_id(signer.clone(), index as u16 + 32_768);
            for account in [&who, &delegatee] {
                assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), account.clone().into(), 1_000_000));
                pallet_motra::MotraBalances::<Runtime>::insert(account, 1_000_000_000_000_000_000u128);
                pallet_motra::LastTouched::<Runtime>::insert(account, 0);
            }
            pallet_motra::Delegatees::<Runtime>::insert(&who, delegatee);
        }
        pallet_motra::MotraBalances::<Runtime>::insert(&signer, 1_000_000_000_000_000_000u128);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.decay_rate_per_block = Perbill::from_parts(999_999_999);
            p.generation_per_matra_per_block = 100_000;
        });
        System::set_block_number(u32::MAX);
        let calls = (0..count).map(|index| RuntimeCall::Utility(pallet_utility::Call::as_derivative {
            index: index as u16, call: Box::new(claim.clone()),
        })).collect();
        let batch = RuntimeCall::Utility(pallet_utility::Call::batch { calls });
        let info = batch.get_dispatch_info();
        let len = batch.encoded_size();
        let start = std::time::Instant::now();
        assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, len));
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new().pre_dispatch(&signer, &batch, &info, len).expect("batch fee");
        let post = batch.dispatch(RuntimeOrigin::signed(signer.clone())).expect("batch dispatch");
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(Some(pre), &info, &post, len, &Ok(())));
        let elapsed = start.elapsed().as_nanos() * 1_000;
        let declared = info.weight.saturating_add(limit.base_extrinsic).ref_time();
        for index in 0..count {
            let who = Utility::derivative_account_id(signer.clone(), index as u16);
            assert_eq!(Motra::last_touched(&who), u32::MAX, "inner claim {index} must run");
        }
        let sample = samples().into_iter().find(|s| s["benchmark"] == "claim_motra").expect("Wasm claim benchmark");
        let wasm_upper = sample["time_results"].as_array().expect("Wasm samples").iter()
            .map(|s| s["extrinsic_time"].as_u64().expect("time")).max().expect("Wasm sample") * 1_000;
        assert!(wasm_upper.saturating_mul(u64::from(count)) <= declared);
        eprintln!("{count} dormant derived claims: native {elapsed} ps; worst Wasm sample x count {} ps; declared {declared} ps", wasm_upper * u64::from(count));
    });
}

#[test]
fn benchmark_signed_transfer_covers_fee_path_and_reports_capacity() {
    let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
        dest: sp_keyring::Sr25519Keyring::Bob.to_account_id().into(),
        value: 1_000,
    });
    let info = call.get_dispatch_info();
    let limits = RuntimeBlockWeights::get();
    let normal = limits.get(DispatchClass::Normal);
    let total = info.weight.saturating_add(normal.base_extrinsic);
    let sample = samples()
        .into_iter()
        .find(|s| s["benchmark"] == "fee_path")
        .expect("fee benchmark");
    let measured = sample["time_results"]
        .as_array()
        .expect("timings")
        .iter()
        .map(|s| s["extrinsic_time"].as_u64().expect("time"))
        .max()
        .expect("sample")
        * 1_000;
    assert!(normal.base_extrinsic.ref_time() >= ExtrinsicBaseWeight::get().ref_time() + measured);
    assert!(total.ref_time() >= info.weight.ref_time() + measured);
    let count = normal.max_total.expect("normal cap").ref_time() / total.ref_time();
    assert!(total
        .saturating_mul(count)
        .all_lte(normal.max_total.expect("cap")));
    eprintln!("transfer_keep_alive: call={:?}; signed total={total:?}; transfers/block={count}; worst measured fee path={measured} ps", info.weight);
}

mod currency_db {
    use frame_support::{derive_impl, parameter_types, weights::RuntimeDbWeight};
    frame_support::construct_runtime!(pub enum Test { System: frame_system });
    parameter_types! {
        pub const Db: RuntimeDbWeight = RuntimeDbWeight { read: 1, write: 10_000 };
    }
    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = frame_system::mocking::MockBlock<Test>;
        type DbWeight = Db;
    }
}

#[test]
fn attestation_database_counts_exclude_separate_checkpoints() {
    use pallet_orinq_receipts::weights::{SubstrateWeight, WeightInfo};
    let samples: Vec<Value> = serde_json::from_str(include_str!(
        "../../../pallets/orinq-receipts/benchmarking/attestation-samples.json"
    ))
    .expect("attestation samples");
    for sample in samples.iter().filter(|sample| {
        matches!(
            sample["benchmark"].as_str(),
            Some("attest_threshold" | "attest_dead_treasury")
        )
    }) {
        for row in sample["db_results"].as_array().expect("database samples") {
            let n = row["components"][0][1].as_u64().expect("committee size");
            let checkpoints = n + 1;
            let reads = row["reads"].as_u64().expect("reads") - checkpoints;
            let writes = row["writes"].as_u64().expect("writes") - checkpoints;
            let actual = SubstrateWeight::<currency_db::Test>::attest_threshold(n as u32)
                .saturating_sub(SubstrateWeight::<zero_db::Test>::attest_threshold(n as u32));
            assert_eq!(
                actual,
                currency_db::Db::get().reads_writes(reads, writes),
                "n={n}: checkpoints must be charged once"
            );
        }
    }
}

mod zero_db {
    use frame_support::derive_impl;
    frame_support::construct_runtime!(pub enum Test { System: frame_system });
    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = frame_system::mocking::MockBlock<Test>;
    }
}

#[test]
fn motra_weights_use_configured_database_schedule() {
    use pallet_motra::weights::{SubstrateWeight, WeightInfo};
    let db = currency_db::Db::get();
    for (actual, execution, reads, writes) in [
        (
            SubstrateWeight::<currency_db::Test>::checkpoint(),
            23_885_000,
            1,
            1,
        ),
        (
            SubstrateWeight::<currency_db::Test>::reconcile(),
            198_197_000,
            10,
            6,
        ),
        (
            SubstrateWeight::<currency_db::Test>::fee_path(),
            189_660_000,
            11,
            7,
        ),
        (
            SubstrateWeight::<currency_db::Test>::claim_motra(),
            197_014_000,
            10,
            6,
        ),
        (
            SubstrateWeight::<currency_db::Test>::set_delegatee(),
            198_657_000,
            10,
            7,
        ),
    ] {
        assert_eq!(
            actual.ref_time(),
            execution + db.reads_writes(reads, writes).ref_time()
        );
    }
}

#[test]
fn runtime_motra_weights_preserve_rocksdb_floor_prices() {
    use pallet_motra::weights::WeightInfo;
    type W = <Runtime as pallet_motra::Config>::WeightInfo;
    assert_eq!(W::checkpoint(), Weight::from_parts(148_885_000, 3_533));
    assert_eq!(W::reconcile(), Weight::from_parts(1_048_197_000, 29_346));
    assert_eq!(W::fee_path(), Weight::from_parts(1_164_660_000, 30_847));
    assert_eq!(W::claim_motra(), Weight::from_parts(1_047_014_000, 29_346));
    assert_eq!(
        W::set_delegatee(),
        Weight::from_parts(1_148_657_000, 29_346)
    );
}

fn currency_base<T: frame_system::Config>(name: &str) -> Weight {
    use pallet_billing::weights::WeightInfo as _;
    use pallet_orinq_receipts::weights::WeightInfo as _;
    match name {
        "submit_receipt" | "submit_receipt_v2" => {
            pallet_orinq_receipts::weights::SubstrateWeight::<T>::submit_receipt()
        }
        "set_availability_cert" => {
            pallet_orinq_receipts::weights::SubstrateWeight::<T>::set_availability_cert()
        }
        "bond" => pallet_orinq_receipts::weights::SubstrateWeight::<T>::bond(),
        "unbond" => pallet_orinq_receipts::weights::SubstrateWeight::<T>::unbond(),
        "slash_attestor" => pallet_orinq_receipts::weights::SubstrateWeight::<T>::slash_attestor(),
        "expire_receipt_fee" => {
            pallet_orinq_receipts::weights::SubstrateWeight::<T>::expire_receipt_fee()
        }
        "topup_self" => pallet_billing::weights::SubstrateWeight::<T>::topup_self(),
        "topup_for" => pallet_billing::weights::SubstrateWeight::<T>::topup_for(),
        "execute_withdrawal" => pallet_billing::weights::SubstrateWeight::<T>::execute_withdrawal(),
        _ => panic!("unpriced currency benchmark {name}"),
    }
}

#[test]
fn benchmark_currency_refunds_retain_measured_execution_and_proofs() {
    let entries = [
        System::storage_info(),
        Balances::storage_info(),
        Timestamp::storage_info(),
        OrinqReceipts::storage_info(),
        Billing::storage_info(),
    ]
    .concat();
    let receipts: Vec<Value> = serde_json::from_str(include_str!(
        "../../../pallets/orinq-receipts/benchmarking/currency-samples.json"
    ))
    .expect("receipt currency samples");
    let billing: Vec<Value> = serde_json::from_str(include_str!(
        "../../../pallets/billing/benchmarking/currency-samples.json"
    ))
    .expect("billing currency samples");
    let mut failures = Vec::new();
    for sample in receipts.iter().chain(&billing) {
        let name = sample["benchmark"].as_str().expect("benchmark name");
        let group: Vec<_> = if name.starts_with("submit_receipt") {
            receipts
                .iter()
                .filter(|s| {
                    s["benchmark"]
                        .as_str()
                        .expect("name")
                        .starts_with("submit_receipt")
                })
                .collect()
        } else {
            vec![sample]
        };
        let execution = group
            .iter()
            .flat_map(|s| s["time_results"].as_array().expect("times"))
            .map(|r| r["extrinsic_time"].as_u64().expect("execution"))
            .max()
            .expect("sample")
            * 1_000;
        let proof = group
            .iter()
            .map(|s| {
                s["proof_storage"]
                    .as_array()
                    .expect("storage bounds")
                    .iter()
                    .map(|bound| {
                        let info = entries
                            .iter()
                            .find(|info| {
                                info.pallet_name
                                    == bound["pallet"].as_str().expect("pallet").as_bytes()
                                    && info.storage_name
                                        == bound["storage"].as_str().expect("storage").as_bytes()
                            })
                            .expect("runtime storage info");
                        bound["count"].as_u64().expect("key count")
                            * (u64::from(info.max_size.expect("bounded storage"))
                                + if info.max_values == Some(1) {
                                    3 * 495
                                } else {
                                    7 * 495
                                })
                    })
                    .sum::<u64>()
            })
            .max()
            .expect("proof bound");
        let actual = currency_base::<Runtime>(name);
        let execution_and_proof = Weight::from_parts(execution, proof);
        let db_count = |field: &str| {
            group
                .iter()
                .map(|s| {
                    s["db_results"]
                        .as_array()
                        .expect("DB samples")
                        .iter()
                        .map(|row| row[field].as_u64().expect("DB count"))
                        .max()
                        .expect("DB sample")
                        - s["checkpoint_keys"]
                            .as_u64()
                            .expect("separately charged checkpoint")
                        + u64::from(s["whitelisted_issuance"].as_bool().unwrap_or(false))
                })
                .max()
                .expect("DB bound")
        };
        assert_eq!(
            currency_base::<currency_db::Test>(name),
            execution_and_proof.saturating_add(
                currency_db::Db::get().reads_writes(db_count("reads"), db_count("writes"))
            ),
            "{name} must retain the measured base DB counts"
        );
        let expected = execution_and_proof.saturating_add(
            RuntimeDbWeight::get().reads_writes(db_count("reads"), db_count("writes")),
        );
        eprintln!("currency {name}: declared={actual:?}, measured/proof bound={expected:?}");
        if actual != expected {
            failures.push(format!("{name}: {actual:?} != {expected:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "refund bases must cover measured branches: {}",
        failures.join("; ")
    );
}
