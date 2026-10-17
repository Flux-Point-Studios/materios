use crate::*;
use frame_support::{
    assert_ok,
    dispatch::{DispatchInfo, GetDispatchInfo, PostDispatchInfo},
    BoundedBTreeSet,
};
use pallet_orinq_receipts::weights::WeightInfo as _;
use sp_runtime::{
    traits::{Dispatchable, SignedExtension},
    BuildStorage,
};

fn account(index: u8) -> AccountId {
    AccountId::new([index; 32])
}

fn externalities() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("genesis")
        .into()
}

fn fund(who: &AccountId, free: u128) {
    assert_ok!(Balances::force_set_balance(
        RuntimeOrigin::root(),
        who.clone().into(),
        free
    ));
}

fn receipt(committee_size: u32, threshold: u32, fee: u128) -> (H256, [u8; 32]) {
    System::set_block_number(100);
    let submitter = account(200);
    fund(&submitter, 1_000_000_000_000);
    let mut members = BoundedBTreeSet::new();
    for i in 1..=committee_size {
        let who = account(i as u8);
        fund(&who, 1_000_000);
        members.try_insert(who).expect("committee bound");
    }
    pallet_orinq_receipts::CommitteeMembers::<Runtime>::put(members);
    pallet_orinq_receipts::AttestationThreshold::<Runtime>::put(threshold);
    pallet_orinq_receipts::ReceiptSubmissionFee::<Runtime>::put(fee);
    pallet_orinq_receipts::ReceiptSubmissionFeeFloor::<Runtime>::put(0);
    let id = H256::repeat_byte(5);
    assert_ok!(OrinqReceipts::submit_receipt(
        RuntimeOrigin::signed(submitter),
        id,
        H256::repeat_byte(6),
        [1; 32],
        None,
        None,
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
    ));
    let hash = OrinqReceipts::canonical_cert_hash(id)
        .expect("canonical cert")
        .0;
    (id, hash)
}

fn attest(id: H256, claimed_hash: [u8; 32]) -> RuntimeCall {
    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::attest_availability_cert {
        receipt_id: id,
        claimed_hash,
    })
}

fn dispatch(call: RuntimeCall, who: AccountId) -> (DispatchInfo, PostDispatchInfo) {
    let info = call.get_dispatch_info();
    let post = call.dispatch(RuntimeOrigin::signed(who)).expect("dispatch");
    assert!(post.calc_actual_weight(&info).all_lte(info.weight));
    (info, post)
}

#[test]
fn refund_non_threshold_attest_charges_no_checkpoints_and_refunds_motra() {
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 2, 100_000);
        let who = account(1);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.decay_rate_per_block = Perbill::one();
            p.generation_per_matra_per_block = 0;
            p.congestion_rate = 1_000_000;
            p.length_fee_per_byte = 0;
        });
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000u128);
        let call = attest(id, hash);
        let info = call.get_dispatch_info();
        let before = Motra::projected_balance(&who);
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &call, &info, 0)
            .expect("fee payment");
        let (_, post) = dispatch(call, who.clone());
        let actual = post.actual_weight.expect("non-threshold refund");
        let samples: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../pallets/orinq-receipts/benchmarking/attestation-samples.json"
        ))
        .expect("attestation samples");
        let benchmark = samples
            .iter()
            .find(|s| s["benchmark"] == "attest_non_threshold")
            .expect("non-threshold sample");
        let mut times: Vec<_> = benchmark["time_results"]
            .as_array()
            .expect("timings")
            .iter()
            .map(|s| s["extrinsic_time"].as_u64().expect("time"))
            .collect();
        times.sort_unstable();
        assert!(
            actual.ref_time() >= times[times.len() / 2] * 1_000,
            "actual weight must cover benchmarked execution"
        );
        assert!(
            actual
                == <Runtime as pallet_orinq_receipts::Config>::WeightInfo::attest_non_threshold(),
            "non-threshold attestation must not carry any checkpoint surcharge: {actual:?}"
        );
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            0,
            &Ok(()),
        ));
        assert_eq!(
            before - Motra::motra_balance(&who),
            Motra::compute_fee(actual, 0)
        );
        assert_eq!(Motra::total_burned(), Motra::compute_fee(actual, 0));
    });
}

#[test]
fn refund_threshold_and_late_attests_cover_observed_checkpoints() {
    for treasury_alive in [false, true] {
        let mut ext = externalities();
        let (id, hash) = ext.execute_with(|| {
            let (id, hash) = receipt(96, 96, 1_000_000);
            pallet_orinq_receipts::AttestationRewardPerSigner::<Runtime>::put(10_000);
            pallet_orinq_receipts::EraCapBase::<Runtime>::put(1_000_000_000);
            pallet_orinq_receipts::EraCapBaselineAttestorCount::<Runtime>::put(96);
            if treasury_alive {
                fund(&OrinqReceipts::treasury_account(), 1_000_000);
            }
            let signers: BoundedBTreeSet<
                _,
                <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
            > = (1..96)
                .map(account)
                .collect::<std::collections::BTreeSet<_>>()
                .try_into()
                .expect("signers");
            pallet_orinq_receipts::Attestations::<Runtime>::insert(id, (H256(hash), signers));
            (id, hash)
        });
        ext.commit_all().expect("fixture commit");
        let (info, post) = ext.execute_with(|| dispatch(attest(id, hash), account(96)));
        let prefix = pallet_motra::AccrualCheckpoint::<Runtime>::hashed_key_for(account(1));
        let touched = ext
            .overlayed_changes()
            .changes()
            .filter(|(key, _)| key.starts_with(&prefix[..32]))
            .count();
        assert_eq!(
            touched, 97,
            "96 rewarded signers plus treasury or refunded submitter"
        );
        let actual = post.actual_weight.expect("threshold refund");
        let checkpoints =
            pallet_motra::checkpoint_weight::<Runtime>().saturating_mul(touched as u64);
        assert!(actual.all_gte(checkpoints));
        use pallet_orinq_receipts::weights::WeightInfo;
        assert_eq!(
            actual,
            checkpoints.saturating_add(
                pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::attest_threshold(96)
            ),
            "threshold charges more than observed payouts: {actual:?}, {checkpoints:?}"
        );
        assert!(actual.all_lte(info.weight));
        ext.execute_with(|| {
            let (_, post) = dispatch(attest(id, hash), account(1));
            assert!(
                post.actual_weight.expect("late refund")
                    == <Runtime as pallet_orinq_receipts::Config>::WeightInfo::attest_non_threshold(
                    )
            );
        });
    }
}

#[test]
fn refund_optional_receipt_and_billing_mutations_return_actual_weight() {
    externalities().execute_with(|| {
        let (id, _) = receipt(3, 2, 0);
        let cert = RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::set_availability_cert {
            receipt_id: id,
            cert_hash: [9; 32],
        });
        let info = cert.get_dispatch_info();
        let post = cert
            .dispatch(RuntimeOrigin::root())
            .expect("root certification");
        use pallet_orinq_receipts::weights::WeightInfo as _;
        assert_eq!(
            post.actual_weight,
            Some(
                pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::set_availability_cert()
            )
        );
        assert!(post.calc_actual_weight(&info).all_lt(info.weight));

        let topup = RuntimeCall::Billing(pallet_billing::Call::topup_self { amount: 0 });
        let (_, post) = dispatch(topup, account(200));
        use pallet_billing::weights::WeightInfo as _;
        assert_eq!(
            post.actual_weight,
            Some(pallet_billing::weights::SubstrateWeight::<Runtime>::topup_self())
        );

        pallet_billing::PendingWithdrawals::<Runtime>::insert(account(200), (100_000u128, 100));
        let call = RuntimeCall::Billing(pallet_billing::Call::execute_withdrawal {});
        let (_, post) = dispatch(call, account(200));
        assert_eq!(
            post.actual_weight,
            Some(
                pallet_billing::weights::SubstrateWeight::<Runtime>::execute_withdrawal()
                    .saturating_add(pallet_motra::checkpoint_weight::<Runtime>())
            )
        );
    });
}

#[test]
fn refund_bond_slash_and_expiry_charge_only_changed_accounts() {
    externalities().execute_with(|| {
        let (id, _) = receipt(3, 3, 0);
        let (_, post) = dispatch(
            RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::bond { amount: 0 }),
            account(1),
        );
        assert_eq!(post.actual_weight, Some(<pallet_orinq_receipts::weights::SubstrateWeight<Runtime> as pallet_orinq_receipts::weights::WeightInfo>::bond()));
        let call = RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::slash_attestor {
            attestor: account(1),
            amount: 100,
            reason: pallet_orinq_receipts::types::SlashReason::Governance,
        });
        let post = call
            .dispatch(RuntimeOrigin::root())
            .expect("empty bond slash");
        assert_eq!(post.actual_weight, Some(<pallet_orinq_receipts::weights::SubstrateWeight<Runtime> as pallet_orinq_receipts::weights::WeightInfo>::slash_attestor()));
        pallet_orinq_receipts::ReceiptExpiryBlocks::<Runtime>::put(10);
        System::set_block_number(111);
        let (_, post) = dispatch(
            RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::expire_receipt_fee {
                receipt_id: id,
            }),
            account(1),
        );
        assert_eq!(post.actual_weight, Some(<pallet_orinq_receipts::weights::SubstrateWeight<Runtime> as pallet_orinq_receipts::weights::WeightInfo>::expire_receipt_fee()));
    });
}

#[test]
fn refund_currency_call_budgets_cover_real_checkpoint_writes() {
    use frame_support::traits::ReservableCurrency;
    for operation in 0..15 {
        let mut ext = externalities();
        let call = ext.execute_with(|| {
            let (id, hash) = receipt(3, 3, 100_000);
            let who = account(200);
            match operation {
                0 => RuntimeCall::Billing(pallet_billing::Call::topup_self { amount: 10_000 }),
                1 => RuntimeCall::Billing(pallet_billing::Call::topup_for {
                    target: account(1),
                    amount: 10_000,
                }),
                2 | 3 => {
                    pallet_billing::PendingWithdrawals::<Runtime>::insert(&who, (100_000u128, 100));
                    if operation == 3 {
                        fund(&who, u128::MAX);
                    }
                    RuntimeCall::Billing(pallet_billing::Call::execute_withdrawal {})
                }
                4 => {
                    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::bond { amount: 10_000 })
                }
                5 | 6 => {
                    assert_ok!(Balances::reserve(&who, 10_000));
                    pallet_orinq_receipts::AttestorBonds::<Runtime>::insert(&who, 10_000);
                    if operation == 5 {
                        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::unbond {})
                    } else {
                        fund(&OrinqReceipts::attestor_reserve_account(), 1_000_000);
                        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::slash_attestor {
                            attestor: who,
                            amount: 10_000,
                            reason: pallet_orinq_receipts::types::SlashReason::Governance,
                        })
                    }
                }
                7 => {
                    pallet_orinq_receipts::ReceiptExpiryBlocks::<Runtime>::put(10);
                    System::set_block_number(111);
                    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::expire_receipt_fee {
                        receipt_id: id,
                    })
                }
                8 => {
                    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::set_availability_cert {
                        receipt_id: id,
                        cert_hash: hash,
                    })
                }
                9 | 10 => {
                    let signer = account(1);
                    assert_ok!(Balances::reserve(&signer, 10_000));
                    pallet_orinq_receipts::AttestorBonds::<Runtime>::insert(&signer, 10_000);
                    pallet_orinq_receipts::BadAttestSlashThreshold::<Runtime>::put(1);
                    if operation == 9 {
                        fund(&OrinqReceipts::attestor_reserve_account(), 1_000_000);
                    }
                    attest(id, [99; 32])
                }
                11..=14 => {
                    pallet_orinq_receipts::ReceiptSubmissionFee::<Runtime>::put(
                        if operation % 2 == 0 { 0 } else { 10_000 },
                    );
                    if operation <= 12 {
                        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_receipt {
                            receipt_id: H256::repeat_byte(50),
                            content_hash: H256::repeat_byte(51),
                            base_root_sha256: [1; 32],
                            zk_root_poseidon: None,
                            poseidon_params_hash: None,
                            base_manifest_hash: [2; 32],
                            safety_manifest_hash: [3; 32],
                            monitor_config_hash: [4; 32],
                            attestation_evidence_hash: [5; 32],
                            storage_locator_hash: [6; 32],
                            schema_hash: [7; 32],
                        })
                    } else {
                        RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_receipt_v2 {
                            player_pubkey: [8; 32],
                            player_sig: [0; 64],
                            sig_type: 0,
                            receipt_id: H256::repeat_byte(50),
                            content_hash: H256::repeat_byte(51),
                            base_root_sha256: [1; 32],
                            zk_root_poseidon: None,
                            poseidon_params_hash: None,
                            base_manifest_hash: [2; 32],
                            safety_manifest_hash: [3; 32],
                            monitor_config_hash: [4; 32],
                            attestation_evidence_hash: [5; 32],
                            storage_locator_hash: [6; 32],
                            schema_hash: [7; 32],
                        })
                    }
                }
                _ => unreachable!(),
            }
        });
        ext.commit_all().expect("fixture commit");
        let (declared, actual, success) = ext.execute_with(|| {
            let info = call.get_dispatch_info();
            let signer = if matches!(operation, 9 | 10) {
                account(1)
            } else {
                account(200)
            };
            let origin = if matches!(operation, 6 | 8) {
                RuntimeOrigin::root()
            } else {
                RuntimeOrigin::signed(signer)
            };
            match call.dispatch(origin) {
                Ok(post) => {
                    assert!(
                        post.actual_weight.is_some(),
                        "operation {operation} omits actual weight"
                    );
                    (info.weight, post.calc_actual_weight(&info), true)
                }
                Err(error) => (
                    info.weight,
                    error.post_info.calc_actual_weight(&info),
                    false,
                ),
            }
        });
        assert_eq!(success, operation != 3, "operation {operation}");
        let prefix = pallet_motra::AccrualCheckpoint::<Runtime>::hashed_key_for(account(1));
        let touched = ext
            .overlayed_changes()
            .changes()
            .filter(|(key, _)| key.starts_with(&prefix[..32]))
            .count();
        assert_eq!(
            touched,
            if matches!(operation, 3 | 10 | 12 | 14) {
                0
            } else {
                1
            },
            "operation {operation}"
        );
        let required = pallet_motra::checkpoint_weight::<Runtime>().saturating_mul(touched as u64);
        assert!(
            actual.all_gte(required),
            "operation {operation}: {actual:?}, {required:?}"
        );
        assert!(actual.all_lte(declared), "operation {operation}");
        if operation == 3 {
            ext.execute_with(|| {
                assert!(pallet_billing::PendingWithdrawals::<Runtime>::contains_key(
                    account(200)
                ));
                assert_eq!(Balances::free_balance(account(200)), u128::MAX);
            });
            assert!(
                declared.all_gte(pallet_motra::checkpoint_weight::<Runtime>().saturating_mul(2))
            );
        }
    }
}

#[test]
fn refund_non_threshold_block_capacity_matches_priced_work() {
    use frame_support::dispatch::DispatchClass;
    use parity_scale_codec::Encode;
    externalities().execute_with(|| {
        let (template, _) = receipt(3, 2, 0);
        let record = pallet_orinq_receipts::Receipts::<Runtime>::get(template).expect("template receipt");
        let who = account(1);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.decay_rate_per_block = Perbill::one();
            p.generation_per_matra_per_block = 0;
            p.congestion_rate = 1_000_000;
            p.length_fee_per_byte = 0;
        });
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        let limits = RuntimeBlockWeights::get();
        let normal = limits.get(DispatchClass::Normal);
        let cap = normal.max_total.expect("normal cap").ref_time();
        let mut accepted = 0u64;
        let mut declared = 0;
        let mut actual = 0;
        let mut proof = 0;
        for i in 0u64..20_000 {
            let id = H256::from_low_u64_be(i + 1_000);
            pallet_orinq_receipts::Receipts::<Runtime>::insert(id, record.clone());
            let hash = OrinqReceipts::canonical_cert_hash(id).expect("cert").0;
            let call = attest(id, hash);
            let info = call.get_dispatch_info();
            let len = call.encoded_size() + 128;
            if frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, len).is_err() { break; }
            let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&who, &call, &info, len).expect("fee");
            let post = call.dispatch(RuntimeOrigin::signed(who.clone())).expect("non-threshold attest");
            assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(None, &info, &post, len, &Ok(())));
            assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(Some(pre), &info, &post, len, &Ok(())));
            declared = info.weight.ref_time() + normal.base_extrinsic.ref_time();
            actual = post.calc_actual_weight(&info).ref_time() + normal.base_extrinsic.ref_time();
            proof = post.calc_actual_weight(&info).proof_size() + normal.base_extrinsic.proof_size() + len as u64;
            accepted += 1;
        }
        let before_refunds = cap / declared;
        let expected = (cap - declared) / actual + 1;
        assert_eq!(accepted, expected);
        assert_eq!(*System::block_weight().get(DispatchClass::Normal), Weight::from_parts(actual * accepted,
            proof * accepted));
        assert!(accepted > before_refunds * 10);
        let pre_68 = cap / (ExtrinsicBaseWeight::get().ref_time() + 15_000);
        assert!(pre_68 * normal.base_extrinsic.ref_time() > cap,
            "the historical capacity cannot fit even with zero call weight once the fee path is reserved");
        eprintln!("non-threshold attests/block: actual {accepted}; without refunds {before_refunds}; fully refunded theoretical {}; pre-68 underpriced {pre_68}; declared={declared}, actual={actual}", cap / actual);
    });
}

#[test]
fn refund_failed_legacy_bond_keeps_its_budget_and_rolls_back_checkpoints() {
    let mut ext = externalities();
    let who = account(200);
    ext.execute_with(|| {
        System::set_block_number(100);
        fund(&who, 1_000);
        frame_system::Account::<Runtime>::mutate(&who, |a| {
            a.data.free = 250;
            a.data.reserved = 500;
            a.data.flags = pallet_balances::ExtraFlags::old_logic();
            a.providers = 0;
        });
        pallet_motra::AccrualCheckpoint::<Runtime>::insert(&who, (250u128, 90));
    });
    ext.commit_all().expect("legacy fixture");
    ext.execute_with(|| {
        let call = RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::bond { amount: 250 });
        let info = call.get_dispatch_info();
        let error = call
            .dispatch(RuntimeOrigin::signed(who.clone()))
            .expect_err("reserved funds keep the repaired provider alive");
        assert_eq!(error.error, sp_runtime::DispatchError::ConsumerRemaining);
        assert_eq!(error.post_info.calc_actual_weight(&info), info.weight);
        assert_eq!(Balances::free_balance(&who), 250);
        assert_eq!(
            pallet_motra::AccrualCheckpoint::<Runtime>::get(&who),
            Some((250, 90))
        );
    });
    let prefix = pallet_motra::AccrualCheckpoint::<Runtime>::hashed_key_for(&who);
    let touched = ext
        .overlayed_changes()
        .changes()
        .filter(|(key, _)| key.starts_with(&prefix[..32]))
        .count();
    assert_eq!(
        touched, 0,
        "the rejected reserve must unwind the preceding repair"
    );
}

#[test]
fn refund_batched_non_threshold_attests_match_database_pricing() {
    use frame_support::dispatch::DispatchClass;
    use pallet_utility::WeightInfo;
    use parity_scale_codec::Encode;
    for maximum_width in [1, 32, 96] {
        externalities().execute_with(|| {
        let (template, _) = receipt(3, 2, 0);
        let record = pallet_orinq_receipts::Receipts::<Runtime>::get(template).expect("receipt");
        let who = account(1);
        pallet_motra::Params::<Runtime>::mutate(|p| {
            p.decay_rate_per_block = Perbill::one();
            p.generation_per_matra_per_block = 0;
            p.congestion_rate = 1_000_000;
            p.length_fee_per_byte = 0;
        });
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        let limits = RuntimeBlockWeights::get();
        let normal = limits.get(DispatchClass::Normal);
        let cap = normal.max_total.expect("normal cap");
        let per_call = attest(template, [0; 32]).get_dispatch_info().weight;
        let mut accepted = 0u64;
        let mut batches = 0u64;
        loop {
            let remaining = cap.saturating_sub(*System::block_weight().get(DispatchClass::Normal))
                .saturating_sub(normal.base_extrinsic);
            let width = (1u32..=maximum_width).take_while(|n| {
                per_call.saturating_mul(u64::from(*n))
                    .saturating_add(<Runtime as pallet_utility::Config>::WeightInfo::batch(*n))
                    .all_lte(remaining)
            }).last().unwrap_or(0);
            if width == 0 { break; }
            let mut ids = Vec::new();
            let calls = (0..width).map(|i| {
                let id = H256::from_low_u64_be(accepted + u64::from(i) + 1_000);
                pallet_orinq_receipts::Receipts::<Runtime>::insert(id, record.clone());
                let hash = OrinqReceipts::canonical_cert_hash(id).expect("cert").0;
                ids.push(id);
                attest(id, hash)
            }).collect();
            let call = RuntimeCall::Utility(pallet_utility::Call::batch { calls });
            let info = call.get_dispatch_info();
            let len = call.encoded_size() + 128;
            assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(&info, len));
            let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&who, &call, &info, len).expect("batch fee");
            let post = call.dispatch(RuntimeOrigin::signed(who.clone())).expect("batch");
            for id in ids {
                let (_, signers) = pallet_orinq_receipts::Attestations::<Runtime>::get(id).expect("attested");
                assert_eq!(signers.len(), 1);
                assert!(signers.contains(&who));
                assert_eq!(pallet_orinq_receipts::Receipts::<Runtime>::get(id).expect("receipt").availability_cert_hash, [0; 32]);
            }
            assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(None, &info, &post, len, &Ok(())));
            assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(Some(pre), &info, &post, len, &Ok(())));
            accepted += u64::from(width);
            batches += 1;
        }
        let historical = cap.ref_time() / (ExtrinsicBaseWeight::get().ref_time() + 15_000);
        let actual = <Runtime as pallet_orinq_receipts::Config>::WeightInfo::attest_non_threshold();
        let minimum = cap.ref_time() / per_call.saturating_add(normal.base_extrinsic).ref_time();
        assert!(accepted > minimum, "refunds must improve on worst-case admission");
        assert!(accepted <= cap.ref_time() / actual.ref_time());
        if maximum_width == 96 { assert_eq!(accepted, 3_705, "database-priced batching capacity regression"); }
        assert!(System::block_weight().get(DispatchClass::Normal).all_lte(cap));
        eprintln!("batched non-threshold attests/block (maximum width {maximum_width}): {accepted} in {batches} signed batches; historical {historical}; consumed {:?}", System::block_weight());
    });
    }
}
