use crate::*;
use frame_support::{
    assert_ok,
    dispatch::{DispatchInfo, GetDispatchInfo, PostDispatchInfo},
    traits::Get,
    BoundedBTreeSet,
};
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

fn pricing_params(rate: u128) {
    pallet_motra::Params::<Runtime>::mutate(|p| {
        p.decay_rate_per_block = Perbill::one();
        p.generation_per_matra_per_block = 0;
        p.congestion_rate = rate;
        p.max_balance = u128::MAX;
    });
}

fn validity(
    who: &AccountId,
    call: &RuntimeCall,
) -> sp_runtime::transaction_validity::TransactionValidity {
    use parity_scale_codec::Encode;
    pallet_motra::fee::ChargeMotra::<Runtime>::new().validate(
        who,
        call,
        &call.get_dispatch_info(),
        call.encoded_size() + 128,
    )
}

#[test]
fn pricing_refundable_batch_weight_cannot_buy_priority() {
    use parity_scale_codec::Encode;
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 2, 0);
        let who = account(1);
        pricing_params(1_000_000_000);
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        let transfer = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
            dest: account(2).into(), value: 1,
        });
        let failure = RuntimeCall::System(frame_system::Call::set_heap_pages { pages: 0 });
        let transfer_priority = validity(&who, &transfer).expect("transfer valid").priority;
        for count in [1, 10, 29] {
            let mut calls = vec![failure.clone()];
            calls.extend((0..count).map(|_| attest(id, hash)));
            let batch = RuntimeCall::Utility(pallet_utility::Call::batch { calls });
            let priority = validity(&who, &batch).expect("paid mixed batch").priority;
            let info = batch.get_dispatch_info();
            let len = batch.encoded_size() + 128;
            let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&who, &batch, &info, len).expect("batch fee");
            let before = Motra::total_burned();
            let post = batch.dispatch(RuntimeOrigin::signed(who.clone())).expect("batch stops");
            assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(Some(pre.clone()), &info, &post, len, &Ok(())));
            let paid = pre.expect("paid batch").1 - (before - Motra::total_burned());
            let transfer_fee = Motra::compute_fee(transfer.get_dispatch_info().weight, transfer.encoded_size() + 128);
            assert!(priority <= transfer_priority || paid > transfer_fee,
                "{count} refundable attests: priority {priority}>{transfer_priority} while fee {paid}<={transfer_fee}");
        }
    });
}

#[test]
fn pricing_remark_ramp_prices_the_complete_signed_weight() {
    use frame_support::{dispatch::DispatchClass, traits::Hooks};
    externalities().execute_with(|| {
        System::set_block_number(100);
        pricing_params(0);
        let remark = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
        let transfer = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
            dest: account(2).into(),
            value: 1,
        });
        let normal = RuntimeBlockWeights::get()
            .get(DispatchClass::Normal)
            .clone();
        let capacity = normal.max_total.expect("normal limit");
        let mut total = 0u128;
        for block in 100..1_100 {
            let params = Motra::params();
            for call in [&remark, &transfer] {
                let signed = call
                    .get_dispatch_info()
                    .weight
                    .saturating_add(normal.base_extrinsic);
                let fee = Motra::compute_fee(call.get_dispatch_info().weight, 128);
                let length_work = capacity.ref_time()
                    / u64::from(*RuntimeBlockLength::get().max.get(DispatchClass::Normal))
                    * 128;
                assert_eq!(
                    fee,
                    params.min_fee
                        + params.length_fee_per_byte * 128
                        + params.congestion_rate * u128::from(signed.ref_time() + length_work)
                            / 1_000_000,
                    "signed work is underpriced at block {block}"
                );
            }
            total += Motra::compute_fee(remark.get_dispatch_info().weight, 128)
                * u128::from(
                    capacity.ref_time()
                        / (normal.base_extrinsic.ref_time()
                            + remark.get_dispatch_info().weight.ref_time()),
                );
            frame_system::BlockWeight::<Runtime>::mutate(|w| {
                w.set(capacity, DispatchClass::Normal)
            });
            Motra::on_finalize(block);
        }
        assert!(Motra::params().congestion_rate > 1_000_000_000);
        eprintln!(
            "1,000 full remark blocks: cost={total}, final R={}",
            Motra::params().congestion_rate
        );
        let (id, hash) = receipt(1, 1, 0);
        assert_eq!(Motra::motra_balance(&account(1)), 0);
        assert!(
            validity(&account(1), &attest(id, hash)).is_ok(),
            "zero-MOTRA daemon must survive the ramp"
        );
        let call = attest(id, hash);
        let info = call.get_dispatch_info();
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&account(1), &call, &info, 169)
            .expect("duty after congestion ramp");
        let post = call
            .dispatch(RuntimeOrigin::signed(account(1)))
            .expect("certify after ramp");
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            169,
            &Ok(())
        ));
        assert_eq!(
            pallet_orinq_receipts::Receipts::<Runtime>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            hash
        );
    });
}

#[test]
fn pricing_attestation_duty_rejects_invalid_and_replayed_calls() {
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 2, 0);
        pricing_params(50_000_000_000);
        for who in [account(1), account(4)] {
            pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        }
        assert!(
            validity(&account(4), &attest(id, hash)).is_err(),
            "non-member"
        );
        assert!(
            validity(&account(1), &attest(H256::zero(), hash)).is_err(),
            "unknown"
        );
        assert!(
            validity(&account(1), &attest(id, [99; 32])).is_err(),
            "wrong hash cannot consume unlimited free duty slots"
        );
        assert_ok!(attest(id, hash).dispatch(RuntimeOrigin::signed(account(1))));
        assert!(
            validity(&account(1), &attest(id, hash)).is_err(),
            "duplicate"
        );
        assert_ok!(attest(id, hash).dispatch(RuntimeOrigin::signed(account(2))));
        assert!(
            validity(&account(1), &attest(id, hash)).is_err(),
            "certified"
        );
    });
}

#[test]
fn pricing_zero_balance_member_certifies_for_free_and_rechecks_before_dispatch() {
    use parity_scale_codec::Encode;
    externalities().execute_with(|| {
        let (id, hash) = receipt(2, 1, 0);
        pricing_params(50_000_000_000);
        let who = account(1);
        let call = attest(id, hash);
        let valid = validity(&who, &call).expect("zero-MOTRA validator duty");
        assert_eq!(valid.provides.len(), 1);
        let info = call.get_dispatch_info();
        let len = call.encoded_size() + 128;
        assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
            &info, len
        ));
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &call, &info, len)
            .expect("feeless pre-dispatch");
        let burned = Motra::total_burned();
        let post = call
            .clone()
            .dispatch(RuntimeOrigin::signed(who.clone()))
            .expect("certifies");
        assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(
            None,
            &info,
            &post,
            len,
            &Ok(())
        ));
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            len,
            &Ok(())
        ));
        assert_eq!(Motra::total_burned(), burned);
        assert_eq!(Motra::motra_balance(&who), 0);
        assert_eq!(
            pallet_orinq_receipts::Receipts::<Runtime>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            hash
        );
        assert!(
            pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&account(2), &call, &info, len)
                .is_err(),
            "stale pool result must not bypass the check"
        );
    });
}

#[test]
fn pricing_pure_attestation_batches_are_free_and_have_per_receipt_tags() {
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 2, 0);
        pricing_params(50_000_000_000);
        let second = H256::repeat_byte(55);
        pallet_orinq_receipts::Receipts::<Runtime>::insert(
            second,
            pallet_orinq_receipts::Receipts::<Runtime>::get(id).expect("receipt"),
        );
        let other_hash = OrinqReceipts::canonical_cert_hash(second).expect("hash").0;
        let single = attest(id, hash);
        for atomic in [false, true] {
            let calls = vec![single.clone(), attest(second, other_hash)];
            let batch = RuntimeCall::Utility(if atomic {
                pallet_utility::Call::batch_all { calls }
            } else {
                pallet_utility::Call::batch { calls }
            });
            let valid = validity(&account(1), &batch).expect("feeless batch");
            assert_eq!(valid.provides.len(), 2);
            assert!(valid
                .provides
                .contains(&validity(&account(1), &single).expect("single").provides[0]));
            assert_eq!(
                valid.priority,
                validity(&account(1), &single).expect("single").priority
            );
        }
        let duplicate = RuntimeCall::Utility(pallet_utility::Call::batch {
            calls: vec![single.clone(), single],
        });
        assert!(
            validity(&account(1), &duplicate).is_err(),
            "in-batch replay"
        );
    });
}

#[test]
fn pricing_refund_respects_max_balance_and_net_burn() {
    externalities().execute_with(|| {
        System::set_block_number(100);
        pricing_params(1_000_000_000);
        let who = account(1);
        let cap = 10_000_000_000_000u128;
        pallet_motra::Params::<Runtime>::mutate(|p| p.max_balance = cap);
        pallet_motra::MotraBalances::<Runtime>::insert(&who, cap);
        let call = RuntimeCall::Motra(pallet_motra::Call::claim_motra {});
        let info = call.get_dispatch_info();
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &call, &info, 128)
            .expect("fee");
        pallet_motra::MotraBalances::<Runtime>::insert(&who, cap - 7);
        let issued = Motra::total_issued();
        let burned = Motra::total_burned();
        let post = PostDispatchInfo {
            actual_weight: Some(Weight::zero()),
            ..Default::default()
        };
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            128,
            &Ok(())
        ));
        assert_eq!(Motra::motra_balance(&who), cap);
        assert_eq!(Motra::total_burned(), burned - 7);
        assert_eq!(Motra::total_issued(), issued);
    });
}

#[test]
fn pricing_non_threshold_weight_covers_95_prior_signers() {
    externalities().execute_with(|| {
        let (id, hash) = receipt(96, 96, 0);
        let first = attest(id, hash)
            .dispatch(RuntimeOrigin::signed(account(1)))
            .expect("first attest");
        let signers: BoundedBTreeSet<
            AccountId,
            <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
        > = (1..=95)
            .map(account)
            .collect::<std::collections::BTreeSet<_>>()
            .try_into()
            .expect("95 signers");
        pallet_orinq_receipts::Attestations::<Runtime>::insert(id, (H256::from(hash), signers));
        let post = attest(id, hash)
            .dispatch(RuntimeOrigin::signed(account(1)))
            .expect("duplicate backstop");
        assert!(
            post.actual_weight.expect("actual").ref_time()
                > first.actual_weight.expect("actual").ref_time(),
            "95 signers require a measured signer-count term"
        );
    });
}

#[test]
fn pricing_multisig_refundable_max_weight_cannot_raise_priority() {
    externalities().execute_with(|| {
        System::set_block_number(100);
        let who = account(1);
        pricing_params(1_000_000_000);
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        let make = |weight| {
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: vec![account(2)],
                maybe_timepoint: None,
                call: Box::new(RuntimeCall::System(frame_system::Call::remark {
                    remark: vec![],
                })),
                max_weight: Weight::from_parts(weight, 0),
            })
        };
        let small = validity(&who, &make(1_000_000)).expect("small multisig");
        let large = validity(&who, &make(500_000_000_000)).expect("large multisig");
        assert!(
            large.priority <= small.priority,
            "refundable multisig max_weight buys priority"
        );
    });
}

#[test]
fn pricing_fee_and_priority_table() {
    use parity_scale_codec::Encode;
    for rate in [0u128, 1_000_000_000, 50_000_000_000] {
        for name in [
            "transfer",
            "remark",
            "attest_member",
            "attest_non_member",
            "submit_receipt",
            "claim",
            "set_delegatee",
            "operational_stuffer",
        ] {
            externalities().execute_with(|| {
                let (id, hash) = receipt(3, 2, 0);
                pricing_params(rate);
                let who = if name == "attest_non_member" { account(4) } else { account(1) };
                pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
                let call = match name {
                    "transfer" => RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive { dest: account(2).into(), value: 1 }),
                    "remark" => RuntimeCall::System(frame_system::Call::remark { remark: vec![] }),
                    "attest_member" | "attest_non_member" => attest(id, hash),
                    "submit_receipt" => submit(H256::repeat_byte(9)),
                    "claim" => RuntimeCall::Motra(pallet_motra::Call::claim_motra {}),
                    "operational_stuffer" => RuntimeCall::Utility(pallet_utility::Call::with_weight {
                        call: Box::new(RuntimeCall::RootTimelock(pallet_root_timelock::Call::cancel_all {})),
                        weight: Weight::from_parts(1_000_000_000_000, 0),
                    }),
                    _ => RuntimeCall::Motra(pallet_motra::Call::set_delegatee { delegatee: Some(account(2)) }),
                };
                let extra: SignedExtra = (
                    frame_system::CheckNonZeroSender::new(), frame_system::CheckSpecVersion::new(),
                    frame_system::CheckTxVersion::new(), frame_system::CheckGenesis::new(),
                    frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
                    frame_system::CheckNonce::from(0), frame_system::CheckWeight::new(),
                    pallet_motra::fee::ChargeMotra::new(),
                );
                let signed = UncheckedExtrinsic::new_signed(call.clone(), who.clone().into(),
                    Signature::Sr25519(sp_core::sr25519::Signature::from_raw([0; 64])), extra);
                let len = signed.encoded_size();
                let info = call.get_dispatch_info();
                let validity = pallet_motra::fee::ChargeMotra::<Runtime>::new().validate(&who, &call, &info, len);
                if name == "attest_non_member" || name == "operational_stuffer" {
                    assert!(validity.is_err(), "{name} rejected before payment");
                    eprintln!("PRICING {{\"R\":{rate},\"call\":\"{name}\",\"status\":\"rejected\",\"length\":{len}}}");
                    return;
                }
                let priority = validity.expect("valid call").priority;
                let before = Motra::total_burned();
                let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new().pre_dispatch(&who, &call, &info, len).expect("pre-dispatch");
                let escrow = Motra::total_burned() - before;
                let post = call.dispatch(RuntimeOrigin::signed(who)).expect("dispatch");
                assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(Some(pre), &info, &post, len, &Ok(())));
                let fee = Motra::total_burned() - before;
                if ["transfer", "remark", "claim", "set_delegatee"].contains(&name) {
                    let class = frame_support::dispatch::DispatchClass::Normal;
                    let per_byte = RuntimeBlockWeights::get().get(class).max_total.expect("Normal budget").ref_time()
                        / u64::from(*RuntimeBlockLength::get().max.get(class));
                    let params = Motra::params();
                    let work = info.weight.ref_time()
                        + RuntimeBlockWeights::get().get(class).base_extrinsic.ref_time()
                        + len as u64 * per_byte;
                    assert_eq!(
                        fee,
                        params.min_fee + rate * u128::from(work) / 1_000_000
                            + params.length_fee_per_byte * len as u128,
                        "{name} prices call, signed base and length at R={rate}"
                    );
                }
                if name == "transfer" && rate == 1_000_000_000 {
                    assert_eq!(fee, 1_809_018_191_000);
                }
                if name == "attest_member" {
                    assert_eq!(fee, 0);
                    assert_eq!(priority, sp_runtime::transaction_validity::TransactionPriority::MAX - 1);
                } else {
                    assert!(priority < sp_runtime::transaction_validity::TransactionPriority::MAX - 1);
                }
                eprintln!("PRICING {{\"R\":{rate},\"call\":\"{name}\",\"fee\":{fee},\"escrow\":{escrow},\"priority\":{priority},\"length\":{len},\"call_weight\":{}}}", info.weight.ref_time());
            });
        }
    }
}

/// A submission prepays its committee's certification at the current
/// threshold, so its escrow grows with the threshold.
#[test]
fn pricing_submission_escrow_grows_with_the_threshold() {
    use parity_scale_codec::Encode;
    let mut previous = 0;
    for threshold in [1u32, 2, 16, 64, 96] {
        externalities().execute_with(|| {
            receipt(96, threshold, 0);
            pricing_params(1_000_000_000);
            let who = account(1);
            pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
            let call = submit(H256::repeat_byte(9));
            let info = call.get_dispatch_info();
            let len = call.encoded_size() + 105;
            let before = Motra::total_burned();
            pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&who, &call, &info, len)
                .expect("escrow");
            let escrow = Motra::total_burned() - before;
            assert!(escrow > previous, "threshold {threshold}");
            previous = escrow;
            eprintln!(
                "SUBMISSION {{\"threshold\":{threshold},\"escrow\":{escrow},\"length\":{len}}}"
            );
        });
    }
}

#[test]
fn pricing_saturated_refund_preserves_the_non_refundable_base() {
    externalities().execute_with(|| {
        System::set_block_number(100);
        pricing_params(u128::MAX / 4);
        let who = account(1);
        pallet_motra::MotraBalances::<Runtime>::insert(&who, u128::MAX);
        let call = RuntimeCall::Motra(pallet_motra::Call::claim_motra {});
        let info = call.get_dispatch_info();
        assert!(
            RuntimeBlockWeights::get()
                .get(frame_support::dispatch::DispatchClass::Normal)
                .base_extrinsic
                .ref_time()
                > 4_000_000
        );
        let non_refundable = u128::MAX;
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &call, &info, 128)
            .expect("maximum payment");
        let post = PostDispatchInfo {
            actual_weight: Some(Weight::zero()),
            ..Default::default()
        };
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            128,
            &Ok(())
        ));
        assert!(
            Motra::total_burned() >= non_refundable,
            "overflow must not refund the signed base"
        );
    });
}

#[test]
fn pricing_zero_balance_pure_batches_execute_and_pay_nothing() {
    use parity_scale_codec::Encode;
    for atomic in [false, true] {
        externalities().execute_with(|| {
            let (id, hash) = receipt(3, 2, 0);
            pricing_params(50_000_000_000);
            let who = account(1);
            let second = H256::repeat_byte(55);
            pallet_orinq_receipts::Receipts::<Runtime>::insert(
                second,
                pallet_orinq_receipts::Receipts::<Runtime>::get(id).expect("receipt"),
            );
            let other_hash = OrinqReceipts::canonical_cert_hash(second).expect("hash").0;
            let calls = vec![attest(id, hash), attest(second, other_hash)];
            let batch = RuntimeCall::Utility(if atomic {
                pallet_utility::Call::batch_all { calls }
            } else {
                pallet_utility::Call::batch { calls }
            });
            assert_ok!(validity(&who, &batch));
            let info = batch.get_dispatch_info();
            let len = batch.encoded_size() + 128;
            assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
                &info, len
            ));
            let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(&who, &batch, &info, len)
                .expect("free batch");
            let post = batch
                .dispatch(RuntimeOrigin::signed(who.clone()))
                .expect("batch");
            assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(
                None,
                &info,
                &post,
                len,
                &Ok(())
            ));
            assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
                Some(pre),
                &info,
                &post,
                len,
                &Ok(())
            ));
            for receipt_id in [id, second] {
                assert!(
                    pallet_orinq_receipts::Attestations::<Runtime>::get(receipt_id)
                        .expect("attested")
                        .1
                        .contains(&who)
                );
            }
            assert_eq!(Motra::motra_balance(&who), 0);
            assert_eq!(Motra::total_burned(), 0);
            assert_eq!(Motra::insufficient_motra_failures(), 0);
        });
    }
}

fn dispatch(call: RuntimeCall, who: AccountId) -> (DispatchInfo, PostDispatchInfo) {
    let info = call.get_dispatch_info();
    let post = call.dispatch(RuntimeOrigin::signed(who)).expect("dispatch");
    assert!(post.calc_actual_weight(&info).all_lte(info.weight));
    (info, post)
}

#[test]
fn refund_non_threshold_attest_charges_no_checkpoints_and_no_motra() {
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
            .filter(|s| {
                s["components"].as_array().expect("components").is_empty()
                    || s["components"][0][1].as_u64().expect("signer count") == 0
            })
            .map(|s| s["extrinsic_time"].as_u64().expect("time"))
            .collect();
        times.sort_unstable();
        assert!(
            actual.ref_time() >= times[times.len() / 2] * 1_000,
            "actual weight must cover benchmarked execution"
        );
        assert_eq!(
            actual,
            <<Runtime as pallet_orinq_receipts::Config>::WeightInfo as pallet_orinq_receipts::weights::WeightInfo>::attest_non_threshold(1),
            "non-threshold attestation must not carry any checkpoint surcharge"
        );
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            0,
            &Ok(()),
        ));
        assert_eq!(before, Motra::motra_balance(&who));
        assert_eq!(Motra::total_burned(), 0);
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
            assert_eq!(
                post.actual_weight.expect("late refund"),
                pallet_orinq_receipts::weights::SubstrateWeight::<Runtime>::attest_non_threshold(
                    <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize::get()
                ),
                "late backstop retains the signer-count bound without checkpoint charges"
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
            actual = post.calc_actual_weight(&info).ref_time() + ExtrinsicBaseWeight::get().ref_time();
            proof = post.calc_actual_weight(&info).proof_size() + ExtrinsicBaseWeight::get().proof_size() + len as u64;
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
fn refund_batched_non_threshold_attests_fill_the_block_at_their_actual_weight() {
    use frame_support::dispatch::DispatchClass;
    use pallet_utility::WeightInfo;
    use parity_scale_codec::Encode;
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
            let width = (1u32..=96).take_while(|n| {
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
        // Each attest is refunded to its first-signer weight, and each duty
        // batch releases the unused fee path of its signed base; the block
        // stops only when one more single-attest batch cannot reserve its
        // declared weight.
        let actual = <<Runtime as pallet_orinq_receipts::Config>::WeightInfo as pallet_orinq_receipts::weights::WeightInfo>::attest_non_threshold(1);
        let consumed = *System::block_weight().get(DispatchClass::Normal);
        assert!(consumed.all_lte(cap));
        assert!(per_call
            .saturating_add(<Runtime as pallet_utility::Config>::WeightInfo::batch(1))
            .saturating_add(normal.base_extrinsic)
            .any_gt(cap.saturating_sub(consumed)));
        assert!(
            consumed.ref_time()
                >= actual.ref_time() * accepted + ExtrinsicBaseWeight::get().ref_time() * batches,
            "attests must be charged at least their actual weight"
        );
        assert!(accepted > cap.ref_time() / per_call.ref_time(), "refunds must beat declared admission");
        eprintln!("batched non-threshold attests/block: {accepted} in {batches} signed batches; consumed {:?}", System::block_weight());
    });
}

fn remark() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
}

fn utility(call: pallet_utility::Call<Runtime>) -> RuntimeCall {
    RuntimeCall::Utility(call)
}

fn submit(id: H256) -> RuntimeCall {
    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_receipt {
        receipt_id: id,
        content_hash: H256::repeat_byte(66),
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

fn submit_v2(id: H256) -> RuntimeCall {
    RuntimeCall::OrinqReceipts(pallet_orinq_receipts::Call::submit_receipt_v2 {
        player_pubkey: [8; 32],
        player_sig: [9; 64],
        sig_type: 0,
        receipt_id: id,
        content_hash: H256::repeat_byte(66),
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

/// Runs a signed call through block admission, ChargeMotra and dispatch;
/// returns the MOTRA its signer paid and the block weight it consumed.
fn apply_signed(who: &AccountId, call: &RuntimeCall) -> (u128, Weight) {
    use frame_support::dispatch::DispatchClass;
    use parity_scale_codec::Encode;
    let info = call.get_dispatch_info();
    let len = call.encoded_size() + 128;
    let consumed = || {
        let weight = System::block_weight();
        weight
            .get(DispatchClass::Normal)
            .saturating_add(*weight.get(DispatchClass::Operational))
    };
    let (balance, before) = (Motra::motra_balance(who), consumed());
    assert_ok!(validity(who, call));
    assert_ok!(frame_system::CheckWeight::<Runtime>::do_pre_dispatch(
        &info, len
    ));
    let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
        .pre_dispatch(who, call, &info, len)
        .expect("admitted");
    let post = call
        .clone()
        .dispatch(RuntimeOrigin::signed(who.clone()))
        .expect("dispatch");
    assert_ok!(frame_system::CheckWeight::<Runtime>::post_dispatch(
        None,
        &info,
        &post,
        len,
        &Ok(())
    ));
    assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
        Some(pre),
        &info,
        &post,
        len,
        &Ok(())
    ));
    (
        balance - Motra::motra_balance(who),
        consumed().saturating_sub(before),
    )
}

#[test]
fn certification_receipt_fee_covers_its_committee_attestations() {
    use parity_scale_codec::Encode;
    for (committee, threshold) in [(1u32, 1u32), (3, 2), (5, 3), (96, 96)] {
        for path in ["v1", "v2", "batch", "derivative"] {
            externalities().execute_with(|| {
                receipt(committee, threshold, 1_000_000);
                pricing_params(1_000_000_000);
                let submitter = account(200);
                pallet_motra::MotraBalances::<Runtime>::insert(&submitter, u128::MAX / 4);
                let id = H256::repeat_byte(9);
                let call = match path {
                    "v1" => submit(id),
                    "v2" => submit_v2(id),
                    "batch" => utility(pallet_utility::Call::batch { calls: vec![submit(id)] }),
                    _ => utility(pallet_utility::Call::as_derivative {
                        index: 0,
                        call: Box::new(submit(id)),
                    }),
                };
                // A derived account submits and escrows the MATRA fee itself.
                fund(
                    &pallet_utility::Pallet::<Runtime>::derivative_account_id(submitter.clone(), 0),
                    1_000_000_000_000,
                );
                let (fee, submission) = apply_signed(&submitter, &call);
                let hash = OrinqReceipts::canonical_cert_hash(id)
                    .expect("submitted")
                    .0;
                let mut certification = Weight::zero();
                for member in 1..=threshold {
                    let (paid, consumed) = apply_signed(&account(member as u8), &attest(id, hash));
                    assert_eq!(paid, 0, "attestation is a feeless duty");
                    certification = certification.saturating_add(consumed);
                }
                assert_ne!(
                    pallet_orinq_receipts::Receipts::<Runtime>::get(id)
                        .expect("receipt")
                        .availability_cert_hash,
                    [0; 32],
                    "certified"
                );
                let params = Motra::params();
                let floor = params.min_fee
                    + params.length_fee_per_byte * (call.encoded_size() + 128) as u128
                    + params.congestion_rate
                        * u128::from(submission.saturating_add(certification).ref_time())
                        / 1_000_000;
                assert!(
                    fee >= floor,
                    "{path} t={threshold}/{committee}: fee {fee} < {floor} for submission {submission:?} and certification {certification:?}"
                );
            });
        }
    }
}

#[test]
fn duty_wrapped_attests_stay_on_the_paid_path() {
    use parity_scale_codec::Encode;
    use sp_runtime::transaction_validity::InvalidTransaction;
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 2, 0);
        pricing_params(1_000_000_000);
        let who = account(1);
        let single = attest(id, hash);
        let wrapped = [
            utility(pallet_utility::Call::batch {
                calls: vec![utility(pallet_utility::Call::batch {
                    calls: vec![single.clone()],
                })],
            }),
            utility(pallet_utility::Call::force_batch {
                calls: vec![single.clone()],
            }),
            utility(pallet_utility::Call::as_derivative {
                index: 0,
                call: Box::new(single.clone()),
            }),
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![account(2)],
                call: Box::new(single.clone()),
            }),
            utility(pallet_utility::Call::batch {
                calls: vec![single.clone(), remark()],
            }),
        ];
        for call in &wrapped {
            assert_eq!(
                validity(&who, call),
                Err(InvalidTransaction::Payment.into()),
                "a wrapped attest must pay: {call:?}"
            );
        }
        pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        for call in &wrapped {
            let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
                .pre_dispatch(
                    &who,
                    call,
                    &call.get_dispatch_info(),
                    call.encoded_size() + 128,
                )
                .expect("paid");
            assert!(
                pre.is_some(),
                "a wrapped attest took the duty path: {call:?}"
            );
        }
    });
}

#[test]
fn duty_priority_outranks_paid_traffic_and_tags_each_signer() {
    use sp_runtime::transaction_validity::TransactionPriority;
    externalities().execute_with(|| {
        let (id, hash) = receipt(3, 3, 0);
        pricing_params(50_000_000_000);
        for who in [account(1), account(2)] {
            pallet_motra::MotraBalances::<Runtime>::insert(&who, 1_000_000_000_000_000_000u128);
        }
        let transfer = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
            dest: account(3).into(),
            value: 1,
        });
        let duty = validity(&account(1), &attest(id, hash)).expect("duty");
        let paid = validity(&account(1), &transfer).expect("paid");
        assert_eq!(duty.priority, TransactionPriority::MAX - 1);
        assert!(duty.priority > paid.priority);
        let second = validity(&account(2), &attest(id, hash)).expect("second member");
        assert_eq!(duty.provides.len(), 1);
        assert_eq!(second.provides.len(), 1);
        assert_ne!(
            duty.provides, second.provides,
            "members attesting one receipt must not collide in the pool"
        );
    });
}

#[test]
fn duty_batch_tolerates_as_many_stale_attests_as_new_ones() {
    use parity_scale_codec::Encode;
    externalities().execute_with(|| {
        let (certified, certified_hash) = receipt(3, 2, 0);
        pricing_params(50_000_000_000);
        let pending = |tag: u8| {
            let id = H256::repeat_byte(tag);
            pallet_orinq_receipts::Receipts::<Runtime>::insert(
                id,
                pallet_orinq_receipts::Receipts::<Runtime>::get(certified).expect("receipt"),
            );
            (id, OrinqReceipts::canonical_cert_hash(id).expect("hash").0)
        };
        let (b, b_hash) = pending(55);
        let (c, c_hash) = pending(56);
        let (d, d_hash) = pending(57);
        assert_ok!(attest(certified, certified_hash).dispatch(RuntimeOrigin::signed(account(1))));
        assert_ok!(attest(certified, certified_hash).dispatch(RuntimeOrigin::signed(account(2))));
        assert_ok!(attest(d, d_hash).dispatch(RuntimeOrigin::signed(account(3))));
        let who = account(3);
        let batch = |calls: Vec<RuntimeCall>| utility(pallet_utility::Call::batch { calls });
        let tag = |id: H256| {
            validity(&who, &attest(id, if id == b { b_hash } else { c_hash }))
                .expect("new duty")
                .provides
        };

        // One certified and one pending: the pending attest stays a duty.
        let mixed = batch(vec![attest(certified, certified_hash), attest(b, b_hash)]);
        let valid = validity(&who, &mixed).expect("stale items do not drop new ones");
        assert_eq!(valid.provides, tag(b));
        // An item this member already signed counts as stale, too.
        let resigned = batch(vec![attest(d, d_hash), attest(c, c_hash)]);
        assert_eq!(
            validity(&who, &resigned)
                .expect("re-signed is stale")
                .provides,
            tag(c)
        );
        // Stale items may not outnumber new ones, or stand alone.
        assert!(validity(&who, &batch(vec![attest(certified, certified_hash)])).is_err());
        assert!(validity(&who, &attest(certified, certified_hash)).is_err());
        assert!(validity(
            &who,
            &batch(vec![
                attest(certified, certified_hash),
                attest(d, d_hash),
                attest(b, b_hash)
            ])
        )
        .is_err());
        // Invalid items still reject the batch.
        for bad in [attest(H256::zero(), b_hash), attest(c, [9; 32])] {
            assert!(validity(&who, &batch(vec![bad, attest(b, b_hash)])).is_err());
        }
        assert!(validity(&account(4), &mixed).is_err(), "non-member");

        // Pre-dispatch admits it for free, and dispatch records the new item.
        let info = mixed.get_dispatch_info();
        let len = mixed.encoded_size() + 128;
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &mixed, &info, len)
            .expect("free batch");
        assert!(pre.is_none());
        assert_ok!(mixed.dispatch(RuntimeOrigin::signed(who.clone())));
        assert!(pallet_orinq_receipts::Attestations::<Runtime>::get(b)
            .expect("attested")
            .1
            .contains(&who));
        assert_eq!(Motra::total_burned(), 0);
    });
}

#[test]
fn pricing_new_signer_after_95_prior_signers_reports_their_count() {
    use pallet_orinq_receipts::weights::WeightInfo;
    use parity_scale_codec::Encode;
    type W = <Runtime as pallet_orinq_receipts::Config>::WeightInfo;
    externalities().execute_with(|| {
        let (id, hash) = receipt(96, 97, 0);
        let signers: BoundedBTreeSet<
            AccountId,
            <Runtime as pallet_orinq_receipts::Config>::MaxCommitteeSize,
        > = (2..=96)
            .map(account)
            .collect::<std::collections::BTreeSet<_>>()
            .try_into()
            .expect("95 signers");
        pallet_orinq_receipts::Attestations::<Runtime>::insert(id, (H256::from(hash), signers));
        let who = account(1);
        let call = attest(id, hash);
        let info = call.get_dispatch_info();
        let len = call.encoded_size() + 128;
        let pre = pallet_motra::fee::ChargeMotra::<Runtime>::new()
            .pre_dispatch(&who, &call, &info, len)
            .expect("duty");
        let post = call
            .dispatch(RuntimeOrigin::signed(who.clone()))
            .expect("96th signer");
        assert_ok!(pallet_motra::fee::ChargeMotra::<Runtime>::post_dispatch(
            Some(pre),
            &info,
            &post,
            len,
            &Ok(())
        ));
        let actual = post.actual_weight.expect("actual");
        assert_eq!(
            actual,
            W::attest_non_threshold(96).saturating_add(W::balance_mutations(0))
        );
        let samples: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../pallets/orinq-receipts/benchmarking/attestation-samples.json"
        ))
        .expect("attestation samples");
        let mut times: Vec<u64> = samples
            .iter()
            .find(|s| s["benchmark"] == "attest_non_threshold")
            .expect("non-threshold samples")["time_results"]
            .as_array()
            .expect("timings")
            .iter()
            .filter(|s| s["components"][0][1].as_u64() == Some(95))
            .map(|s| s["extrinsic_time"].as_u64().expect("time") * 1_000)
            .collect();
        times.sort_unstable();
        assert!(actual.ref_time() >= times[times.len() / 2]);
    });
}
