#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_core::H256;

#[benchmarks(
    where
        T::Moment: Into<u64>,
        T: pallet_balances::Config<Balance = u128> + pallet_motra::Config + Send + Sync,
        T::Currency: frame_support::traits::Currency<T::AccountId, Balance = u128>,
        <T as frame_system::Config>::RuntimeCall: From<Call<T>>
            + frame_support::dispatch::GetDispatchInfo
            + sp_runtime::traits::Dispatchable<Info = frame_support::dispatch::DispatchInfo,
                PostInfo = frame_support::dispatch::PostDispatchInfo>,
)]
mod benchmarks {
    use super::*;
    use alloc::collections::BTreeSet;
    use frame_support::{
        dispatch::{DispatchInfo, GetDispatchInfo, PostDispatchInfo},
        traits::{Currency, Get, ReservableCurrency, UnfilteredDispatchable},
        BoundedBTreeSet,
    };
    use sp_runtime::traits::{Dispatchable, SignedExtension};

    fn dispatch_duty<T>(caller: T::AccountId, id: H256, hash: [u8; 32])
    where
        T: Config + pallet_motra::Config + Send + Sync,
        T::Moment: Into<u64>,
        <T as frame_system::Config>::RuntimeCall: From<Call<T>>
            + GetDispatchInfo
            + Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    {
        let call: <T as frame_system::Config>::RuntimeCall = Call::<T>::attest_availability_cert {
            receipt_id: id,
            claimed_hash: hash,
        }
        .into();
        let info = call.get_dispatch_info();
        let pre = pallet_motra::fee::ChargeMotra::<T>::new()
            .pre_dispatch(&caller, &call, &info, 169)
            .expect("duty validation");
        assert!(
            pre.is_none(),
            "benchmark must execute the feeless duty path"
        );
        let post = call
            .dispatch(RawOrigin::Signed(caller).into())
            .expect("attest");
        pallet_motra::fee::ChargeMotra::<T>::post_dispatch(Some(pre), &info, &post, 169, &Ok(()))
            .expect("release unused fee work");
    }

    fn attestation<T>(n: u32, treasury_alive: bool) -> (T::AccountId, H256, [u8; 32])
    where
        T: Config + pallet_balances::Config<Balance = u128>,
        T::Moment: Into<u64>,
        T::Currency: Currency<T::AccountId, Balance = u128>,
    {
        let submitter: T::AccountId = account("submitter", 0, 0);
        let _ = T::Currency::deposit_creating(&submitter, 1_000_000_000_000);
        let mut members = BoundedBTreeSet::new();
        let mut signers = BoundedBTreeSet::<T::AccountId, T::MaxCommitteeSize>::new();
        let caller: T::AccountId = account("attester", n.max(1) - 1, 0);
        for i in 0..T::MaxCommitteeSize::get() {
            let who: T::AccountId = account("attester", i, 0);
            let _ = T::Currency::deposit_creating(&who, 1_000_000);
            members.try_insert(who.clone()).expect("member bound");
            if i + 1 < n {
                signers.try_insert(who).expect("signer bound");
            }
        }
        CommitteeMembers::<T>::put(members);
        AttestationThreshold::<T>::put(if n == 0 {
            T::MaxCommitteeSize::get()
        } else {
            n
        });
        ReceiptSubmissionFee::<T>::put(1_000_000);
        ReceiptSubmissionFeeFloor::<T>::put(0);
        AttestationRewardPerSigner::<T>::put(10_000);
        EraCapBase::<T>::put(1_000_000_000);
        EraCapBaselineAttestorCount::<T>::put(1);
        if treasury_alive {
            let _ = T::Currency::deposit_creating(&Pallet::<T>::treasury_account(), 1_000_000);
        }
        let id = H256::repeat_byte(77);
        Pallet::<T>::submit_receipt(
            RawOrigin::Signed(submitter).into(),
            id,
            H256::repeat_byte(78),
            [1; 32],
            None,
            None,
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
        )
        .expect("receipt");
        let hash = Pallet::<T>::canonical_cert_hash(id).expect("canonical hash");
        if n > 1 {
            Attestations::<T>::insert(id, (hash, signers));
        }
        (caller, id, hash.0)
    }

    #[benchmark]
    fn attest_non_threshold(n: Linear<0, { T::MaxCommitteeSize::get() - 1 }>) {
        let (caller, id, hash) = attestation::<T>(n + 1, true);
        AttestationThreshold::<T>::put(T::MaxCommitteeSize::get() + 1);
        #[block]
        {
            dispatch_duty::<T>(caller, id, hash);
        }
        assert_eq!(
            Receipts::<T>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            [0; 32]
        );
    }

    #[benchmark]
    fn attest_repeated(n: Linear<1, { T::MaxCommitteeSize::get() }>) {
        let (_, id, hash) = attestation::<T>(n, true);
        let caller: T::AccountId = account("attester", 0, 0);
        let signers: BoundedBTreeSet<T::AccountId, T::MaxCommitteeSize> = (0..n)
            .map(|i| account("attester", i, 0))
            .collect::<BTreeSet<_>>()
            .try_into()
            .expect("signers");
        Attestations::<T>::insert(id, (H256::from(hash), signers));
        AttestationThreshold::<T>::put(T::MaxCommitteeSize::get() + 1);
        #[extrinsic_call]
        attest_availability_cert(RawOrigin::Signed(caller), id, hash);
        assert_eq!(
            Attestations::<T>::get(id).expect("attestations").1.len(),
            n as usize
        );
    }

    #[benchmark]
    fn attest_threshold(n: Linear<1, { T::MaxCommitteeSize::get() }>) {
        let (caller, id, hash) = attestation::<T>(n, true);
        #[block]
        {
            dispatch_duty::<T>(caller, id, hash);
        }
        assert_eq!(
            Receipts::<T>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            hash
        );
    }

    #[benchmark]
    fn attest_dead_treasury(n: Linear<1, { T::MaxCommitteeSize::get() }>) {
        let (caller, id, hash) = attestation::<T>(n, false);
        #[block]
        {
            dispatch_duty::<T>(caller, id, hash);
        }
        assert_eq!(
            Receipts::<T>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            hash
        );
    }

    #[benchmark]
    fn attest_bad_hash() {
        let (caller, id, _) = attestation::<T>(0, true);
        let _ = T::Currency::deposit_creating(&Pallet::<T>::attestor_reserve_account(), 1_000_000);
        T::Currency::reserve(&caller, 10_000).expect("bond");
        AttestorBonds::<T>::insert(&caller, 10_000);
        BadAttestSlashThreshold::<T>::put(1);
        #[extrinsic_call]
        attest_availability_cert(RawOrigin::Signed(caller.clone()), id, [99; 32]);
        assert!(!CommitteeMembers::<T>::get().contains(&caller));
    }

    #[benchmark]
    fn attest_departed(n: Linear<1, { T::MaxCommitteeSize::get() }>) {
        let (caller, id, hash) = attestation::<T>(1, true);
        let departed: BoundedBTreeSet<T::AccountId, T::MaxCommitteeSize> = (0..n)
            .map(|i| account("departed", i, 0))
            .collect::<BTreeSet<_>>()
            .try_into()
            .expect("departed");
        Attestations::<T>::insert(id, (H256::from(hash), departed));
        AttestationThreshold::<T>::put(T::MaxCommitteeSize::get() + 1);
        #[block]
        {
            dispatch_duty::<T>(caller.clone(), id, hash);
        }
        assert_eq!(
            Attestations::<T>::get(id)
                .expect("attestations")
                .1
                .into_iter()
                .collect::<alloc::vec::Vec<_>>(),
            alloc::vec![caller]
        );
    }

    fn submission<T>(m: u32, v2: bool) -> (T::AccountId, H256, Call<T>)
    where
        T: Config + pallet_balances::Config<Balance = u128>,
        T::Moment: Into<u64>,
        T::Currency: Currency<T::AccountId, Balance = u128>,
    {
        let caller: T::AccountId = account("submitter", 0, 0);
        let _ = T::Currency::deposit_creating(&caller, 1_000_000_000_000);
        frame_system::Pallet::<T>::set_block_number(100u32.into());
        ReceiptSubmissionFee::<T>::put(1_000_000 * u128::from(m));
        ReceiptSubmissionFeeFloor::<T>::put(0);
        let receipt_id = H256::repeat_byte(170);
        let content_hash = H256::repeat_byte(187);
        let ids: frame_support::BoundedVec<_, T::MaxResubmits> = (0..T::MaxResubmits::get()
            .saturating_sub(1))
            .map(|i| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&i.to_le_bytes());
                H256(bytes)
            })
            .collect::<alloc::vec::Vec<_>>()
            .try_into()
            .expect("content bound");
        ContentIndex::<T>::insert(content_hash, ids);
        let call = if v2 {
            Call::submit_receipt_v2 {
                player_pubkey: [8; 32],
                player_sig: [9; 64],
                sig_type: 1,
                receipt_id,
                content_hash,
                base_root_sha256: [1; 32],
                zk_root_poseidon: Some([10; 32]),
                poseidon_params_hash: Some([11; 32]),
                base_manifest_hash: [2; 32],
                safety_manifest_hash: [3; 32],
                monitor_config_hash: [4; 32],
                attestation_evidence_hash: [5; 32],
                storage_locator_hash: [6; 32],
                schema_hash: [7; 32],
            }
        } else {
            Call::submit_receipt {
                receipt_id,
                content_hash,
                base_root_sha256: [1; 32],
                zk_root_poseidon: Some([10; 32]),
                poseidon_params_hash: Some([11; 32]),
                base_manifest_hash: [2; 32],
                safety_manifest_hash: [3; 32],
                monitor_config_hash: [4; 32],
                attestation_evidence_hash: [5; 32],
                storage_locator_hash: [6; 32],
                schema_hash: [7; 32],
            }
        };
        (caller, receipt_id, call)
    }

    #[benchmark]
    fn submit_receipt(m: Linear<0, 1>) {
        let (caller, id, call) = submission::<T>(m, false);
        #[block]
        {
            call.dispatch_bypass_filter(RawOrigin::Signed(caller).into())
                .expect("submission");
        }
        assert!(Receipts::<T>::contains_key(id));
    }

    #[benchmark]
    fn submit_receipt_v2(m: Linear<0, 1>) {
        let (caller, id, call) = submission::<T>(m, true);
        #[block]
        {
            call.dispatch_bypass_filter(RawOrigin::Signed(caller).into())
                .expect("submission");
        }
        assert!(PlayerSignatures::<T>::contains_key(id));
    }

    #[benchmark]
    fn set_availability_cert(m: Linear<0, 1>) {
        let (caller, id, call) = submission::<T>(m, false);
        call.dispatch_bypass_filter(RawOrigin::Signed(caller).into())
            .expect("receipt");
        #[extrinsic_call]
        set_availability_cert(RawOrigin::Root, id, [255; 32]);
        assert_eq!(
            Receipts::<T>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            [255; 32]
        );
    }

    fn bonded<T>(m: u32, member: bool) -> T::AccountId
    where
        T: Config + pallet_balances::Config<Balance = u128>,
        T::Moment: Into<u64>,
        T::Currency: Currency<T::AccountId, Balance = u128>,
    {
        let caller: T::AccountId = account("bonded", 0, 0);
        let _ = T::Currency::deposit_creating(&caller, 1_000_000);
        let _ = T::Currency::deposit_creating(&Pallet::<T>::attestor_reserve_account(), 1_000_000);
        T::Currency::reserve(&caller, 10_000 * u128::from(m)).expect("reserve");
        AttestorBonds::<T>::insert(&caller, 10_000);
        let mut members = BoundedBTreeSet::<T::AccountId, T::MaxCommitteeSize>::new();
        if member {
            members.try_insert(caller.clone()).expect("caller");
        }
        for i in u32::from(member)..T::MaxCommitteeSize::get() {
            members
                .try_insert(account("member", i, 0))
                .expect("member bound");
        }
        CommitteeMembers::<T>::put(members);
        BondRequirement::<T>::put(1);
        AttestationThreshold::<T>::put(T::MaxCommitteeSize::get());
        caller
    }

    #[benchmark]
    fn bond(m: Linear<0, 1>) {
        let caller = bonded::<T>(0, false);
        #[extrinsic_call]
        bond(RawOrigin::Signed(caller.clone()), 10_000 * u128::from(m));
        assert_eq!(
            AttestorBonds::<T>::get(caller),
            10_000 * (1 + u128::from(m))
        );
    }

    #[benchmark]
    fn unbond(m: Linear<0, 1>) {
        let caller = bonded::<T>(m, false);
        #[extrinsic_call]
        unbond(RawOrigin::Signed(caller.clone()));
        assert!(!AttestorBonds::<T>::contains_key(caller));
    }

    #[benchmark]
    fn slash_attestor(m: Linear<0, 1>) {
        let caller = bonded::<T>(m, true);
        AttestorBonds::<T>::insert(&caller, 10_000 * u128::from(m));
        #[extrinsic_call]
        slash_attestor(
            RawOrigin::Root,
            caller.clone(),
            10_000,
            crate::types::SlashReason::InvalidSignature,
        );
        assert!(!CommitteeMembers::<T>::get().contains(&caller));
    }

    #[benchmark]
    fn expire_receipt_fee(m: Linear<0, 1>) {
        let (caller, id, call) = submission::<T>(m, false);
        call.dispatch_bypass_filter(RawOrigin::Signed(caller.clone()).into())
            .expect("receipt");
        ReceiptExpiryBlocks::<T>::put(10);
        frame_system::Pallet::<T>::set_block_number(111u32.into());
        #[extrinsic_call]
        expire_receipt_fee(RawOrigin::Signed(caller), id);
        assert!(!ReceiptFeeEscrow::<T>::contains_key(id));
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
