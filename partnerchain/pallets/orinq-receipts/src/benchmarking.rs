#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_core::H256;

#[benchmarks(
    where
        T::Moment: Into<u64>,
        T: pallet_balances::Config<Balance = u128>,
        T::Currency: frame_support::traits::Currency<T::AccountId, Balance = u128>,
)]
mod benchmarks {
    use super::*;
    use frame_support::{
        traits::{Currency, Get, ReservableCurrency},
        BoundedBTreeSet,
    };

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
    fn attest_non_threshold() {
        let (caller, id, hash) = attestation::<T>(0, true);
        #[extrinsic_call]
        attest_availability_cert(RawOrigin::Signed(caller), id, hash);
        assert_eq!(
            Receipts::<T>::get(id)
                .expect("receipt")
                .availability_cert_hash,
            [0; 32]
        );
    }

    #[benchmark]
    fn attest_threshold(n: Linear<1, { T::MaxCommitteeSize::get() }>) {
        let (caller, id, hash) = attestation::<T>(n, true);
        #[extrinsic_call]
        attest_availability_cert(RawOrigin::Signed(caller), id, hash);
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
        #[extrinsic_call]
        attest_availability_cert(RawOrigin::Signed(caller), id, hash);
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
    fn submit_receipt() {
        let caller: T::AccountId = whitelisted_caller();
        let _ = T::Currency::deposit_creating(&caller, 1_000_000_000_000);
        let receipt_id = H256::from([0xAA; 32]);
        let content_hash = H256::from([0xBB; 32]);

        #[extrinsic_call]
        submit_receipt(
            RawOrigin::Signed(caller),
            receipt_id,
            content_hash,
            [1u8; 32], // base_root_sha256
            None,      // zk_root_poseidon
            None,      // poseidon_params_hash
            [2u8; 32], // base_manifest_hash
            [3u8; 32], // safety_manifest_hash
            [4u8; 32], // monitor_config_hash
            [5u8; 32], // attestation_evidence_hash
            [6u8; 32], // storage_locator_hash
            [7u8; 32], // schema_hash
        );

        assert!(Receipts::<T>::contains_key(receipt_id));
    }

    #[benchmark]
    fn set_availability_cert() {
        // Setup: submit a receipt first so there is something to certify.
        let caller: T::AccountId = whitelisted_caller();
        let _ = T::Currency::deposit_creating(&caller, 1_000_000_000_000);
        let receipt_id = H256::from([0xCC; 32]);
        let content_hash = H256::from([0xDD; 32]);

        Pallet::<T>::submit_receipt(
            RawOrigin::Signed(caller).into(),
            receipt_id,
            content_hash,
            [1u8; 32],
            None,
            None,
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            [7u8; 32],
        )
        .expect("setup: submit_receipt should succeed");

        let cert_hash = [0xFF; 32];

        #[extrinsic_call]
        set_availability_cert(RawOrigin::Root, receipt_id, cert_hash);

        let record = Receipts::<T>::get(receipt_id).expect("receipt should exist");
        assert_eq!(record.availability_cert_hash, cert_hash);
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
