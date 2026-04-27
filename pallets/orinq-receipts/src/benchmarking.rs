#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use sp_core::H256;

#[benchmarks(
    where
        T::Moment: Into<u64>,
)]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn submit_receipt() {
        let caller: T::AccountId = whitelisted_caller();
        let receipt_id = H256::from([0xAA; 32]);
        let content_hash = H256::from([0xBB; 32]);

        #[extrinsic_call]
        submit_receipt(
            RawOrigin::Signed(caller),
            receipt_id,
            content_hash,
            [1u8; 32],  // base_root_sha256
            None,        // zk_root_poseidon
            None,        // poseidon_params_hash
            [2u8; 32],  // base_manifest_hash
            [3u8; 32],  // safety_manifest_hash
            [4u8; 32],  // monitor_config_hash
            [5u8; 32],  // attestation_evidence_hash
            [6u8; 32],  // storage_locator_hash
            [7u8; 32],  // schema_hash
        );

        assert!(Receipts::<T>::contains_key(receipt_id));
    }

    #[benchmark]
    fn set_availability_cert() {
        // Setup: submit a receipt first so there is something to certify.
        let caller: T::AccountId = whitelisted_caller();
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
