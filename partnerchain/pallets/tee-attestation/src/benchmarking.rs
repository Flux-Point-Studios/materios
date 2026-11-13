//! `submit_evidence` at its most expensive: signed by a committee member who
//! did not submit the receipt, so both authorization reads run, with a chain
//! whose every signature verifies. No chain is bound to the receipt, so each
//! fails after its last signature check, which is where the cost lies.

use super::*;
use crate::types::{EvidenceEntry, EvidenceType, ReceiptId};
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use parity_scale_codec::Encode;
use sp_std::prelude::*;

const GOOGLE_RSA_ROOT: &[u8] = include_bytes!("../benchmarking/google-rsa-root.der");
const GOOGLE_P384_ROOT: &[u8] = include_bytes!("../benchmarking/google-p384-root.der");
const SEEKER_CHAIN: [&[u8]; 5] = [
    GOOGLE_RSA_ROOT,
    include_bytes!("../benchmarking/seeker-droid-ca2.der"),
    include_bytes!("../benchmarking/seeker-droid-ca3.der"),
    include_bytes!("../benchmarking/seeker-rkp.der"),
    include_bytes!("../benchmarking/seeker-leaf.der"),
];

/// Chain shape `c`: 0 the Seeker RKP chain (two RSA, two P-384 and one
/// P-256 signature), 1 Google's RSA root certificate five times, 2 its
/// P-384 root certificate five times. A repeated root verifies against its
/// own key, so each copy costs a full signature check.
fn worst_case_chain(c: u32) -> EvidenceEntry {
    let chain: Vec<Vec<u8>> = match c {
        0 => SEEKER_CHAIN.iter().map(|der| der.to_vec()).collect(),
        1 => vec![GOOGLE_RSA_ROOT.to_vec(); 5],
        _ => vec![GOOGLE_P384_ROOT.to_vec(); 5],
    };
    EvidenceEntry {
        evidence_type: EvidenceType::ArmTrustZone,
        payload: chain
            .encode()
            .try_into()
            .expect("five certificates fit the payload bound"),
    }
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn submit_evidence(c: Linear<0, 2>) {
        let receipt_id = ReceiptId::repeat_byte(0xBE);
        let content_hash = [0xC0; 32];
        let caller: T::AccountId = whitelisted_caller();
        T::Receipts::register_receipt(receipt_id, content_hash, account("submitter", 0, 0));
        T::Receipts::add_committee_member(caller.clone());
        Disabled::<T>::put(false);
        let entry = worst_case_chain(c);

        let outcome;
        #[block]
        {
            outcome = Pallet::<T>::submit_evidence(
                RawOrigin::Signed(caller).into(),
                receipt_id,
                content_hash,
                entry,
            );
        }
        assert_eq!(outcome, Err(Error::<T>::VerificationFailed.into()));
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
