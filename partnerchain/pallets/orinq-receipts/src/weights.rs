use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn attest_non_threshold(n: u32) -> Weight;
    fn attest_threshold(n: u32) -> Weight;
    fn attest_bad_hash() -> Weight;
    fn submit_receipt() -> Weight;
    fn set_availability_cert() -> Weight;
    fn bond() -> Weight;
    fn unbond() -> Weight;
    fn slash_attestor() -> Weight;
    fn expire_receipt_fee() -> Weight;
    /// Additional account-store work for each potential balance mutation.
    fn balance_mutations(_accounts: u32) -> Weight {
        Weight::zero()
    }
}

/// Measured execution and independent storage bounds; see benchmarking samples.
pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn attest_non_threshold(n: u32) -> Weight {
        crate::attestation_weights::attest_non_threshold::<T>(n)
            .max(crate::attestation_weights::attest_repeated::<T>(n))
    }
    fn attest_threshold(n: u32) -> Weight {
        crate::attestation_weights::attest_threshold::<T>(n)
            .max(crate::attestation_weights::attest_dead_treasury::<T>(n))
    }
    fn attest_bad_hash() -> Weight {
        crate::attestation_weights::attest_bad_hash::<T>()
    }
    fn submit_receipt() -> Weight {
        Weight::from_parts(101_874_000, 28_238)
            .saturating_add(T::DbWeight::get().reads_writes(6, 7))
    }
    fn set_availability_cert() -> Weight {
        Weight::from_parts(67_549_000, 14_578).saturating_add(T::DbWeight::get().reads_writes(3, 4))
    }
    fn bond() -> Weight {
        Weight::from_parts(53_642_000, 7_122).saturating_add(T::DbWeight::get().reads_writes(2, 2))
    }
    fn unbond() -> Weight {
        Weight::from_parts(81_425_000, 11_681).saturating_add(T::DbWeight::get().reads_writes(3, 2))
    }
    fn slash_attestor() -> Weight {
        Weight::from_parts(110_751_000, 18_264)
            .saturating_add(T::DbWeight::get().reads_writes(6, 5))
    }
    fn expire_receipt_fee() -> Weight {
        Weight::from_parts(70_634_000, 16_067).saturating_add(T::DbWeight::get().reads_writes(5, 3))
    }
}
