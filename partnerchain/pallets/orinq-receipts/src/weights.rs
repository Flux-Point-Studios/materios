use frame_support::weights::Weight;

pub trait WeightInfo {
    fn attest_non_threshold() -> Weight;
    fn attest_threshold(n: u32) -> Weight;
    fn attest_bad_hash() -> Weight;
    fn submit_receipt() -> Weight;
    fn set_availability_cert() -> Weight;
    /// Additional account-store work for each potential balance mutation.
    fn balance_mutations(_accounts: u32) -> Weight {
        Weight::zero()
    }
}

/// Substrate reference weights -- replace with benchmarked values.
pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn attest_non_threshold() -> Weight {
        crate::attestation_weights::attest_non_threshold::<T>()
    }
    fn attest_threshold(n: u32) -> Weight {
        crate::attestation_weights::attest_threshold::<T>(n)
            .max(crate::attestation_weights::attest_dead_treasury::<T>(n))
    }
    fn attest_bad_hash() -> Weight {
        crate::attestation_weights::attest_bad_hash::<T>()
    }
    fn submit_receipt() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }
    fn set_availability_cert() -> Weight {
        Weight::from_parts(25_000_000, 0)
    }
}
