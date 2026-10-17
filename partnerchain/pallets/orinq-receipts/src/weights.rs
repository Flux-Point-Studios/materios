use frame_support::weights::Weight;

pub trait WeightInfo {
    fn submit_receipt() -> Weight;
    fn set_availability_cert() -> Weight;
    /// Additional account-store work for each potential balance mutation.
    fn balance_mutations(_accounts: u32) -> Weight {
        Weight::zero()
    }
}

/// Substrate reference weights -- replace with benchmarked values.
pub struct SubstrateWeight;
impl WeightInfo for SubstrateWeight {
    fn submit_receipt() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }
    fn set_availability_cert() -> Weight {
        Weight::from_parts(25_000_000, 0)
    }
}
