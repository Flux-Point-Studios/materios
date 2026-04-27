use frame_support::weights::Weight;

pub trait WeightInfo {
    fn set_delegatee() -> Weight;
    fn set_params() -> Weight;
    fn claim_motra() -> Weight;
}

/// Substrate reference weights -- replace with benchmarked values.
pub struct SubstrateWeight;
impl WeightInfo for SubstrateWeight {
    fn set_delegatee() -> Weight {
        Weight::from_parts(30_000_000, 0)
    }
    fn set_params() -> Weight {
        Weight::from_parts(15_000_000, 0)
    }
    fn claim_motra() -> Weight {
        Weight::from_parts(40_000_000, 0)
    }
}
