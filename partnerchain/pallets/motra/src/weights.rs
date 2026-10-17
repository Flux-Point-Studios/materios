use frame_support::weights::Weight;

pub trait WeightInfo {
    fn checkpoint() -> Weight;
    fn initialize_delegatee_clock() -> Weight;
    fn set_delegatee() -> Weight;
    fn set_params() -> Weight;
    fn claim_motra() -> Weight;
}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn checkpoint() -> Weight {
        crate::checkpoint_weights::checkpoint::<T>()
    }

    fn initialize_delegatee_clock() -> Weight {
        crate::delegatee_clock_weights::initialize_delegatee_clock::<T>()
    }

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
