use frame_support::weights::Weight;

pub trait WeightInfo {
    fn checkpoint() -> Weight;
    fn reconcile() -> Weight;
    fn fee_path() -> Weight;
    fn set_delegatee() -> Weight;
    fn set_params() -> Weight;
    fn claim_motra() -> Weight;
}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn checkpoint() -> Weight {
        crate::checkpoint_weights::checkpoint::<T>()
    }

    fn reconcile() -> Weight {
        crate::reconciliation_weights::reconcile::<T>()
            .max(crate::reconciliation_weights::reconcile_100k::<T>())
            .max(crate::reconciliation_weights::reconcile_million::<T>())
            .max(crate::reconciliation_weights::reconcile_legacy::<T>())
    }

    fn fee_path() -> Weight {
        crate::reconciliation_weights::fee_path::<T>()
    }

    fn set_delegatee() -> Weight {
        crate::reconciliation_weights::set_delegatee::<T>()
    }
    fn set_params() -> Weight {
        Weight::from_parts(15_000_000, 0)
    }
    fn claim_motra() -> Weight {
        crate::reconciliation_weights::claim_motra::<T>()
    }
}
