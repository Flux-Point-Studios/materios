//! Currency paths use Wasm execution maxima and independent storage bounds.

use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn balance_mutations(_accounts: u32) -> Weight {
        Weight::zero()
    }
    fn topup_self() -> Weight;
    fn topup_for() -> Weight;
    fn pay_request() -> Weight;
    fn governance_set_endpoint_price() -> Weight;
    fn governance_set_debits_enabled() -> Weight;
    fn request_withdrawal() -> Weight;
    fn execute_withdrawal() -> Weight;
    fn cancel_withdrawal() -> Weight;
    /// `n` is the number of `(payer, request_id)` tuples passed. Cost scales
    /// linearly.
    fn prune_paid_requests(n: u32) -> Weight;
}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn topup_self() -> Weight {
        Weight::from_parts(55_787_000, 8_623).saturating_add(T::DbWeight::get().reads_writes(3, 3))
    }

    fn topup_for() -> Weight {
        Weight::from_parts(48_853_000, 8_623).saturating_add(T::DbWeight::get().reads_writes(3, 3))
    }

    fn pay_request() -> Weight {
        Weight::from_parts(60_000_000, 8_192)
    }

    fn governance_set_endpoint_price() -> Weight {
        Weight::from_parts(20_000_000, 4_096)
    }

    fn governance_set_debits_enabled() -> Weight {
        Weight::from_parts(20_000_000, 4_096)
    }

    fn request_withdrawal() -> Weight {
        Weight::from_parts(35_000_000, 4_096)
    }

    fn execute_withdrawal() -> Weight {
        Weight::from_parts(75_884_000, 8_627).saturating_add(T::DbWeight::get().reads_writes(3, 3))
    }

    fn cancel_withdrawal() -> Weight {
        Weight::from_parts(25_000_000, 4_096)
    }

    fn prune_paid_requests(n: u32) -> Weight {
        Weight::from_parts(10_000_000, 1_024)
            .saturating_add(Weight::from_parts(5_000_000, 256).saturating_mul(n as u64))
    }
}

impl WeightInfo for () {
    fn topup_self() -> Weight {
        Weight::zero()
    }
    fn topup_for() -> Weight {
        Weight::zero()
    }
    fn pay_request() -> Weight {
        Weight::zero()
    }
    fn governance_set_endpoint_price() -> Weight {
        Weight::zero()
    }
    fn governance_set_debits_enabled() -> Weight {
        Weight::zero()
    }
    fn request_withdrawal() -> Weight {
        Weight::zero()
    }
    fn execute_withdrawal() -> Weight {
        Weight::zero()
    }
    fn cancel_withdrawal() -> Weight {
        Weight::zero()
    }
    fn prune_paid_requests(_n: u32) -> Weight {
        Weight::zero()
    }
}
