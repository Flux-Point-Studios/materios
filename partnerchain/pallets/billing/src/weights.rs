//! Hand-tuned weights for `pallet-billing`.

use frame_support::weights::Weight;

pub trait WeightInfo {
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

pub struct SubstrateWeight;

impl WeightInfo for SubstrateWeight {
    fn topup_self() -> Weight {
        Weight::from_parts(40_000_000, 4_096)
    }

    fn topup_for() -> Weight {
        Weight::from_parts(45_000_000, 4_096)
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
        Weight::from_parts(50_000_000, 4_096)
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
