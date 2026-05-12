//! Weight placeholder for `pallet-billing`.
//!
//! Phase 2.A ships with conservative hand-tuned weights — proportional to
//! the equivalent extrinsics in `pallet-motra` + a safety margin. Real
//! benchmark-derived weights are a 2.B task (see task #211's pattern of
//! adding benchmarks alongside the runtime upgrade that activates the
//! pallet).

use frame_support::weights::Weight;

pub trait WeightInfo {
    fn topup_self() -> Weight;
    fn topup_for() -> Weight;
    fn pay_request() -> Weight;
    fn governance_set_endpoint_price() -> Weight;
    fn request_withdrawal() -> Weight;
    fn execute_withdrawal() -> Weight;
}

/// Conservative hand-tuned weights for Phase 2.A. Each is ~2x the cost of
/// the equivalent pallet-motra operation, providing safety margin before
/// real benchmarks land in 2.B.
pub struct SubstrateWeight;

impl WeightInfo for SubstrateWeight {
    fn topup_self() -> Weight {
        Weight::from_parts(40_000_000, 4_096)
    }

    fn topup_for() -> Weight {
        Weight::from_parts(45_000_000, 4_096)
    }

    fn pay_request() -> Weight {
        // Includes one StorageMap read (EndpointPrices), one StorageMap
        // read+write (Balances), one StorageMap read+write (PaidRequests for
        // idempotency), and event emission.
        Weight::from_parts(60_000_000, 8_192)
    }

    fn governance_set_endpoint_price() -> Weight {
        Weight::from_parts(20_000_000, 4_096)
    }

    fn request_withdrawal() -> Weight {
        Weight::from_parts(35_000_000, 4_096)
    }

    fn execute_withdrawal() -> Weight {
        Weight::from_parts(50_000_000, 4_096)
    }
}

/// Fallback used by tests + benchmarks.
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
    fn request_withdrawal() -> Weight {
        Weight::zero()
    }
    fn execute_withdrawal() -> Weight {
        Weight::zero()
    }
}
