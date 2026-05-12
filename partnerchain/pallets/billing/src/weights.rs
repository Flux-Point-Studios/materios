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
    fn governance_set_debits_enabled() -> Weight;
    fn request_withdrawal() -> Weight;
    fn execute_withdrawal() -> Weight;
    fn cancel_withdrawal() -> Weight;
    /// `n` is the number of `(payer, request_id)` tuples passed in the
    /// `ids: Vec<_>` parameter. Each entry is one StorageDoubleMap read +
    /// up to one remove, so the cost scales linearly.
    fn prune_paid_requests(n: u32) -> Weight;
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
        // read+write (Balances), one StorageDoubleMap read+write
        // (PaidRequests for idempotency), and event emission.
        Weight::from_parts(60_000_000, 8_192)
    }

    fn governance_set_endpoint_price() -> Weight {
        Weight::from_parts(20_000_000, 4_096)
    }

    fn governance_set_debits_enabled() -> Weight {
        // Parity with governance_set_endpoint_price — one StorageValue write
        // plus event emission. Same magnitude of work.
        Weight::from_parts(20_000_000, 4_096)
    }

    fn request_withdrawal() -> Weight {
        Weight::from_parts(35_000_000, 4_096)
    }

    fn execute_withdrawal() -> Weight {
        Weight::from_parts(50_000_000, 4_096)
    }

    fn cancel_withdrawal() -> Weight {
        // Slightly cheaper than request_withdrawal — only one storage take
        // + balance credit, no cooldown bookkeeping or new pending insert.
        Weight::from_parts(25_000_000, 4_096)
    }

    fn prune_paid_requests(n: u32) -> Weight {
        // Base cost (origin check + retention read + block_number read) plus
        // per-entry cost (one DoubleMap read + possible remove).
        Weight::from_parts(10_000_000, 1_024)
            .saturating_add(Weight::from_parts(5_000_000, 256).saturating_mul(n as u64))
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
