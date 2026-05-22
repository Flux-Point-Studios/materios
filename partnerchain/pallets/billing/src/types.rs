//! Public types for `pallet-billing`.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// How an endpoint's price is computed at gateway charge time.
#[derive(
    Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub enum PricingModel {
    /// Flat MATRA charge per request, regardless of payload size.
    PerCall(u128),

    /// MATRA charge proportional to the request's byte length.
    PerByte { unit_price: u128 },
}

impl PricingModel {
    /// A never-configured endpoint is free until governance sets a price.
    pub const FREE: Self = Self::PerCall(0);

    /// Compute the charge for a request. `request_bytes` is ignored by `PerCall`.
    pub fn compute(&self, request_bytes: u64) -> u128 {
        match self {
            Self::PerCall(price) => *price,
            Self::PerByte { unit_price } => unit_price.saturating_mul(request_bytes as u128),
        }
    }
}

impl Default for PricingModel {
    fn default() -> Self {
        Self::FREE
    }
}

/// Maximum byte length of an endpoint class string.
pub const MAX_ENDPOINT_CLASS_LEN: u32 = 64;

/// Blocks a withdrawal must wait between request and execution (~5 min at
/// 6s block time).
pub const WITHDRAWAL_COOLDOWN_BLOCKS: u32 = 50;
