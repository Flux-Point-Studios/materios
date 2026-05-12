//! Public types for `pallet-billing`.
//!
//! Kept in their own module so the runtime + gateway-side TS bindings can
//! import them without pulling in the whole pallet crate's frame-support
//! macros.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// How an endpoint's price is computed at gateway charge time.
///
/// Encoded as a tagged enum so adding new pricing strategies later (e.g.
/// time-based, tiered) does not change the on-wire layout for the existing
/// variants — only adds new tags. Existing storage entries keep their
/// SCALE-decoded shape.
#[derive(
    Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub enum PricingModel {
    /// Flat MATRA charge per request, regardless of payload size.
    /// Use for most endpoints: receipt_submit, anchor_query, manifest_post.
    PerCall(u128),

    /// MATRA charge proportional to the request's byte length.
    /// `unit_price` is MATRA-per-byte; the gateway passes the request's
    /// Content-Length as `request_bytes` when calling `pay_request`.
    /// Use for upload endpoints: chunk_upload.
    PerByte { unit_price: u128 },
}

impl PricingModel {
    /// Default for any endpoint that has not been priced by governance.
    /// Returns zero — a never-configured endpoint is free until governance
    /// explicitly sets a price. This is deliberate: prevents a footgun where
    /// adding a new endpoint silently bills against an unset price.
    pub const FREE: Self = Self::PerCall(0);

    /// Compute the charge for a request given its size in bytes.
    /// `request_bytes` is ignored by `PerCall`.
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

/// Maximum byte length of an endpoint class string (e.g. "receipt_submit").
/// Kept small to bound storage cost per `EndpointPrices` entry.
pub const MAX_ENDPOINT_CLASS_LEN: u32 = 64;

/// Number of blocks a withdrawal must wait between request and execution.
///
/// At ~6s block time this is ~5 minutes. Long enough to prevent
/// front-running a gateway charge that's already in-flight, short enough to
/// not punish legitimate overfunding-then-recovery.
pub const WITHDRAWAL_COOLDOWN_BLOCKS: u32 = 50;
