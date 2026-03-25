use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::Perbill;

/// Configuration parameters for the MOTRA system.
/// Governed via `set_params` (root-only for MVP).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MotraParams {
    /// Minimum fee per transaction (base fee floor).
    pub min_fee: u128,
    /// Current congestion multiplier (updated each block).
    /// TxFee = min_fee + congestion_rate * tx_weight
    pub congestion_rate: u128,
    /// Target block fullness (default 50%). Congestion rate rises above this, falls below.
    pub target_fullness: Perbill,
    /// Decay factor per block, expressed as Perbill of remaining balance.
    /// e.g., Perbill(999_900_000) means 99.99% retained per block => 0.01% decay per block
    pub decay_rate_per_block: Perbill,
    /// MOTRA generated per MATRA unit per block (in MOTRA smallest units).
    /// e.g., if 1 MATRA = 10^12 units and generation = 1000, then holding 1 MATRA
    /// generates 1000 MOTRA-units per block.
    pub generation_per_matra_per_block: u128,
    /// Maximum MOTRA any account can accumulate (prevents infinite hoarding).
    pub max_balance: u128,
    /// Maximum step size for congestion_rate adjustment per block.
    pub max_congestion_step: u128,
    /// Fee per byte of encoded extrinsic length.
    /// Prevents spam of large extrinsics that are cheap by weight but expensive by bandwidth.
    pub length_fee_per_byte: u128,
    /// Smoothing factor for congestion rate update (as Perbill).
    /// new_rate = (1 - smoothing) * old_rate + smoothing * target_rate
    /// Higher values = faster response, lower = more stable.
    /// Default: 10% = Perbill::from_percent(10)
    pub congestion_smoothing: Perbill,
}

impl Default for MotraParams {
    fn default() -> Self {
        Self {
            min_fee: 1_000_000,                                     // 1M smallest units
            congestion_rate: 0,                                     // starts at zero congestion
            target_fullness: Perbill::from_percent(50),
            decay_rate_per_block: Perbill::from_parts(999_900_000), // retain 99.99% per block
            generation_per_matra_per_block: 100,                    // 100 MOTRA-units per MATRA-unit per block
            max_balance: 1_000_000_000_000_000,                     // 1 quadrillion cap
            max_congestion_step: 1_000_000,                         // max adjustment step
            length_fee_per_byte: 1_000,                             // 1000 MOTRA-units per byte
            congestion_smoothing: Perbill::from_percent(10),        // 10% EMA smoothing
        }
    }
}
