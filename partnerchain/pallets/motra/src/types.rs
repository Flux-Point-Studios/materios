use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::Perbill;

/// Configuration parameters for the MOTRA system.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MotraParams {
    /// Minimum fee per transaction (base fee floor).
    pub min_fee: u128,
    /// Congestion multiplier in `TxFee = min_fee + congestion_rate * tx_weight`.
    pub congestion_rate: u128,
    /// Target block fullness; congestion rises above it, falls below.
    pub target_fullness: Perbill,
    /// Per-block decay factor as Perbill of remaining balance
    /// (e.g. `999_900_000` keeps 99.99% per block).
    pub decay_rate_per_block: Perbill,
    /// MOTRA generated per MATRA base unit per block. MATRA is 6 decimals,
    /// MOTRA is 15.
    pub generation_per_matra_per_block: u128,
    /// Maximum MOTRA any account can accumulate.
    pub max_balance: u128,
    /// Maximum step size for `congestion_rate` adjustment per block.
    pub max_congestion_step: u128,
    /// Fee per byte of encoded extrinsic length.
    pub length_fee_per_byte: u128,
    /// EMA smoothing for congestion rate updates:
    /// `new_rate = (1 - smoothing) * old + smoothing * target`.
    pub congestion_smoothing: Perbill,
}

impl Default for MotraParams {
    fn default() -> Self {
        Self {
            // 1 µMOTRA floor at 15 decimals.
            min_fee: 1_000_000_000,
            congestion_rate: 0,
            target_fullness: Perbill::from_percent(50),
            // 99.99% retained per block.
            decay_rate_per_block: Perbill::from_parts(999_900_000),
            generation_per_matra_per_block: 100_000,
            // 1,000 MOTRA cap at 15 decimals.
            max_balance: 1_000_000_000_000_000_000,
            max_congestion_step: 1_000_000_000,
            // 1 nano-MOTRA/byte at 15 decimals.
            length_fee_per_byte: 1_000_000,
            congestion_smoothing: Perbill::from_percent(10),
        }
    }
}
