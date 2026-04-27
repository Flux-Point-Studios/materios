#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::Perbill;

/// MOTRA system parameters (mirrors pallet_motra::types::MotraParams).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MotraParams {
    pub min_fee: u128,
    pub congestion_rate: u128,
    pub target_fullness: Perbill,
    pub decay_rate_per_block: Perbill,
    pub generation_per_matra_per_block: u128,
    pub max_balance: u128,
    pub max_congestion_step: u128,
    pub length_fee_per_byte: u128,
    pub congestion_smoothing: Perbill,
}

/// MOTRA account info returned via RPC.
#[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MotraAccountInfo {
    pub balance: u128,
    pub last_touched_block: u64,
    pub delegatee: Option<Vec<u8>>, // encoded AccountId
}

sp_api::decl_runtime_apis! {
    /// Runtime API for querying MOTRA state.
    pub trait MotraApi {
        /// Get MOTRA balance for an account (after lazy reconciliation).
        fn motra_balance(account: sp_core::crypto::AccountId32) -> u128;

        /// Get current MOTRA parameters.
        fn motra_params() -> MotraParams;

        /// Estimate fee for a given weight (ref_time in picoseconds).
        fn estimate_fee(weight_ref_time: u64) -> u128;

        /// Get total MOTRA issued.
        fn total_motra_issued() -> u128;

        /// Get total MOTRA burned as fees (cumulative).
        fn total_motra_burned() -> u128;

        /// Get count of transactions that failed due to insufficient MOTRA.
        fn insufficient_motra_failures() -> u64;
    }
}
