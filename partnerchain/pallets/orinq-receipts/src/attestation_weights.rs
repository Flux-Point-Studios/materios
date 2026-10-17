//! Generated from FRAME Wasm samples; see docs/motra-checkpoint-weights.md.
//! Independent StorageInfo proof bounds exclude the separately charged MOTRA checkpoints.

use frame_support::{traits::Get, weights::Weight};

pub fn attest_non_threshold<T: frame_system::Config>() -> Weight {
    let proof = 20_083;

    Weight::from_parts(48_973_000, proof)
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
pub fn attest_threshold<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 43_329_u64.saturating_add(7_122_u64.saturating_mul(n.into()));

    Weight::from_parts(129_230_520, proof)
        .saturating_add(Weight::from_parts(55_051_141, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(14))
        .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(n.into())))
        .saturating_add(T::DbWeight::get().writes(9))
        .saturating_add(T::DbWeight::get().writes(2_u64.saturating_mul(n.into())))
}
pub fn attest_dead_treasury<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 43_329_u64.saturating_add(7_122_u64.saturating_mul(n.into()));

    Weight::from_parts(157_357_000, proof)
        .saturating_add(Weight::from_parts(49_530_379, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(14))
        .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(n.into())))
        .saturating_add(T::DbWeight::get().writes(9))
        .saturating_add(T::DbWeight::get().writes(2_u64.saturating_mul(n.into())))
}
pub fn attest_bad_hash<T: frame_system::Config>() -> Weight {
    let proof = 29_185;

    Weight::from_parts(128_334_000, proof)
        .saturating_add(T::DbWeight::get().reads(10))
        .saturating_add(T::DbWeight::get().writes(7))
}
