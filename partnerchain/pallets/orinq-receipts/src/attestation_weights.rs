//! Generated from FRAME Wasm samples; see docs/motra-checkpoint-weights.md.
//! Independent StorageInfo proof bounds exclude the separately charged MOTRA checkpoints.

use frame_support::{traits::Get, weights::Weight};

pub fn attest_non_threshold<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 20_083;

    Weight::from_parts(73_700_018, proof)
        .saturating_add(Weight::from_parts(341_416, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
pub fn attest_repeated<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 20_083;

    Weight::from_parts(63_313_184, proof)
        .saturating_add(Weight::from_parts(161_321, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
pub fn attest_threshold<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 43_329_u64.saturating_add(7_122_u64.saturating_mul(n.into()));

    Weight::from_parts(320_801_977, proof)
        .saturating_add(Weight::from_parts(49_206_763, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(15))
        .saturating_add(T::DbWeight::get().reads(3_u64.saturating_mul(n.into())))
        .saturating_add(T::DbWeight::get().writes(10))
        .saturating_add(T::DbWeight::get().writes(3_u64.saturating_mul(n.into())))
        // The samples hold the checkpoint of each signer and of the treasury
        // or refunded submitter, which `balance_mutations` charges.
        .saturating_sub(T::DbWeight::get().reads_writes(1 + u64::from(n), 1 + u64::from(n)))
}
pub fn attest_dead_treasury<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 43_329_u64.saturating_add(7_122_u64.saturating_mul(n.into()));

    Weight::from_parts(948_930_136, proof)
        .saturating_add(Weight::from_parts(53_604_824, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(15))
        .saturating_add(T::DbWeight::get().reads(3_u64.saturating_mul(n.into())))
        .saturating_add(T::DbWeight::get().writes(10))
        .saturating_add(T::DbWeight::get().writes(3_u64.saturating_mul(n.into())))
        // The samples hold the checkpoint of each signer and of the treasury
        // or refunded submitter, which `balance_mutations` charges.
        .saturating_sub(T::DbWeight::get().reads_writes(1 + u64::from(n), 1 + u64::from(n)))
}
pub fn attest_bad_hash<T: frame_system::Config>() -> Weight {
    let proof = 29_185;

    Weight::from_parts(132_031_000, proof)
        .saturating_add(T::DbWeight::get().reads(10))
        .saturating_add(T::DbWeight::get().writes(7))
}
pub fn attest_departed<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 20_083;

    Weight::from_parts(77_698_000, proof)
        .saturating_add(Weight::from_parts(207_500, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
