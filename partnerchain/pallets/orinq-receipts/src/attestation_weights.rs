//! Generated from FRAME Wasm samples; see docs/motra-checkpoint-weights.md.
//! Independent StorageInfo proof bounds exclude the separately charged MOTRA checkpoints.

use frame_support::{traits::Get, weights::Weight};

pub fn attest_non_threshold<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 20_083;

    Weight::from_parts(80_001_000, proof)
        .saturating_add(Weight::from_parts(733_600, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
pub fn attest_repeated<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 20_083;

    Weight::from_parts(56_690_480, proof)
        .saturating_add(Weight::from_parts(62_920, 0).saturating_mul(n.into()))
        .saturating_add(T::DbWeight::get().reads(5))
        .saturating_add(T::DbWeight::get().writes(1))
}
pub fn attest_threshold<T: frame_system::Config>(n: u32) -> Weight {
    let proof = 43_329_u64.saturating_add(7_122_u64.saturating_mul(n.into()));

    Weight::from_parts(759_625_753, proof)
        .saturating_add(Weight::from_parts(50_096_257, 0).saturating_mul(n.into()))
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

    Weight::from_parts(723_495_090, proof)
        .saturating_add(Weight::from_parts(51_161_110, 0).saturating_mul(n.into()))
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

    Weight::from_parts(130_267_000, proof)
        .saturating_add(T::DbWeight::get().reads(10))
        .saturating_add(T::DbWeight::get().writes(7))
}
