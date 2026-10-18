//! Generated from FRAME Wasm samples; see docs/motra-checkpoint-weights.md.
//! Execution: median sample, in picoseconds. DB: RocksDB floor.
//! Proof: sum of independent StorageInfo bounds, checked by runtime tests.

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, RuntimeDbWeight, Weight},
};

pub fn set_delegatee<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(198_657_000, proof)
        .saturating_add(db.reads(9))
        .saturating_add(db.writes(7))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
pub fn claim_motra<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(197_014_000, proof)
        .saturating_add(db.reads(9))
        .saturating_add(db.writes(6))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
pub fn reconcile<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(198_197_000, proof)
        .saturating_add(db.reads(9))
        .saturating_add(db.writes(6))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
pub fn reconcile_100k<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(106_833_000, proof)
        .saturating_add(db.reads(9))
        .saturating_add(db.writes(6))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
pub fn reconcile_million<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(112_053_000, proof)
        .saturating_add(db.reads(9))
        .saturating_add(db.writes(6))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
pub fn reconcile_legacy<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 29_346;
    Weight::from_parts(138_794_000, proof)
        .saturating_add(db.reads(10))
        .saturating_add(db.writes(6))
    // The legacy read is already present in these samples.
}
pub fn fee_path<T: frame_system::Config>() -> Weight {
    let configured = T::DbWeight::get();
    let minimum = RocksDbWeight::get();
    let db = RuntimeDbWeight {
        read: configured.read.max(minimum.read),
        write: configured.write.max(minimum.write),
    };
    let proof = 30_847;
    Weight::from_parts(211_852_000, proof)
        .saturating_add(db.reads(10))
        .saturating_add(db.writes(7))
        // A missing holding checkpoint additionally reads the legacy baseline.
        .saturating_add(db.reads(1))
}
