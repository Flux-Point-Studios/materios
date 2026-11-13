//! Weights measured in Wasm with `frame-omni-bencher`.
//!
//! `submit_evidence` samples (`benchmarking/submit-evidence-samples.json`):
//! three runs of
//!
//! ```sh
//! cargo build -p materios-runtime --features runtime-benchmarks --locked
//! frame-omni-bencher v1 benchmark pallet --runtime <measurement.wasm> \
//!   --pallet pallet_tee_attestation --extrinsic submit_evidence \
//!   --steps 3 --repeat 20 --external-repeat 3 --output-analysis max \
//!   --map-size 1000000 --additional-trie-layers 2 \
//!   --genesis-builder runtime --genesis-builder-preset development \
//!   --json-file <run.json>
//! ```
//!
//! on Gemtek (Ryzen 7 7730U, Rust 1.85.0, SDK c455194a), each started at the
//! CPU's idle temperature (65 °C). Measurement Wasm SHA-256
//! `cac46da477484d7ae4eee858df0a3264c9f466705f54152411bf93b0053655f2`.
//!
//! | chain | median | p90 | max |
//! |---|---:|---:|---:|
//! | Seeker RKP (2 RSA, 2 P-384, 1 P-256 signatures) | 20.5 ms | 24.7 ms | 29.8 ms |
//! | Google RSA root certificate × 5 | 17.9 ms | 22.8 ms | 28.1 ms |
//! | Google P-384 root certificate × 5 | 48.0 ms | 57.0 ms | 66.7 ms |
//!
//! Runs recorded at most 10 reads (the five of authorization, binding and
//! the receipt's entries, the block time, and a revocation lookup for each
//! of the four certificates above the leaf), no writes and a 715-byte
//! proof.

use frame_support::{traits::Get, weights::Weight};

/// `submit_evidence`: the slowest sample, five P-384 signature checks; a
/// proof covering the measured 715 bytes with the receipt committee grown
/// to its 96-member bound (95 × 32 bytes more); the ten measured reads and
/// an accepted entry's two writes (`VerifiedEntries`,
/// `CompositeTrustScores`).
pub fn submit_evidence<T: frame_system::Config>() -> Weight {
    Weight::from_parts(67_000_000_000, 4_096).saturating_add(T::DbWeight::get().reads_writes(10, 2))
}
