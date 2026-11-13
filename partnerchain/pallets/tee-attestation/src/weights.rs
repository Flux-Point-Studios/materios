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
//! `e6b570aa1527612b23b61f0d104dcc82ed69c2bc8336786ff0fd389f4f800de1`.
//!
//! | chain | median | p90 | max |
//! |---|---:|---:|---:|
//! | Seeker RKP (2 RSA, 2 P-384, 1 P-256 signatures) | 20.1 ms | 21.6 ms | 23.1 ms |
//! | Google RSA root certificate × 5 | 17.2 ms | 18.5 ms | 19.6 ms |
//! | Google P-384 root certificate × 5 | 49.7 ms | 56.4 ms | 63.5 ms |
//!
//! Every run recorded 5 reads, no writes and a 711-byte proof.

use frame_support::{traits::Get, weights::Weight};

/// `submit_evidence`: the slowest sample, five P-384 signature checks; a
/// proof covering the measured 711 bytes with the receipt committee grown
/// to its 96-member bound (95 × 32 bytes more); the five measured reads and
/// an accepted entry's two writes (`VerifiedEntries`,
/// `CompositeTrustScores`).
pub fn submit_evidence<T: frame_system::Config>() -> Weight {
    Weight::from_parts(64_000_000_000, 4_096).saturating_add(T::DbWeight::get().reads_writes(5, 2))
}
