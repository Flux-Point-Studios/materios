#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export CARGO_TARGET_DIR="$PWD/.zk-spec-target"
export CARGO_HOME="$PWD/.zk-spec-scratch/cargo"
export CARGO_BUILD_JOBS=2
rustup component add --toolchain 1.85.0 clippy
rustup target add --toolchain 1.85.0 wasm32-unknown-unknown
nice -n 10 cargo +1.85.0 build --offline --locked --release --no-default-features --target wasm32-unknown-unknown --manifest-path tools/zk-spec/wasm/Cargo.toml
nice -n 10 cargo +1.85.0 clippy --offline --locked --release --no-default-features --target wasm32-unknown-unknown --manifest-path tools/zk-spec/wasm/Cargo.toml --lib -- -D warnings
python3 tools/zk-spec/vectors.py --check
# CI verifies proofs without timing hardware that hosts live services.
nice -n 10 node tools/zk-spec/wasm-run.mjs .zk-spec-target/wasm32-unknown-unknown/release/materios_zk_wasm.wasm --verify-only > .zk-spec-scratch/ci-wasm-verification.json
