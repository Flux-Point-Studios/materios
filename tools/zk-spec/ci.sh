#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export CARGO_TARGET_DIR="$PWD/.zk-spec-target"
export CARGO_BUILD_JOBS=2
if ! git cat-file -e '546044815026a643cc95ea9737d6dfd167465e6d^{commit}' 2>/dev/null; then
  git fetch --no-tags --depth=1 origin 546044815026a643cc95ea9737d6dfd167465e6d
fi
rustup component add --toolchain 1.85.0 rustfmt clippy
rustup target add --toolchain 1.85.0 wasm32-unknown-unknown
nice -n 10 cargo +1.85.0 fetch --locked --manifest-path tools/zk-spec/Cargo.toml
nice -n 10 cargo +1.85.0 fmt --manifest-path tools/zk-spec/Cargo.toml --all -- --check
nice -n 10 cargo +1.85.0 test --offline --locked --manifest-path tools/zk-spec/core/Cargo.toml
nice -n 10 cargo +1.85.0 clippy --offline --locked --manifest-path tools/zk-spec/Cargo.toml -p materios-zk-core -p materios-zk-spec-driver --all-targets -- -D warnings
nice -n 10 python3 -m unittest discover -s tools/zk-spec -p 'test_*.py'
nice -n 10 python3 tools/zk-spec/check.py c-p0-mainnet-refusal
nice -n 10 python3 tools/zk-spec/check.py c-p0-midnight-negative-control
nice -n 10 python3 tools/zk-spec/check.py c-p0-bridge-codec
nice -n 10 cargo +1.85.0 build --offline --locked --release --no-default-features --target wasm32-unknown-unknown --manifest-path tools/zk-spec/wasm/Cargo.toml
nice -n 10 cargo +1.85.0 clippy --offline --locked --release --no-default-features --target wasm32-unknown-unknown --manifest-path tools/zk-spec/wasm/Cargo.toml --lib -- -D warnings
python3 tools/zk-spec/vectors.py --check
# CI verifies proofs without timing hardware that hosts live services.
nice -n 10 node tools/zk-spec/wasm-run.mjs .zk-spec-target/wasm32-unknown-unknown/release/materios_zk_wasm.wasm --verify-only > .zk-spec-scratch/ci-wasm-verification.json
