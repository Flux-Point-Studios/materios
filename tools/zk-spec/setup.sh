#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export CARGO_TARGET_DIR="$PWD/.zk-spec-target"
export CARGO_BUILD_JOBS=2
export WASM_BUILD_WORKSPACE_HINT="$PWD/partnerchain"
export WASM_BUILD_TYPE=release
mkdir -p .zk-spec-scratch tools/zk-spec/artifacts
rustup target add --toolchain 1.85.0 wasm32-unknown-unknown
nice -n 10 cargo +1.85.0 fetch --locked --manifest-path tools/zk-spec/Cargo.toml
nice -n 10 cargo +1.85.0 fetch --locked --manifest-path partnerchain/Cargo.toml
nice -n 10 cargo +1.85.0 build --locked --offline --manifest-path partnerchain/Cargo.toml -p materios-runtime
cp .zk-spec-target/debug/wbuild/materios-runtime/materios_runtime.compact.compressed.wasm tools/zk-spec/artifacts/runtime.wasm
python3 - <<'PY'
from pathlib import Path
import hashlib
import subprocess
import urllib.request
archive = Path('tools/zk-spec/artifacts/subwasm.deb')
if not archive.is_file():
    archive.write_bytes(urllib.request.urlopen('https://github.com/chevdor/subwasm/releases/download/v0.21.3/subwasm_linux_amd64_v0.21.3.deb', timeout=120).read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != '0560d1b8785be9a0d04cb0bf939feaaa621c2d0809f818225698d5c44198550c':
    raise SystemExit('subwasm download hash mismatch')
subprocess.run(['dpkg-deb', '-x', str(archive), 'tools/zk-spec/artifacts/subwasm'], check=True)
PY
python3 tools/zk-spec/vectors.py --check
nice -n 10 cargo +1.85.0 test --offline --locked --manifest-path tools/zk-spec/core/Cargo.toml
nice -n 10 cargo +1.85.0 build --offline --locked --release --no-default-features --target wasm32-unknown-unknown --manifest-path tools/zk-spec/wasm/Cargo.toml
nice -n 10 cargo +1.85.0 build --offline --locked --manifest-path tools/zk-spec/driver/Cargo.toml
nice -n 10 aiken check --deny tools/zk-spec/aiken
