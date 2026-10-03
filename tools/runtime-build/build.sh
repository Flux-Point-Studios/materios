#!/bin/sh
# Builds the runtime blob of a commit so that every build of it gives the same
# bytes: the commit's tree at /materios in a digest-pinned Rust image, whatever
# checkout, machine or architecture runs this.
#
# usage: tools/runtime-build/build.sh [commit] [out-dir]
set -eu

commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
mkdir -p "${2:-runtime-build}"
out=$(cd "${2:-runtime-build}" && pwd)
image=rust:1.85.0-bookworm@sha256:0ff31c9ffa641a62e48d543fb00b4960955ea375f40776f40f585b89e654cc5e
blob=materios_runtime.compact.compressed.wasm

git archive --format=tar "$commit" partnerchain |
	docker run --rm -i -v "$out:/out" -e CARGO_BUILD_JOBS "$image" sh -euc "
		mkdir /materios
		tar -x -C /materios
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends clang libclang-dev libssl-dev pkg-config protobuf-compiler make cmake >/dev/null
		rustup target add wasm32-unknown-unknown
		rustup component add rust-src
		cd /materios/partnerchain
		# A release build takes every core it gets; at low priority it yields to a node on the same host.
		nice -n 19 cargo check --locked --release -p materios-runtime
		cp target/release/wbuild/materios-runtime/$blob /out/
		chown $(id -u):$(id -g) /out/$blob"

echo "commit     $commit"
echo "blob       $out/$blob"
echo "sha256     $(sha256sum "$out/$blob" | cut -d' ' -f1)"
echo "blake2-256 0x$(b2sum -l 256 "$out/$blob" | cut -d' ' -f1)"
