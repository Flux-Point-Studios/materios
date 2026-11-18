#!/bin/sh
# Builds the runtime blob of a commit, or with --node the release node that
# embeds it, so that every build of it gives the same bytes: the commit's tree
# at /materios in a digest-pinned Rust image, whatever checkout, machine or
# architecture runs this.
#
# usage: tools/runtime-build/build.sh [--node] [commit] [out-dir]
set -eu

node=
if [ "${1:-}" = --node ]; then
	node=1
	shift
fi
commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
mkdir -p "${2:-runtime-build}"
out=$(cd "${2:-runtime-build}" && pwd)
image=rust:1.85.0-bookworm@sha256:0ff31c9ffa641a62e48d543fb00b4960955ea375f40776f40f585b89e654cc5e
blob=materios_runtime.compact.compressed.wasm
wbuild=target/release/wbuild/materios-runtime

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
git archive --format=tar "$commit" partnerchain > "$archive"

if [ -n "$node" ]; then
	# The node's --version names its commit, which substrate-build-script-utils
	# reads from git as `rev-parse --short=11`; the archived tree has no .git, so
	# the commit id the archive records is passed in instead. The validators run
	# x86-64; an arm64 host would otherwise pull the image's arm64 variant and
	# build another binary.
	set -- --platform linux/amd64 \
		-e "SUBSTRATE_CLI_GIT_COMMIT_HASH=$(git get-tar-commit-id < "$archive" | cut -c1-11)"
	build="nice -n 19 cargo build --locked --release -p materios-node
		cp target/release/materios-node /out/
		# The runtime the node embeds, as build-spec writes it to :code.
		target/release/materios-node build-spec --chain preprod --raw |
			sed -n 's/^ *\"0x3a636f6465\": \"0x\([0-9a-f]*\)\",\{0,1\}\$/\1/p' | tr -d '\n' |
			perl -0777 -ne 'print pack(\"H*\", \$_)' > /out/$blob
		cmp /out/$blob $wbuild/$blob
		chown $(id -u):$(id -g) /out/materios-node /out/$blob"
else
	set --
	build="nice -n 19 cargo check --locked --release -p materios-runtime
		cp $wbuild/$blob /out/
		chown $(id -u):$(id -g) /out/$blob"
fi

docker run --rm -i -v "$out:/out" -e CARGO_BUILD_JOBS "$@" "$image" sh -euc "
	mkdir /materios
	tar -x -C /materios
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends clang libclang-dev libssl-dev pkg-config protobuf-compiler make cmake >/dev/null
	rustup target add wasm32-unknown-unknown
	rustup component add rust-src
	cd /materios/partnerchain
	# A release build takes every core it gets; at low priority it yields to a node on the same host.
	$build" < "$archive"

echo "commit     $commit"
if [ -n "$node" ]; then
	echo "node       $out/materios-node"
	echo "sha256     $(sha256sum "$out/materios-node" | cut -d' ' -f1)"
fi
echo "blob       $out/$blob"
echo "sha256     $(sha256sum "$out/$blob" | cut -d' ' -f1)"
echo "blake2-256 0x$(b2sum -l 256 "$out/$blob" | cut -d' ' -f1)"
