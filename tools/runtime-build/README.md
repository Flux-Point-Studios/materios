# Reproducible runtime and release node build

`build.sh [commit] [out-dir]` builds the runtime blob of a commit,
`materios_runtime.compact.compressed.wasm`, and prints its sha256 and
blake2-256. Everyone who runs it on the same commit gets the same bytes, so the
`:code` of a published chain spec, and the code hash a signed launch manifest
pins, can be checked against the source.

`build.sh --node [commit] [out-dir]` builds the release node of a commit,
`materios-node`, the binary every validator runs and every authority pins as
`exe_sha256`. It prints the node's sha256 and the sha256 and blake2-256 of the
`:code` the node's own `build-spec` writes, which it holds to the blob the node
build compiled, so the node embeds the blob `build.sh <commit>` gives.

```
tools/runtime-build/build.sh <commit> runtime-build
tools/runtime-build/build.sh --node <commit> release
```

It needs docker, git, `b2sum` and network access (the image, apt packages and
crates). The default commit is `HEAD` and the default output directory is
`runtime-build`.

## How

- `git archive` takes the commit's `partnerchain` tree, so only committed files
  go in.
- The tree is extracted to `/materios` in `rust:1.85.0-bookworm`, pinned by its
  multi-platform index digest. That is the toolchain `rust-toolchain.toml`
  pins, and the image Woodpecker builds with.
- `cargo check --locked --release -p materios-runtime` builds the blob as a
  release node build embeds it.

## Why a fixed path

Cargo hashes the absolute location of a path dependency into its crate
metadata, which every symbol name of the workspace crates carries. Two builds
of one commit from different checkout paths, on one machine with the same
toolchain and Cargo home, gave blobs that differ in their function, code and
data sections, not only in their strings.

The runtime's build script also remaps the directories the blob's panic
messages name: the toolchain to `/rust-toolchain`, the Cargo home to
`/cargo-home` and the repository to `/materios`. The toolchain's directory
names the host's architecture, which differs between an arm64 and an x86-64
host running this image.

A debug node build embeds a different blob (not compacted), so do not take
`:code` from a debug node.

## The release node

`--node` runs the same image, path and preparation, then
`cargo build --locked --release -p materios-node`. Nothing else is set: no
`RUSTFLAGS`, `WASM_BUILD_*` or linker flags, and the workspace's default
release profile. Two builds of one commit, each from a clean target directory
and Cargo home, give the same binary, the same sha256. The build's job count
does not change it.

- The node's `--version` names its commit, which its build script reads from
  git. The archived tree has no `.git`, so `build.sh` passes the commit id the
  archive records (`git get-tar-commit-id`), cut to the 11 digits
  `git rev-parse --short=11` gives, as `SUBSTRATE_CLI_GIT_COMMIT_HASH`.
  Without it the version reads `unknown` and the binary is another file.
- The container runs as `linux/amd64`, the validators' architecture, on any
  host. An arm64 host needs qemu-user binfmt for amd64 to run it.
- The image's apt packages are not pinned. A Debian point release that
  changes clang, libclang or protobuf-compiler can change the binary; the
  release notes record the versions a release was built with.

`partnerchain/Dockerfile` cannot build the release. It builds with rust 1.88
rather than the toolchain `rust-toolchain.toml` pins, without `--locked`,
after editing the workspace `Cargo.toml` with sed and patching sp-io in the
Cargo home, at another path. Its node does not embed the blob `build.sh`
gives, so it fails the code hash check of a launch
(docs/launch/GENESIS-DAY.md, step 7a).

## Putting the blob in a genesis

A plain chain spec carries the code its genesis is built from at
`genesis.runtimeGenesis.code`. `build-spec --raw` runs that code's genesis
builder and stores the code as `:code`, so the raw spec's genesis depends only
on the blob and the plain spec's patch, not on the node that ran it:

```
materios-node build-spec --chain preprod > plain.json
xxd -p runtime-build/materios_runtime.compact.compressed.wasm | tr -d '\n' > code.hex
jq --rawfile code code.hex '.genesis.runtimeGenesis.code = "0x" + $code' plain.json > plain-built.json
materios-node build-spec --chain plain-built.json --raw > raw.json
```
