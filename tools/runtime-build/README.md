# Reproducible runtime build

`build.sh [commit] [out-dir]` builds the runtime blob of a commit,
`materios_runtime.compact.compressed.wasm`, and prints its sha256 and
blake2-256. Everyone who runs it on the same commit gets the same bytes, so the
`:code` of a published chain spec, and the code hash a signed launch manifest
pins, can be checked against the source.

```
tools/runtime-build/build.sh <commit> runtime-build
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
