# Stage 1: chef
FROM rust:1.88.0-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler clang libclang-dev libssl-dev pkg-config make cmake && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef@0.1.71 --locked
RUN rustup target add wasm32-unknown-unknown && rustup component add rust-src
WORKDIR /build

# Stage 2: planner
FROM chef AS planner
COPY partnerchain/ ./partnerchain/
WORKDIR /build/partnerchain
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: builder
FROM chef AS builder
COPY --from=planner /build/partnerchain/recipe.json /build/partnerchain/recipe.json
WORKDIR /build/partnerchain
RUN cargo chef cook --release --recipe-path recipe.json
COPY partnerchain/ /build/partnerchain/

# Fix 1: Workspace Cargo.toml - missing default-features = false
RUN sed -i \
  's|^sp-consensus-aura = { git = "https://github.com/paritytech/polkadot-sdk.git", tag = "polkadot-stable2409-5" }$|sp-consensus-aura = { git = "https://github.com/paritytech/polkadot-sdk.git", tag = "polkadot-stable2409-5", default-features = false }|' \
  Cargo.toml && \
  sed -i \
  's|^sp-consensus-grandpa = { git = "https://github.com/paritytech/polkadot-sdk.git", tag = "polkadot-stable2409-5" }$|sp-consensus-grandpa = { git = "https://github.com/paritytech/polkadot-sdk.git", tag = "polkadot-stable2409-5", default-features = false }|' \
  Cargo.toml && \
  sed -i \
  's|^serde_json = "1.0"$|serde_json = { version = "1.0", default-features = false }|' \
  Cargo.toml && \
  echo "Workspace deps fixed"

ENV WASM_BUILD_RUSTFLAGS='--cfg getrandom_backend="unsupported"'

# Two-phase build: Phase 1 populates git checkout, then we patch sp-io for Rust 1.88 compat
RUN bash -c 'set -e; \
  echo "=== Phase 1: Initial build (expected to fail) ==="; \
  cargo build --release -p materios-node 2>&1 || true; \
  echo "=== Patching sp-io for Rust 1.88 compat ==="; \
  SP_IO=$(find /usr/local/cargo/git/checkouts/ -path "*/substrate/primitives/io/src/lib.rs" 2>/dev/null | head -1); \
  if [ -z "$SP_IO" ]; then echo "ERROR: sp-io lib.rs not found!"; exit 1; fi; \
  echo "Found sp-io at: $SP_IO"; \
  sed -i "/#\\[panic_handler\\]/{n;s/#\\[no_mangle\\]/\\/\\/ #[no_mangle] -- removed for Rust 1.88 compat/}" "$SP_IO"; \
  echo "=== Clearing WASM build cache ==="; \
  rm -rf target/release/wbuild/materios-runtime/target; \
  echo "=== Phase 2: Rebuilding with patches ==="; \
  cargo build --release -p materios-node; \
  echo "=== Build complete ==="'

# Stage 4: runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3 jq && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 1000 materios && useradd -u 1000 -g materios -m materios
COPY --from=builder /build/partnerchain/target/release/materios-node /usr/local/bin/materios-node
COPY ops/scripts/healthcheck-substrate.sh /usr/local/bin/healthcheck-substrate.sh
RUN chmod +x /usr/local/bin/healthcheck-substrate.sh
USER materios
EXPOSE 9944 9615 30333
ENTRYPOINT ["materios-node"]
