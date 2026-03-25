# Materios
<img width="2048" height="2048" alt="materios_wordmark_true_transparent" src="https://github.com/user-attachments/assets/43d63d5d-a0e4-40ff-b250-b092af71d516" />

Materios is a **Cardano Partner Chain** purpose-built for cheap, fast settlement of gaming micro-transactions and AI audit receipts. It pairs a Substrate-based partner chain with a **Midnight ZK proof coprocessor** so that on-chain commitments remain small (roots, hashes, attestations) while full receipt data stays off-chain.

The result is a verifiable audit trail without exposing raw prompts, responses, or proprietary game telemetry.

> **Status:** Alpha / MVP prototype. The Partner Chains toolkit is alpha-grade software. Expect breaking changes.

---

## Architecture

Materios has three layers:

| Layer | Purpose | Tech |
|-------|---------|------|
| **Partner Chain** | Receipt settlement, fee payment, consensus | Substrate (Rust), Aura+GRANDPA |
| **Cardano Mainchain** | Governance, validator registration, anchoring | cardano-node, db-sync, ogmios |
| **Midnight Coprocessor** | Privacy-preserving ZK claims (e.g. risk thresholds) | Compact language, Midnight ledger |

**Hard constraint:** Only commitments go on-chain (roots, hashes, attestations). No raw data ever touches the ledger.

**Data flow:**
```
JSONL input
  -> receipt-builder (canonicalize, chunk, hash, compress, encrypt)
    -> Partner Chain pallet (receipt_id, content_hash, merkle_root)
      -> Midnight contract (ZK proof: "risk >= threshold" without revealing score)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design, data-flow diagrams, and the 8 design decisions (D1–D8).

---

## Two-Token Model (MATRA / MOTRA)

| Token | Role | Transferable | Decimals |
|-------|------|:------------:|:--------:|
| **MATRA** | Capital token (native currency) | Yes | 12 |
| **MOTRA** | Capacity token (pays fees, decays over time) | No | 12 |

- **Fee formula:** `TxFee = MinFee + CongestionRate * Weight + LengthFeePerByte * Len` (paid in MOTRA)
- **Congestion rate:** EMA smoothing, adjusts per block vs target fullness
- **MOTRA generation:** Proportional to MATRA holdings, lazy reconciliation
- **Delegation:** `set_delegatee` routes future MOTRA generation to a sponsor account

Inspired by Midnight's NIGHT/DUST model. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Project Structure

```
materios/
├── README.md
├── .gitignore
├── .dockerignore
│
├── docs/                                 # Specifications & operations
│   ├── ARCHITECTURE.md                   #   System design, design decisions D1-D8
│   ├── CANONICALIZATION.md               #   RFC 8785 JCS canonicalization spec
│   ├── AVAILABILITY_CERT_SPEC.md         #   dCBOR availability certificate spec
│   ├── GOVERNANCE.md                     #   Governance UTXO, D-parameter, migration
│   └── RUNBOOK.md                        #   Deployment steps, testing, troubleshooting
│
├── partnerchain/                         # Substrate partner chain (Rust workspace)
│   ├── Cargo.toml                        #   Workspace root
│   ├── Cargo.lock                        #   Dependency lockfile
│   ├── rust-toolchain.toml               #   Rust 1.90.0, wasm32v1-none
│   ├── Dockerfile                        #   Multi-stage cargo-chef build
│   ├── flake.nix                         #   Nix dev shell (optional)
│   ├── node/                             #   Node binary (CLI, RPC, service)
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs                    #     CLI argument definitions
│   │       ├── command.rs                #     Subcommand dispatch
│   │       ├── service.rs                #     Full node / partial components
│   │       ├── rpc.rs                    #     JSON-RPC extension wiring
│   │       ├── chain_spec.rs             #     Dev / local chain specs
│   │       └── chain_spec_preprod.rs     #     Preprod / staging chain specs
│   ├── runtime/                          #   WASM runtime (pallets, config)
│   │   └── src/lib.rs
│   └── pallets/
│       ├── orinq-receipts/               #   Receipt settlement pallet
│       │   ├── src/
│       │   │   ├── lib.rs                #     Pallet logic (submit, anchor, query)
│       │   │   ├── types.rs              #     Receipt, ReceiptStatus, AnchorData
│       │   │   ├── tests.rs              #     Unit tests
│       │   │   ├── integration_tests.rs  #     E2E integration tests
│       │   │   ├── weights.rs            #     Benchmark weights
│       │   │   └── benchmarking.rs
│       │   ├── primitives/               #     Shared types for RPC
│       │   └── rpc/                      #     orinq_* JSON-RPC methods
│       └── motra/                        #   MOTRA capacity-token pallet
│           ├── src/
│           │   ├── lib.rs                #     Generation, decay, delegation
│           │   ├── fee.rs                #     ChargeMotra fee adapter
│           │   ├── types.rs              #     MotraParams, MotraBalance
│           │   ├── tests.rs              #     Unit tests
│           │   ├── weights.rs
│           │   └── benchmarking.rs
│           ├── primitives/               #     Shared types for RPC
│           └── rpc/                      #     motra_* JSON-RPC methods
│
├── cert-daemon/                         # Certification daemon (Python)
│   ├── Dockerfile                       #   Multi-stage Python build
│   ├── requirements.txt                 #   Python dependencies
│   ├── daemon/
│   │   ├── attestation.py               #     Receipt attestation (threshold multi-attester)
│   │   ├── checkpoint.py                #     Cardano L1 checkpoint batching
│   │   ├── heartbeat.py                 #     sr25519-signed heartbeats (30s interval)
│   │   ├── locator_registry.py          #     Blob locator resolution via gateway
│   │   ├── blob_verifier.py             #     Blob data verification (SHA-256 chunks)
│   │   ├── substrate_client.py          #     Substrate RPC client
│   │   └── watchtower.py                #     Committee health monitoring + Discord alerts
│   ├── k8s/                             #   K8s manifests (deployments, configmaps, secrets)
│   ├── chaos/                           #   Chaos drill scripts (5 drills)
│   ├── scripts/
│   │   └── verify.py                    #   8-step chain-of-custody verification
│   └── materios-operator-kit/           #   Public external operator kit (submodule)
│
├── tools/
│   ├── receipt-builder/                  # Off-chain receipt construction (TypeScript)
│   │   ├── package.json                  #   @materios/receipt-builder
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts                  #     CLI entry point (commander)
│   │   │   ├── pipeline.ts               #     Full canonicalize-chunk-hash-compress-encrypt
│   │   │   ├── canonicalize.ts           #     RFC 8785 JCS per-line canonicalization
│   │   │   ├── chunker.ts               #     Line-aware chunking
│   │   │   ├── compress.ts              #     gzip compression
│   │   │   ├── encrypt.ts               #     AES-256-GCM encryption
│   │   │   ├── manifest.ts              #     Receipt manifest builder
│   │   │   ├── receipt.ts               #     Receipt type construction
│   │   │   ├── types.ts                 #     Shared TypeScript types
│   │   │   └── hash/
│   │   │       ├── sha256.ts            #       SHA-256 (primary)
│   │   │       ├── merkle.ts            #       Merkle tree builder
│   │   │       └── poseidon.ts          #       Poseidon hash (optional, ZK-friendly)
│   │   ├── tests/
│   │   │   └── pipeline.test.ts         #     Vitest test suite
│   │   └── examples/
│   │       └── trace.jsonl              #     Sample AI audit trace
│   │
│   ├── materios-verify/                  # Receipt verification CLI + library (Python)
│   │   ├── setup.py                      #   pip install materios-verify
│   │   └── materios_verify/
│   │       └── __main__.py               #   8-step chain-of-custody verification
│   │
│   └── explorer/                         # Receipt explorer web UI (FastAPI)
│       └── app.py                        #   Dashboard: recent activity, verification status
│
├── midnight/                             # Midnight ZK coprocessor
│   ├── package.json
│   ├── PROOF_DEMO.md                     #   ZK proof walkthrough
│   ├── docker-compose.yml                #   Midnight local devnet
│   ├── contracts/
│   │   └── audit-claims.compact          #   Compact ZK circuit (proveRiskThreshold)
│   └── client/                           #   TypeScript client for Midnight
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── deploy.ts                 #     Contract deployment
│           ├── submitCommitment.ts       #     Commit receipt roots
│           ├── submitClaim.ts            #     Submit ZK claims
│           ├── proveRiskThreshold.ts     #     Prove risk >= threshold
│           ├── query.ts                  #     Query claims
│           ├── providers.ts              #     Midnight provider setup
│           └── utils.ts
│
└── ops/                                  # Operations & deployment
    ├── docker-compose.yml                #   Full stack (6 services)
    ├── deploy.sh                         #   One-shot deploy script
    ├── .env.example                      #   Environment template
    ├── .env.preprod                      #   Preprod-specific (jerry)
    ├── nginx/
    │   └── nginx.conf                    #   Reverse proxy, IP allowlist, rate limiting
    ├── scripts/
    │   ├── bootstrap.sh                  #   Download configs + start infra
    │   ├── deploy.sh → ../deploy.sh
    │   ├── preprod-boot.sh               #   Automated preprod bootstrap
    │   ├── wait-for-sync.sh              #   Poll db-sync until chain tip
    │   ├── healthcheck-substrate.sh      #   Docker HEALTHCHECK for materios-node
    │   └── healthcheck-stack.sh          #   Operator full-stack health check
    └── config/
        └── preprod/                      #   Downloaded at deploy time (.gitignored)
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Rust** | 1.90.0 | Pinned via `partnerchain/rust-toolchain.toml` |
| **Node.js** | 22+ | LTS recommended |
| **pnpm** | latest | For receipt-builder and midnight client |
| **Docker** | 24+ | Docker Compose v2 plugin required |
| **Nix** | optional | Reproducible dev shell via `partnerchain/flake.nix` |

---

## Quick Start (Development)

```bash
# Clone
git clone https://github.com/<org>/materios.git && cd materios

# Build the partner chain node
cd partnerchain
cargo build --release -p materios-node

# Run unit tests (38 pallet tests + 11 integration tests)
cargo test --workspace

# Build the receipt-builder
cd ../tools/receipt-builder
pnpm install && pnpm build

# Run receipt-builder tests
pnpm test
```

### Local dev chain

```bash
# Start a dev chain (single-node, instant block production)
./partnerchain/target/release/materios-node --dev --tmp

# Query via RPC
curl -s -X POST http://localhost:9944 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'
```

---

## Container Deployment (Preprod)

The `ops/` directory contains a fully containerized stack for preprod burn-in.

### Services

| Service | Image | Purpose |
|---------|-------|---------|
| cardano-node | `ghcr.io/intersectmbo/cardano-node:10.5.1` | Cardano preprod relay |
| postgres | `postgres:16-alpine` | DB Sync backend |
| cardano-db-sync | `ghcr.io/intersectmbo/cardano-db-sync:13.6.0.4` | Chain indexer |
| ogmios | `cardanosolutions/ogmios:v6.13.0` | Cardano JSON-RPC bridge |
| materios-node | local build (`partnerchain/Dockerfile`) | Partner chain validator |
| nginx | `nginx:1.27-alpine` | Reverse proxy + IP allowlist |

### Deploy

```bash
cd ops
chmod +x deploy.sh && ./deploy.sh
```

This builds the materios-node image, starts the Cardano infrastructure, and prints wizard instructions for governance initialization. See the full sequence in [docs/RUNBOOK.md](docs/RUNBOOK.md).

### Wizard-First Flow

The materios-node does **not** auto-start as a validator. The deployment follows a wizard-first flow:

1. Start infrastructure: `docker compose up -d cardano-node postgres cardano-db-sync ogmios nginx`
2. Wait for db-sync to reach chain tip (~12-48h)
3. Run wizards as one-shot containers:
   ```bash
   docker compose run --rm materios-node materios-node wizards generate-keys
   docker compose run --rm materios-node materios-node wizards prepare-configuration
   docker compose run --rm materios-node materios-node wizards create-chain-spec
   docker compose run --rm materios-node materios-node wizards setup-main-chain-state
   ```
4. Wait 2 Cardano epochs (~2 days)
5. Start the validator: `docker compose up -d materios-node`

### Security

- **RPC lockdown:** `--rpc-methods safe` blocks admin/author methods; no `--rpc-cors`
- **IP allowlist:** nginx `geo` module restricts RPC access to authorized networks
- **Rate limiting:** 30 req/s RPC, 10 req/s WebSocket
- **Ogmios:** Only health check and WebSocket exposed; dashboard blocked (426 on plain HTTP)

### Health Checks

```bash
# Full stack check (all 5 services)
bash ops/scripts/healthcheck-stack.sh

# Individual service
curl http://localhost/health              # nginx
curl http://localhost/health-ogmios       # ogmios via nginx
curl -X POST http://localhost/substrate/  # materios-node via nginx
  -H 'Content-Type: application/json'
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'
```

---

## Testing

### Partner Chain (Rust)

```bash
cd partnerchain

# All workspace tests
cargo test --workspace

# Specific pallet
cargo test -p pallet-orinq-receipts
cargo test -p pallet-motra

# Integration tests only
cargo test -p pallet-orinq-receipts integration_tests
```

### Receipt Builder (TypeScript)

```bash
cd tools/receipt-builder
pnpm test          # single run
pnpm test:watch    # watch mode
```

### Midnight Contract

```bash
cd midnight
pnpm run compile   # compile audit-claims.compact
```

---

## RPC Methods

### Orinq Receipts

| Method | Description |
|--------|-------------|
| `orinq_getReceipt` | Fetch a receipt by receipt_id |
| `orinq_getReceiptsByContentHash` | Look up receipts by content_hash |
| `orinq_receiptExists` | Check if a receipt exists (lightweight, returns bool) |
| `orinq_getReceiptStatus` | Get receipt status: pending, certified, or anchored |

### MOTRA

| Method | Description |
|--------|-------------|
| `motra_getBalance` | Query MOTRA balance for an account |
| `motra_getParams` | Get current MOTRA parameters (decay rate, generation rate, etc.) |
| `motra_estimateFee` | Estimate fee for a given extrinsic weight + length |

---

## Governance

Materios uses the Partner Chains governance model anchored on Cardano:

- **Governance UTXO:** One-time, irreversible genesis on Cardano mainchain
- **D-parameter:** Controls permissioned vs registered validator ratio
- **Migration plan:** `(3,0)` fully permissioned -> `(0,N)` fully decentralized

See [docs/GOVERNANCE.md](docs/GOVERNANCE.md) for initialization procedures and the D-parameter migration roadmap.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

---

## Appendix: Knowledge Map

A topic-to-file index for navigating the codebase.

### Specifications

| Topic | Location | Notes |
|-------|----------|-------|
| System architecture & design decisions | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | D1-D8, data flow, component overview |
| JSON canonicalization (RFC 8785 JCS) | [docs/CANONICALIZATION.md](docs/CANONICALIZATION.md) | Per-line normalization, hash-before-compress, chunk boundaries |
| Availability certificates (dCBOR) | [docs/AVAILABILITY_CERT_SPEC.md](docs/AVAILABILITY_CERT_SPEC.md) | 9-field signed message, 3 verification levels, on-chain hash |
| Governance & D-parameter | [docs/GOVERNANCE.md](docs/GOVERNANCE.md) | UTXO setup, wizard flow, decentralization roadmap |
| Deployment runbook | [docs/RUNBOOK.md](docs/RUNBOOK.md) | Full deployment, MOTRA testing, troubleshooting (8 scenarios) |
| Midnight ZK proof demo | [midnight/PROOF_DEMO.md](midnight/PROOF_DEMO.md) | proveRiskThreshold circuit, fee considerations, limitations |

### Partner Chain (Rust)

| Topic | Location | Notes |
|-------|----------|-------|
| Receipt pallet (submit, anchor, query) | `partnerchain/pallets/orinq-receipts/src/lib.rs` | Core settlement logic |
| Receipt types (Receipt, AnchorData) | `partnerchain/pallets/orinq-receipts/src/types.rs` | On-chain data structures |
| Receipt RPC methods | `partnerchain/pallets/orinq-receipts/rpc/src/lib.rs` | orinq_getReceipt, orinq_getReceiptsByContentHash |
| MOTRA pallet (generation, decay, delegation) | `partnerchain/pallets/motra/src/lib.rs` | Capacity token mechanics |
| MOTRA fee adapter (ChargeMotra) | `partnerchain/pallets/motra/src/fee.rs` | Fee calculation with congestion EMA |
| MOTRA types (MotraParams, MotraBalance) | `partnerchain/pallets/motra/src/types.rs` | Must stay in sync with primitives |
| MOTRA RPC methods | `partnerchain/pallets/motra/rpc/src/lib.rs` | motra_getBalance, motra_getParams, motra_estimateFee |
| Chain spec (dev / local) | `partnerchain/node/src/chain_spec.rs` | Genesis config for development |
| Chain spec (preprod / staging) | `partnerchain/node/src/chain_spec_preprod.rs` | Genesis config for preprod |
| CLI subcommands | `partnerchain/node/src/cli.rs` | Argument definitions |
| Subcommand dispatch | `partnerchain/node/src/command.rs` | CLI routing + stub error messages |
| Node service (full + partial) | `partnerchain/node/src/service.rs` | Aura, GRANDPA, RPC wiring |
| Runtime configuration | `partnerchain/runtime/src/lib.rs` | Pallet composition, parameter tuning |
| Rust toolchain | `partnerchain/rust-toolchain.toml` | 1.90.0, wasm32v1-none |
| Dockerfile (multi-stage cargo-chef) | `partnerchain/Dockerfile` | Build context = repo root |

### Receipt Builder (TypeScript)

| Topic | Location | Notes |
|-------|----------|-------|
| CLI entry point | `tools/receipt-builder/src/index.ts` | commander-based CLI |
| Full pipeline (canonicalize-chunk-hash-compress-encrypt) | `tools/receipt-builder/src/pipeline.ts` | End-to-end receipt construction |
| RFC 8785 JCS canonicalization | `tools/receipt-builder/src/canonicalize.ts` | Uses `canonicalize` npm package |
| Line-aware chunking | `tools/receipt-builder/src/chunker.ts` | Lines are atomic, never split |
| SHA-256 hashing | `tools/receipt-builder/src/hash/sha256.ts` | Primary hash function |
| Merkle tree construction | `tools/receipt-builder/src/hash/merkle.ts` | Builds tree from chunk hashes |
| Poseidon hash (ZK-friendly) | `tools/receipt-builder/src/hash/poseidon.ts` | Optional, version-bound (D4) |
| Pipeline tests | `tools/receipt-builder/tests/pipeline.test.ts` | Vitest suite |
| Sample input | `tools/receipt-builder/examples/trace.jsonl` | AI audit trace example |

### Midnight (ZK Coprocessor)

| Topic | Location | Notes |
|-------|----------|-------|
| Compact ZK circuit | `midnight/contracts/audit-claims.compact` | proveRiskThreshold, commitReceipt |
| Contract deployment | `midnight/client/src/deploy.ts` | Deploy to Midnight devnet/testnet |
| Submit receipt commitments | `midnight/client/src/submitCommitment.ts` | Commit roots to Midnight |
| Prove risk threshold | `midnight/client/src/proveRiskThreshold.ts` | ZK proof: risk >= threshold |
| Submit ZK claims | `midnight/client/src/submitClaim.ts` | Post proof on-chain |
| Query claims | `midnight/client/src/query.ts` | Look up verified claims |
| Midnight devnet | `midnight/docker-compose.yml` | Local development network |

### Cert Daemon (Python)

| Topic | Location | Notes |
|-------|----------|-------|
| Receipt attestation (multi-attester) | `cert-daemon/daemon/attestation.py` | Threshold-based, 2-of-N committee |
| Cardano L1 checkpointing | `cert-daemon/daemon/checkpoint.py` | Batches certified receipts, Merkle root anchoring |
| sr25519-signed heartbeats | `cert-daemon/daemon/heartbeat.py` | 30s interval, verified on gateway |
| Blob locator resolution | `cert-daemon/daemon/locator_registry.py` | Fetches blob data via gateway (public reads) |
| Blob data verification | `cert-daemon/daemon/blob_verifier.py` | SHA-256 chunk verification |
| Substrate RPC client | `cert-daemon/daemon/substrate_client.py` | Keypair, chain queries, extrinsic submission |
| Committee watchtower | `cert-daemon/daemon/watchtower.py` | Health monitoring + Discord alerts |
| Chaos drill scripts (5 drills) | `cert-daemon/chaos/` | Network partition, node failure, pipeline E2E |
| Chain-of-custody verification | `cert-daemon/scripts/verify.py` | 8-step proof: receipt → cert → anchor → Merkle |
| K8s deployments | `cert-daemon/k8s/` | Alice + Bob daemons, configmaps, secrets |
| External operator kit | `cert-daemon/materios-operator-kit/` | Public repo for external validators |

### Tools

| Topic | Location | Notes |
|-------|----------|-------|
| Receipt verification CLI | `tools/materios-verify/` | `materios-verify <receipt_id>`, pip-installable |
| Receipt explorer web UI | `tools/explorer/app.py` | FastAPI dashboard, 5-state status badges |

### Operations & Deployment

| Topic | Location | Notes |
|-------|----------|-------|
| Docker Compose (full stack, 6 services) | `ops/docker-compose.yml` | materios-net bridge, log rotation |
| Nginx reverse proxy | `ops/nginx/nginx.conf` | IP allowlist, rate limiting, Ogmios WS gate |
| Deploy script | `ops/deploy.sh` | One-shot: preflight, build, start infra |
| Bootstrap (config download + start) | `ops/scripts/bootstrap.sh` | Downloads preprod config files |
| Preprod automated boot | `ops/scripts/preprod-boot.sh` | Full automated deployment |
| DB Sync wait | `ops/scripts/wait-for-sync.sh` | Polls until db-sync reaches chain tip |
| Substrate health check | `ops/scripts/healthcheck-substrate.sh` | Docker HEALTHCHECK (system_health RPC) |
| Stack health check | `ops/scripts/healthcheck-stack.sh` | Tests all 5 services, prints report |
| Environment template | `ops/.env.example` | Tracked; copy to .env |
| Preprod environment | `ops/.env.preprod` | jerry-asus-nuc-14 specific values |

### Conventions

| Convention | Reference |
|------------|-----------|
| Hash canonical bytes BEFORE compression | [docs/CANONICALIZATION.md](docs/CANONICALIZATION.md) (eliminates gzip non-determinism) |
| RFC 8785 JCS for JSON canonicalization | [docs/CANONICALIZATION.md](docs/CANONICALIZATION.md) |
| dCBOR (RFC 8949 sec. 4.2) for availability certs | [docs/AVAILABILITY_CERT_SPEC.md](docs/AVAILABILITY_CERT_SPEC.md) |
| Runtime-sourced timestamps (not client) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (D6) |
| content_hash = deterministic, receipt_id = unique per submission | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (D1) |
| Only commitments on-chain (roots, hashes, attestations) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (hard constraint) |
| Schema version as hash, not semver | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (D8) |
