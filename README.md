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
Game run / AI trace
  -> blob upload (JSON telemetry to gateway)
    -> Partner Chain pallet (receipt_id, content_hash, merkle_root)
      -> Cert daemon network (fetch, verify, attest)
        -> Certified receipt (threshold attestation met)
          -> Cardano L1 anchor (Merkle checkpoint)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design, data-flow diagrams, and the 8 design decisions (D1-D8).

---

## Two-Token Model (MATRA / MOTRA)

| Token | Role | Transferable | Decimals |
|-------|------|:------------:|:--------:|
| **MATRA** | Capital token (native currency) | Yes | 6 |
| **MOTRA** | Capacity token (pays fees, decays over time) | No | 6 |

- **Fee formula:** `TxFee = MinFee + CongestionRate * Weight + LengthFeePerByte * Len` (paid in MOTRA)
- **Congestion rate:** EMA smoothing, adjusts per block vs target fullness
- **MOTRA generation:** Proportional to MATRA holdings, lazy reconciliation
- **Delegation:** `set_delegatee` routes future MOTRA generation to a sponsor account

Inspired by Midnight's NIGHT/DUST model. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Validator Rewards

Operators earn tMATRA from two separate reserve pools:

| Pool | Reserve | Mechanism |
|------|---------|-----------|
| **Block production** | 150M MATRA (15% of supply) | Pro-rata per era (~24h), proportional to blocks authored |
| **Attestation** | 50M MATRA (5% of supply) | 10 tMATRA per signer per certified receipt, instant payout |

- **No slashing** — missed blocks = missed rewards
- **Permissionless attestation** — anyone can call `join_committee` and earn attestation rewards
- **Per-era cap** — attestation rewards capped at 50,000 MATRA/era to prevent reserve drain

---

## Project Structure

```
materios/
├── partnerchain/                         # Substrate partner chain (Rust)
│   ├── Cargo.toml                        #   Workspace root
│   ├── rust-toolchain.toml               #   Rust 1.88.0, wasm32-unknown-unknown
│   ├── Dockerfile                        #   Multi-stage cargo-chef build
│   ├── flake.nix                         #   Nix dev shell (optional)
│   ├── node/src/                         #   Node binary
│   │   ├── main.rs
│   │   ├── cli.rs                        #     CLI argument definitions
│   │   ├── command.rs                    #     Subcommand dispatch
│   │   ├── service.rs                    #     Full node / partial components
│   │   ├── rpc.rs                        #     JSON-RPC extension wiring
│   │   ├── chain_spec.rs                 #     Dev / local chain specs
│   │   └── chain_spec_preprod.rs         #     Preprod / staging chain specs
│   ├── runtime/src/lib.rs                #   WASM runtime (spec_version 111)
│   └── pallets/
│       ├── orinq-receipts/               #   Receipt settlement pallet
│       │   ├── src/
│       │   │   ├── lib.rs                #     Pallet logic (submit, attest, anchor, rewards)
│       │   │   ├── types.rs              #     ReceiptRecord, PlayerSigRecord, AnchorRecord
│       │   │   ├── tests.rs              #     Unit tests (15 tests)
│       │   │   ├── integration_tests.rs  #     E2E integration tests (11 tests)
│       │   │   ├── weights.rs            #     Benchmark weights
│       │   │   └── benchmarking.rs
│       │   ├── primitives/               #     Shared types for RPC
│       │   └── rpc/                      #     orinq_* JSON-RPC methods
│       └── motra/                        #   MOTRA capacity-token pallet
│           ├── src/
│           │   ├── lib.rs                #     Generation, decay, delegation
│           │   ├── fee.rs                #     ChargeMotra fee adapter
│           │   ├── types.rs              #     MotraParams, MotraBalance
│           │   ├── tests.rs              #     Unit tests (20 tests)
│           │   ├── weights.rs
│           │   └── benchmarking.rs
│           ├── primitives/               #     Shared types for RPC
│           └── rpc/                      #     motra_* JSON-RPC methods
│
├── cert-daemon/                          # Certification daemon (Python)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── schemas/
│   │   └── registry.json                 #   Content validation schema registry
│   ├── daemon/
│   │   ├── main.py                       #     Entry point
│   │   ├── config.py                     #     Configuration (env vars)
│   │   ├── cert_daemon.py                #     Main poll loop and attestation logic
│   │   ├── cert_builder.py               #     dCBOR certificate construction
│   │   ├── cert_store.py                 #     Certificate persistence
│   │   ├── content_validator.py          #     Schema-driven content validation
│   │   ├── checkpoint.py                 #     Cardano L1 checkpoint batching
│   │   ├── heartbeat.py                  #     sr25519-signed heartbeats (30s interval)
│   │   ├── locator_registry.py           #     Blob locator resolution via gateway
│   │   ├── blob_verifier.py              #     SHA-256 chunk verification
│   │   ├── merkle.py                     #     Merkle tree construction
│   │   ├── models.py                     #     Data models
│   │   ├── health_server.py              #     HTTP health endpoints
│   │   ├── substrate_client.py           #     Substrate RPC client
│   │   └── watchtower.py                 #     Committee health monitoring
│   ├── tests/                            #   Unit tests
│   ├── scripts/
│   │   └── verify.py                     #   8-step chain-of-custody verification
│   ├── docs/
│   │   └── verification-guide.md         #   Verification walkthrough
│   ├── docker-compose.external.yml       #   External operator compose template
│   └── e2e_test.py                       #   End-to-end test
│
├── tools/
│   ├── receipt-builder/                  # Off-chain receipt construction (TypeScript)
│   │   ├── package.json
│   │   ├── src/
│   │   │   ├── index.ts                  #     CLI entry point
│   │   │   ├── pipeline.ts               #     Full canonicalize-chunk-hash-compress-encrypt
│   │   │   ├── canonicalize.ts           #     RFC 8785 JCS canonicalization
│   │   │   ├── chunker.ts               #     Line-aware chunking
│   │   │   ├── compress.ts              #     gzip compression
│   │   │   ├── encrypt.ts               #     AES-256-GCM encryption
│   │   │   ├── manifest.ts              #     Receipt manifest builder
│   │   │   ├── receipt.ts               #     Receipt type construction
│   │   │   ├── types.ts                 #     Shared TypeScript types
│   │   │   └── hash/
│   │   │       ├── sha256.ts            #       SHA-256 (primary)
│   │   │       ├── merkle.ts            #       Merkle tree builder
│   │   │       └── poseidon.ts          #       Poseidon hash (ZK-friendly, optional)
│   │   ├── tests/
│   │   │   └── pipeline.test.ts
│   │   └── examples/
│   │       └── trace.jsonl              #     Sample AI audit trace
│   │
│   ├── materios-verify/                  # Receipt verification CLI (Python)
│   │   ├── pyproject.toml
│   │   ├── setup.py / setup.cfg
│   │   ├── materios_verify/
│   │   │   ├── cli.py                    #     CLI entry point
│   │   │   └── core.py                   #     Verification logic
│   │   └── examples/
│   │       └── sample-receipts.json
│   │
│   └── explorer/                         # Receipt explorer web UI (FastAPI)
│       ├── Dockerfile
│       ├── requirements.txt
│       ├── app.py                        #     FastAPI routes + API endpoints
│       ├── chain.py                      #     Chain indexer + event scanner
│       ├── cache.py                      #     In-memory TTL cache
│       └── static/
│           ├── index.html                #     SPA shell
│           ├── app.js                    #     Frontend (hash router)
│           └── style.css
│
├── midnight/                             # Midnight ZK coprocessor
│   ├── PROOF_DEMO.md                     #   ZK proof walkthrough
│   ├── docker-compose.yml                #   Midnight local devnet
│   ├── contracts/
│   │   └── audit-claims.compact          #   Compact ZK circuit
│   └── client/src/                       #   TypeScript client
│       ├── deploy.ts                     #     Contract deployment
│       ├── submitCommitment.ts           #     Commit receipt roots
│       ├── submitClaim.ts                #     Submit ZK claims
│       ├── proveRiskThreshold.ts         #     Prove risk >= threshold
│       ├── query.ts                      #     Query claims
│       └── providers.ts                  #     Midnight provider setup
│
└── docs/                                 # Specifications
    ├── ARCHITECTURE.md                   #   System design, decisions D1-D8
    ├── CANONICALIZATION.md               #   RFC 8785 JCS canonicalization spec
    ├── AVAILABILITY_CERT_SPEC.md         #   dCBOR availability certificate spec
    ├── GOVERNANCE.md                     #   Governance UTXO, D-parameter
    ├── OPERATOR_KIT.md                   #   External operator onboarding
    └── RUNBOOK.md                        #   Deployment, testing, troubleshooting
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Rust** | 1.88.0 | Pinned via `partnerchain/rust-toolchain.toml` |
| **Node.js** | 22+ | LTS recommended (for receipt-builder) |
| **pnpm** | latest | For receipt-builder and midnight client |
| **Docker** | 24+ | Docker Compose v2 plugin required |
| **Python** | 3.12+ | For cert-daemon and verification tools |
| **Nix** | optional | Reproducible dev shell via `partnerchain/flake.nix` |

---

## Quick Start (Development)

```bash
# Clone
git clone https://github.com/Flux-Point-Studios/materios.git && cd materios

# Build the partner chain node
cd partnerchain
cargo build --release -p materios-node

# Run unit tests (46 tests across both pallets + integration tests)
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

## Running the Cert Daemon

The cert daemon verifies blob integrity and attests receipt availability. It connects to a Materios node via WebSocket RPC.

```bash
cd cert-daemon
pip install -r requirements.txt
python -m daemon.main
```

Configure via environment variables (see `daemon/config.py` for the full list):

| Variable | Purpose |
|----------|---------|
| `MATERIOS_RPC_URL` | WebSocket endpoint for the Materios node |
| `SIGNER_URI` | BIP39 mnemonic or `//Alice` for dev |
| `BLOB_GATEWAY_URL` | Blob gateway URL for fetching blob data |
| `CONTENT_VALIDATION_ENABLED` | Enable schema-based content validation |
| `SCHEMA_REGISTRY_PATH` | Path to schema registry JSON (default: `schemas/registry.json`) |

### Schema Registry

Content validation uses a JSON schema registry (`schemas/registry.json`). Each game defines required fields, types, bounds, and computed plausibility checks. See the registry file for the format and the Clay Monster Dash v1 schema as a reference.

---

## Testing

### Partner Chain (Rust)

```bash
cd partnerchain

# All workspace tests (46 total: 15 orinq-receipts + 11 integration + 20 motra)
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

### Cert Daemon (Python)

```bash
cd cert-daemon
python -m pytest tests/
```

---

## RPC Methods

### Orinq Receipts

| Method | Description |
|--------|-------------|
| `orinq_getReceipt` | Fetch a receipt by receipt_id |
| `orinq_getReceiptsByContent` | Look up receipt IDs by content_hash |
| `orinq_getReceiptCount` | Get total number of receipts on-chain |
| `orinq_receiptExists` | Check if a receipt exists (lightweight, returns bool) |
| `orinq_getReceiptStatus` | Get receipt status: pending, certified, or anchored |

### MOTRA

| Method | Description |
|--------|-------------|
| `motra_getBalance` | Query MOTRA balance for an account |
| `motra_getParams` | Get current MOTRA parameters (decay rate, generation rate, etc.) |
| `motra_estimateFee` | Estimate fee for a given extrinsic weight + length |

---

## Extrinsics

### orinqReceipts

| Call | Index | Description |
|------|:-----:|-------------|
| `submit_receipt` | 0 | Submit a receipt (studio wallet signs) |
| `set_availability_cert` | 1 | Root-only: set availability cert directly |
| `set_committee` | 2 | Root-only: set attestation committee + threshold |
| `attest_availability_cert` | 3 | Committee member attests a receipt |
| `submit_anchor` | 4 | Submit a Cardano L1 anchor |
| `rotate_authorities` | 5 | Root-only: rotate Aura + Grandpa authority sets |
| `submit_receipt_v2` | 6 | Submit receipt with player anti-cheat signature |
| `join_committee` | 7 | Permissionless: join the attestation committee |
| `leave_committee` | 8 | Voluntary: leave the attestation committee |

---

## Becoming an Operator

There are two ways to participate:

### Attestor (No Approval Needed)

Run a cert daemon and earn tMATRA for verifying receipts:

```bash
curl -sSL https://raw.githubusercontent.com/Flux-Point-Studios/materios-operator-kit/main/install.sh \
  | bash -s -- --mode attestor
```

Requirements: 1 vCPU, 512 MB RAM, 1 GB disk, outbound HTTPS only.

### Full Validator (Invite Required)

Run a full node (block production + finality) and a cert daemon:

```bash
curl -sSL https://raw.githubusercontent.com/Flux-Point-Studios/materios-operator-kit/main/install.sh \
  | bash -s -- --token YOUR_INVITE_TOKEN
```

Requirements: 2+ vCPU, 2 GB RAM, 50 GB SSD, port 30333 open.

See the [Operator Guide](https://docs.fluxpointstudios.com/materios-partner-chain/operator-guide) for full details.

---

## Governance

Materios uses the Partner Chains governance model anchored on Cardano:

- **Governance UTXO:** One-time, irreversible genesis on Cardano mainchain
- **D-parameter:** Controls permissioned vs registered validator ratio
- **Migration plan:** `(3,0)` fully permissioned -> `(0,N)` fully decentralized

See [docs/GOVERNANCE.md](docs/GOVERNANCE.md) for initialization procedures and the D-parameter migration roadmap.

---

## Security

- **RPC lockdown:** `--rpc-methods safe` blocks admin/author methods on public-facing nodes
- **No slashing:** Offline validators miss rewards but are not penalized
- **Permissionless attestation:** Anyone can join via `join_committee`, with per-era reward caps to prevent drain
- **Content validation:** Schema-driven, AST-based expression evaluation (no `eval()`)
- **Path traversal protection:** All file:// and local manifest paths are normalized and prefix-checked

---

## Contributing

Materios is newly open-source and we're actively looking for feedback from developers, security researchers, and anyone interested in verifiable gaming and on-chain attestation.

**Ways to get involved:**

- **Found a bug or vulnerability?** [Open an issue](https://github.com/Flux-Point-Studios/materios/issues) — security reports are especially appreciated
- **Have a game you want to integrate?** Check the [Game Integration Guide](https://docs.fluxpointstudios.com/materios-partner-chain/game-integration) and open a PR to add your schema to `cert-daemon/schemas/registry.json`
- **Want to improve the pallets?** The pallet weights are hand-estimated (not benchmarked), player signatures aren't verified on-chain yet, and there's room for gas optimization — PRs welcome
- **Run an attestor node** and help secure the network — takes 1 minute, no approval needed (see [Becoming an Operator](#becoming-an-operator))
- **Questions or ideas?** Join us in the [Flux Point Studios Discord](https://discord.gg/MfYUMnfrJM) (#materios channel)

For significant changes, please open an issue first to discuss the approach.

---

## License

This project is licensed under the Apache License 2.0. See the source files for details.
