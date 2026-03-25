# Materios — Architecture

## System Overview

Materios is composed of two cooperating subsystems:

1. **Partner Chain** — A Substrate-based sidechain anchored to Cardano mainnet via the Partner Chains toolkit (v1.8.1). It stores receipt commitments (content hashes, Merkle roots, attestation records) and enforces ordering, deduplication, and fee logic. The chain inherits Cardano's security through periodic cross-chain checkpointing.

2. **Midnight ZK Coprocessor** — A Compact smart contract deployed on the Midnight network. It accepts batched Merkle roots from the partner chain and produces zero-knowledge proofs that attest to batch integrity without revealing any underlying receipt content. This lets auditors verify that a set of receipts was correctly processed without accessing raw data.

### Hard Constraint

**Only commitments live on-chain.** The partner chain and Midnight contract store roots, hashes, and attestation metadata. No raw prompts, responses, or session transcripts are ever written to any chain. Full receipt bodies remain off-chain in the operator's storage, referenced by deterministic content hashes.

## Data Flow

```
JSONL file (prompts/responses/events)
        │
        ▼
 ┌──────────────┐
 │ receipt-builder│   Off-chain Rust library
 │               │   - Canonicalizes (JCS / RFC 8785)
 │               │   - Hashes canonical bytes (BEFORE compression)
 │               │   - Builds ReceiptPayload struct
 └──────┬───────┘
        │  Extrinsic: submit_receipt(payload)
        ▼
 ┌──────────────────────────┐
 │  Partner Chain Runtime    │
 │  pallet_orinq_receipts   │
 │  - Validates payload      │
 │  - Stores commitment      │
 │  - Indexes by content_hash│
 │  - Stamps runtime timestamp│
 └──────────┬───────────────┘
            │  Batch export (off-chain worker or cron)
            ▼
 ┌──────────────────────────┐
 │  Midnight Contract        │
 │  receipt-anchor (Compact) │
 │  - Receives Merkle root   │
 │  - Generates ZK proof     │
 │  - Publishes attestation  │
 └──────────────────────────┘
```

## Design Decisions

### D1: Two Identifiers

Every receipt carries two identifiers:

- **`content_hash`** — Deterministic. Derived from the canonical representation of the receipt body. The same logical content always produces the same hash. Used for deduplication and cross-system references.
- **`receipt_id`** — Unique. Includes a nonce or timestamp component so that two submissions of identical content produce distinct IDs. Used for on-chain storage keys and event correlation.

**Rationale:** Deduplication needs a stable key (content_hash), but audit trails need unique entries (receipt_id). Conflating the two leads to either missed duplicates or lost history.

### D2: Hash Canonical Bytes Before Compression

The content hash is computed over the canonical byte representation of the receipt body **before** any compression (zstd, gzip, etc.) is applied.

**Rationale:** Compression algorithms are not guaranteed to be deterministic across versions and implementations. Hashing pre-compression bytes ensures reproducibility. Compressed payloads can still be stored and transmitted, but verification always operates on the uncompressed canonical form.

### D3: RFC 8785 JCS Canonicalization

Receipt bodies are canonicalized using JSON Canonicalization Scheme (RFC 8785) before hashing.

**Rationale:** JSON serialization is non-deterministic (key order, whitespace, number formatting). JCS provides a well-specified, interoperable canonical form. It is simpler than alternatives (e.g., CBOR-based canonicalization) for a JSON-native data pipeline and has broad library support.

### D4: Poseidon Hash — Optional, Versioned, Parameter-Bound

Poseidon hashing is supported as an optional hash function alongside SHA-256/Blake2b. When used, the Poseidon parameters (width, rounds, MDS matrix) are bound to the schema version.

**Rationale:** Poseidon is ZK-friendly and dramatically reduces constraint counts inside Midnight's proof circuits. However, it is less battle-tested than SHA-256 for general use. Making it optional and version-bound lets the system start with conservative hashing and adopt Poseidon for ZK-optimized paths without breaking existing receipts.

### D5: dCBOR Availability Certificates

Availability certificates (proofs that off-chain data is stored and retrievable) are encoded using deterministic CBOR (dCBOR, RFC 8949 Core Deterministic Encoding).

**Rationale:** dCBOR is compact, deterministic by specification, and natively supported by the Cardano ecosystem. It avoids the canonicalization overhead of JSON for machine-to-machine attestation payloads.

### D6: Runtime-Sourced Timestamps

Receipt timestamps are assigned by the partner chain runtime at inclusion time, not by the submitting client.

**Rationale:** Client-supplied timestamps are untrusted. Runtime timestamps provide a consistent, monotonic ordering that all validators agree on. This is essential for audit sequencing and dispute resolution.

### D7: Content Hash Index

The pallet maintains a storage map indexed by `content_hash`, enabling O(1) lookups and duplicate detection.

**Rationale:** The most common query patterns are "does this receipt already exist?" and "retrieve the receipt for this content." A content-hash index serves both without full-table scans. The index is maintained on write and does not require background reindexing.

### D8: Schema Version Hash

Each receipt includes a `schema_version` field whose value is the hash of the schema definition itself (not a semver string).

**Rationale:** Semver is ambiguous — two schemas can both call themselves "1.0" while differing in fields. Hashing the schema definition produces a unique, verifiable identifier. Consumers can detect schema mismatches immediately and the chain can enforce that submitted receipts reference a known schema hash.

## Two-Token Economic Model

Materios uses a two-token model to separate capital ownership from network usage rights. This design avoids the common problem in single-token chains where users must sell their governance/staking token to pay transaction fees, creating constant sell pressure.

### MATRA (Capital Token)

MATRA is the native currency of the Materios Partner Chain, implemented via Substrate's `pallet_balances`.

- **Transferable** between accounts (standard balance transfers)
- **Used for:** governance deposits, validator incentives (future), ecosystem rewards (future)
- **Denomination:** 12 decimal places (1 MATRA = 10^12 smallest units)
- **Initial supply:** configurable at genesis (dev chain uses pre-funded test accounts such as Alice, Bob, etc.)

MATRA represents ownership and long-term alignment with the network. Holding MATRA does not directly pay for transactions — that role belongs to MOTRA.

### MOTRA (Capacity Token)

MOTRA is a non-transferable fee currency inspired by Midnight's DUST model.

- **Non-transferable** — cannot be sent between accounts directly
- **Generated automatically** based on an account's MATRA holdings
- **Decays over time** if unused (prevents hoarding and ensures continuous MATRA holding is necessary)
- **Can be delegated** via a sponsorship model (app developers can sponsor their users' fees)

MOTRA represents the right to use the network. Because it is non-transferable and decays, it cannot be speculated on or hoarded.

### Fee Model

Transaction fees are denominated in MOTRA, not MATRA:

```
TxFee = MinFee + (CongestionRate × Weight / 1,000,000) + (LengthFeePerByte × TxLength)
```

- **Fees paid in MOTRA (primary), not MATRA.** This avoids "gas token sell pressure" — MATRA holders are not forced to sell MATRA to pay fees.
- **CongestionRate** adjusts dynamically based on block fullness:
  - If block fullness > target (default 50%): rate increases
  - If block fullness < target: rate decreases
  - Bounded step size prevents oscillation
  - Smoothed via EMA (`congestion_smoothing`, default 10%) to prevent oscillation
- **MinFee** establishes a floor cost even when the network is idle
- **LengthFeePerByte** charges for encoded transaction size (default 1000 MOTRA-units per byte)

### Fee Destination: Permanent Burn

**Fees are permanently destroyed.** They are not redistributed to validators, a treasury, or any other account.

The burn path (`ChargeMotra` SignedExtension in `fee.rs`):

1. **Pre-dispatch** — Before an extrinsic executes, `burn_fee(who, amount)` is called
2. **Account debit** — The fee amount is subtracted from the sender's MOTRA balance
3. **Global counter** — The fee amount is added to a monotonically increasing `TotalBurned` counter
4. **Event emitted** — `FeeBurned { who, amount }` is deposited for indexers

Key properties:

- **No refunds (MVP)** — The full pre-dispatch fee is burned regardless of actual weight consumed. A future iteration could refund unused weight.
- **Failed transactions still pay** — If the extrinsic dispatches but fails (e.g., a receipt submission hits a duplicate check), the fee is still burned. The sender pays for the chain's validation effort.
- **Insufficient balance** — If an account's MOTRA balance is below the fee, the transaction is rejected at validation time (`InvalidTransaction::Payment`). The `InsufficientMotraFailures` counter is incremented for monitoring.

**Why burn instead of redistribute?**

| Alternative | Why not |
|---|---|
| Validator tips | Materios validators are permissioned infrastructure, not economic actors competing for MEV |
| Treasury fund | Adds governance complexity for an MVP chain; burn is simpler and auditable |
| Fee redistribution to MATRA holders | Would create a circular incentive (hold MATRA → earn MOTRA → pay fees → receive fees → hold MATRA) that obscures fee cost |

Burning creates clean deflationary pressure that is offset by generation. The equilibrium is self-regulating: if fees increase, MOTRA balances decrease, creating pressure to reduce on-chain activity or increase MATRA holdings (which increases generation).

### Generation, Decay & Burn Equilibrium

Three forces act on the MOTRA supply:

```
                 Generation (+)
                    ↓
    MATRA holding → MOTRA balance → Fee payment → Burn (permanent -)
                    ↓
                 Decay (-)
```

**Generation** (adds to supply):

- MOTRA is generated proportionally to an account's MATRA free balance
- Rate: `generation_per_matra_per_block` (configurable at genesis and via governance)
- Formula per block: `matra_balance * rate / 10^12`
- Generation is credited lazily — the balance is reconciled on the next interaction
- Tracked in `TotalIssued` (global cumulative counter)

**Decay** (reduces individual balances):

- Multiplicative decay applied per block
- Rate: `decay_rate_per_block` as Perbill (e.g., 999_900_000 = 99.99% retained per block)
- Applied lazily on next interaction (fee payment, claim, delegation change)
- Ensures that MOTRA balances trend toward zero without continuous MATRA holding
- Decayed amounts are subtracted from `TotalIssued` — decay is a supply contraction, not a burn

**Burn** (permanently destroys supply):

- Only triggered by fee payment (no other burn path exists)
- Tracked in `TotalBurned` (global cumulative counter, never decreases)
- `TotalBurned` is independent of `TotalIssued` — they are separate counters

**Decay vs Burn distinction:**

| | Decay | Burn |
|---|---|---|
| Trigger | Time passing (per-block) | Transaction fee payment |
| Scope | Individual account balance | Individual account + global counter |
| Reversibility | Offset by future generation | Permanent |
| Tracking | Reduces `TotalIssued` | Increases `TotalBurned` |
| Purpose | Prevents hoarding; ensures continuous MATRA holding | Gives fees real cost; deflationary pressure |

**Effective circulating supply** at any point:

```
CirculatingSupply = TotalIssued - TotalBurned
```

Both values are available via the `motra_getParams` RPC method and displayed on the explorer status page.

**Max balance cap** prevents infinite accumulation even with large MATRA holdings.

### Delegation (Sponsorship)

- Account holders can delegate their MOTRA generation to another account
- **Use case:** An app developer holds MATRA and delegates generated MOTRA to their app's fee-paying account, sponsoring user transactions
- Delegation only affects **future** generation, not existing balances
- Clear delegation with `set_delegatee(None)`
- A single account can receive delegations from multiple delegators

### Design Rationale

| Property | Purpose |
|---|---|
| Non-transferability | Prevents MOTRA markets and speculation |
| Decay | Prevents hoarding; ensures continuous MATRA holding is necessary |
| Fee burn | Gives fees real cost without redistribution complexity |
| Delegation | Enables sponsorship without transferability |
| Lazy accounting | Deterministic — same state produces same results regardless of reconciliation timing |
| Fee separation | MATRA holders never forced to sell MATRA to use the network |
| No refunds (MVP) | Simplifies fee logic; full fee is burned pre-dispatch |

## Component Descriptions

### pallet_orinq_receipts

The core Substrate pallet. Responsibilities:

- **Extrinsics:** `submit_receipt`, `submit_batch`, `revoke_receipt`
- **Storage:** Receipt commitments keyed by `receipt_id`, with a secondary index on `content_hash`
- **Validation:** Schema version check, duplicate detection, payload size limits
- **Events:** `ReceiptSubmitted`, `ReceiptRevoked`, `BatchAnchored`
- **Weights:** Benchmarked via `frame_benchmarking`; see `weights.rs`

### receipt-builder

An off-chain Rust library (no-std compatible where possible) that constructs well-formed receipt payloads. Responsibilities:

- Read JSONL input streams
- Canonicalize each record (RFC 8785 JCS)
- Compute `content_hash` over canonical bytes
- Generate unique `receipt_id`
- Assemble `ReceiptPayload` struct ready for extrinsic submission
- Optionally compute Poseidon hash for ZK-optimized paths

### Midnight Contract (receipt-anchor)

A Compact smart contract deployed to the Midnight network. Responsibilities:

- Accept a Merkle root representing a batch of receipt commitments
- Verify the root against a provided witness (proof of correct batch construction)
- Emit an attestation event that auditors can query
- Maintain a ledger of anchored roots with timestamps

The contract operates on commitments only. It never sees or processes raw receipt content.
