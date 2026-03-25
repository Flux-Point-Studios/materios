# How to Verify Materios Receipts

This guide explains how to independently verify that a data receipt submitted to
the Materios chain has been certified for data availability and checkpointed to
the Cardano blockchain.

---

## Table of Contents

1. [Overview](#overview)
2. [Trust Model](#trust-model)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Step-by-Step Verification](#step-by-step-verification)
6. [Demo Trace](#demo-trace)
7. [Verifying the Cardano Anchor Independently](#verifying-the-cardano-anchor-independently)
8. [Trust Assumptions and Limitations](#trust-assumptions-and-limitations)
9. [Glossary](#glossary)

---

## Overview

Materios is a Substrate-based chain that issues **availability certificates**
for data receipts. When a data producer submits a receipt to the chain, a
committee of independent attesters verifies that the underlying data is
retrievable, intact, and matches the declared hashes. Once enough committee
members attest, the chain emits an `AvailabilityCertified` event and stores
the `cert_hash` on-chain.

Periodically, the cert daemon batches certified receipts into a SHA-256 Merkle
tree and checkpoints the root to **Cardano L1** via an anchor transaction. This
creates a publicly auditable, immutable record linking Materios certificates
back to Cardano's proof-of-stake finality.

The verification tool (`scripts/verify.py`) lets anyone with RPC access to a
Materios node reconstruct this entire chain of custody and confirm that a
receipt is genuine.

### What the Verification Proves

Given a receipt ID, a successful verification confirms:

1. **The receipt exists on-chain** -- it was submitted via `orinqReceipts.submitReceipt`
   and is stored in the `OrinqReceipts.Receipts` storage map.
2. **The availability certificate was issued** -- the receipt's `availability_cert_hash`
   is non-zero, meaning the attestation threshold was met.
3. **The checkpoint leaf is correctly bound** -- the leaf hash
   `SHA256("materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)` can be
   recomputed from public data alone.
4. **An anchor exists on-chain** -- the Merkle root (or the leaf hash for single-leaf
   batches) is recorded in an `AnchorSubmitted` event, linking the batch to a Cardano
   L1 transaction.
5. **The certification event is consistent** -- the `AvailabilityCertified` event's
   `cert_hash` matches the value stored in the receipt record.

---

## Trust Model

### Parties Involved

| Party | Role |
|---|---|
| **Data Producer** | Submits a receipt containing content hashes, schema hash, storage locator, and other metadata via `orinqReceipts.submitReceipt`. |
| **Committee Members** | Independent attesters (e.g., Alice, Bob) who each fetch the data, verify chunk hashes, reconstruct the Merkle root, and call `attest_availability_cert` on-chain. |
| **Materios Chain** | Substrate runtime that stores receipts, tracks attestation progress, enforces the threshold, and emits `AvailabilityCertified` when enough attestations arrive. |
| **Cert Daemon** | Off-chain daemon that automates the attestation workflow: poll for new receipts, fetch and verify blobs, build dCBOR certificates, submit attestations, and batch checkpoints to Cardano. |
| **Cardano L1** | Settlement layer where checkpoint Merkle roots are anchored via transactions, providing public, immutable finality. |
| **Verifier (You)** | Anyone with RPC access to a Materios node who runs `verify.py` to independently reconstruct the proof chain. |

### Attestation Threshold

The committee has a configurable **threshold** (currently 2-of-2). An
availability certificate is only issued when the number of independent
attestations meets or exceeds the threshold. Each attester independently
verifies the data before attesting -- they do not coordinate or share results.

### Attestation Levels

Each attester performs a tiered verification of the underlying data:

| Level | Name | Meaning |
|---|---|---|
| L1 | `FETCHED` | Data chunks were retrievable from storage. |
| L2 | `HASH_VERIFIED` | Every chunk's SHA-256 hash matches the declared hash. |
| L3 | `ROOT_VERIFIED` | The Merkle root computed from all chunk hashes matches the on-chain `base_root_sha256`. |

Attestation only proceeds if verification reaches at least L2
(`HASH_VERIFIED`). L3 (`ROOT_VERIFIED`) provides the strongest guarantee.

---

## Prerequisites

### Software

- **Python 3.10+**
- **substrate-interface** (Python library for Substrate RPC):
  ```bash
  pip install substrate-interface>=1.7.0
  ```

### Network Access

You need WebSocket RPC access to a Materios node. Options:

| Method | URL |
|---|---|
| Local node | `ws://127.0.0.1:9944` (default) |
| Public endpoint | Check the Materios documentation for public RPC URLs |

### What You Need

- A **receipt ID** (64-character hex string, optionally 0x-prefixed) from a
  receipt that was submitted to the Materios chain.

---

## Quick Start

```bash
# Clone the repo (or just grab the verify.py script)
git clone https://github.com/Flux-Point-Studios/materios-cert-daemon.git
cd materios-cert-daemon

# Install the dependency
pip install substrate-interface

# Run verification against a Materios node
python3 scripts/verify.py <receipt_id> --rpc-url ws://127.0.0.1:9944
```

### Examples

```bash
# Basic verification (uses default RPC URL or $MATERIOS_RPC_URL)
python3 scripts/verify.py 0x7a3f...e91b

# Point at a specific node
python3 scripts/verify.py 0x7a3f...e91b --rpc-url wss://materios.fluxpointstudios.com/rpc

# Verbose mode -- shows all receipt fields and the raw hash preimage
python3 scripts/verify.py 0x7a3f...e91b --verbose

# Wider scan window (default is 500 blocks; increase if the receipt is old)
python3 scripts/verify.py 0x7a3f...e91b --scan-window 5000

# Check pending checkpoint batch status (daemon operator only)
python3 scripts/verify.py 0x7a3f...e91b --checkpoint-state /data/checkpoint-state.json

# Pipe-friendly output (no ANSI colors)
python3 scripts/verify.py 0x7a3f...e91b --no-color
```

### Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `MATERIOS_RPC_URL` | WebSocket RPC URL for the Materios node | `ws://127.0.0.1:9944` |
| `CHAIN_ID` | Override genesis hash (normally auto-detected) | _(auto)_ |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | All verification steps passed (`VERIFIED`) |
| `1` | One or more steps failed, or receipt/cert not found |

---

## Step-by-Step Verification

The verifier runs six stages (0 through 5). Here is what each one does and what
it proves.

### Step 0: Connect to the Materios chain

```
[0/5] Connecting to Materios chain
```

The tool opens a WebSocket connection to the Materios Substrate node and reads
the chain name, runtime version, and genesis hash. The genesis hash serves as
the **chain ID** -- a unique identifier that binds all checkpoint leaves to this
specific chain instance, preventing cross-chain replay.

**What it proves:** You are connected to a live Materios node and can query
its state.

### Step 1: Query the on-chain receipt

```
[1/5] Querying on-chain receipt
```

Reads the `OrinqReceipts.Receipts` storage map for the given receipt ID. The
receipt record contains:

| Field | Description |
|---|---|
| `content_hash` | SHA-256 of the full data payload |
| `base_root_sha256` | Merkle root of all data chunks |
| `schema_hash` | Hash of the data schema |
| `storage_locator_hash` | Hash of the storage location descriptor |
| `base_manifest_hash` | Hash of the chunk manifest |
| `safety_manifest_hash` | Hash of the safety/compliance manifest |
| `monitor_config_hash` | Hash of the monitoring configuration |
| `attestation_evidence_hash` | Hash of attestation evidence data |
| `availability_cert_hash` | The certificate hash (zero if not yet certified) |
| `submitter` | Account that submitted the receipt |
| `created_at_millis` | Submission timestamp (milliseconds) |

**What it proves:** The receipt was submitted to the chain and its metadata is
permanently recorded in on-chain storage.

### Step 2: Check the availability certificate

```
[2/5] Checking availability certificate
```

Checks whether `availability_cert_hash` is non-zero. A zero hash means the
attestation threshold has not yet been met. When non-zero, it means at least
`threshold` committee members independently verified the data and attested.

If the cert hash is zero, the tool also checks the `OrinqReceipts.Attestations`
storage to show how many attestations have been collected so far (e.g.,
"1/2 signatures collected").

**What it proves:** The data availability committee has reached consensus that
the receipt's data is available and intact.

### Step 3: Compute the checkpoint leaf hash

```
[3/5] Computing checkpoint leaf hash
```

Recomputes the checkpoint leaf using the binding formula:

```
leaf = SHA256("materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)
```

Where:
- `"materios-checkpoint-v1"` is a 22-byte domain separator that prevents hash
  collisions with other protocols.
- `chain_id` is the 32-byte genesis hash of the Materios chain.
- `receipt_id` is the 32-byte receipt identifier.
- `cert_hash` is the 32-byte availability certificate hash from step 2.

The concatenation is 118 bytes total: 22 + 32 + 32 + 32.

In `--verbose` mode, the tool also prints the raw hex preimage so you can
verify the hash independently with any SHA-256 tool:

```bash
echo -n "<preimage_hex>" | xxd -r -p | sha256sum
```

**What it proves:** The leaf hash deterministically binds this specific receipt
on this specific chain to its certificate. No one can substitute a different
receipt, chain, or cert hash and produce the same leaf.

### Step 4: Search for the checkpoint anchor

```
[4/5] Searching for checkpoint anchor
```

Scans recent blocks (default: last 500) for `AnchorSubmitted` events. For each
anchor found, the tool queries the `OrinqReceipts.Anchors` storage map and
compares the anchor's `root_hash` to the computed leaf hash.

For single-leaf batches, `root_hash == leaf_hash` (exact match). For multi-leaf
batches, the root is a Merkle tree computed from all leaves in the batch. The
tree uses standard SHA-256 binary Merkle construction:

- Odd number of leaves: duplicate the last leaf.
- Pair nodes: `H(left || right)`.
- Repeat until a single root remains.

**What it proves:** The receipt's certification has been committed to the
Materios chain's anchor storage, and (for single-leaf batches) the anchor root
directly matches the computed leaf. The anchor's `content_hash` is then
checkpointed to Cardano L1.

### Step 5: Locate the AvailabilityCertified event

```
[5/5] Locating AvailabilityCertified event on chain
```

Scans the same block range for the `AvailabilityCertified` event matching this
receipt ID. When found, the event's `cert_hash` is compared to the on-chain
receipt's `availability_cert_hash` to confirm consistency.

This step is supplementary -- the on-chain storage is authoritative. But
confirming the event exists provides an additional cross-check that the state
transition was recorded correctly.

**What it proves:** The runtime emitted the expected event at the time the
threshold was met, and the event data is consistent with the current on-chain
state.

---

## Demo Trace

Below is what a successful verification looks like. Receipt ID and hashes are
realistic placeholders.

```
$ python3 scripts/verify.py 0x7a3f8c1d5e2b09a4f6d7e8c3b1a0f5d4e9c2b7a6f8d1e3c5b9a4f2d7e08e91b \
    --rpc-url wss://materios.fluxpointstudios.com/rpc

=== Materios Checkpoint Verifier ===
  Receipt ID : 0x7a3f8c1d5e2b09a4f6d7e8c3b1a0f5d4e9c2b7a6f8d1e3c5b9a4f2d7e08e91b
  RPC URL    : wss://materios.fluxpointstudios.com/rpc

[0/5] Connecting to Materios chain
  PASS  Connected to 'Materios', runtime v102
  INFO  Chain ID (genesis): 0xb3a1f7c9e2d45b...
  INFO  Best block: #28417

[1/5] Querying on-chain receipt
  PASS  Receipt exists on chain

[2/5] Checking availability certificate
  PASS  Availability cert hash: 0xd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6
  INFO  Committee: 2 members, threshold=2

[3/5] Computing checkpoint leaf hash
  PASS  Leaf binding: SHA256("materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)
  INFO  Domain tag    : b"materios-checkpoint-v1" (22 bytes)
  INFO  Chain ID      : 0xb3a1f7c9e2d45b... (32 bytes)
  INFO  Receipt ID    : 0x7a3f8c1d5e2b09... (32 bytes)
  INFO  Cert hash     : 0xd4e5f6a7b8c9d0... (32 bytes)
  PASS  Leaf hash     : 0x9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a

[4/5] Searching for checkpoint anchor
  INFO  Scanning blocks #27917 to #28417 for AnchorSubmitted events...
  INFO  Found 3 anchor(s) in scan range
  PASS  Checkpoint anchor found!
  INFO  Anchor ID     : 42
  INFO  Root hash     : 0x9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
  INFO  Content hash  : 0x9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
  INFO  Manifest hash : 0xa8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7
  INFO  Block          : #28350
  INFO  Match type    : exact (single-leaf batch)

[5/5] Locating AvailabilityCertified event on chain
  PASS  AvailabilityCertified event at block #28291 matches on-chain cert hash

=== Verification Summary ===
  Receipt ID          : 0x7a3f8c1d5e2b09a4f6d7e8c3b1a0f5d4e9c2b7a6f8d1e3c5b9a4f2d7e08e91b
  On-chain cert hash  : 0xd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6
  Checkpoint leaf     : 0x9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
  Anchor root         : 0x9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
  Anchor block        : #28350

  RESULT: VERIFIED
  Full chain of custody established:
    Receipt -> Availability Cert -> Checkpoint Leaf -> Anchor Root
```

### Partial Verification

If the receipt is certified but the checkpoint has not been flushed to Cardano
yet, you will see:

```
  RESULT: PARTIALLY VERIFIED
  Receipt and cert are valid. Checkpoint anchor not yet found.
  The checkpoint may be pending flush or in an older block range.
```

This means steps 1-3 passed but the Cardano anchor (step 4) was not found in
the scan window. The receipt is valid -- the L1 checkpoint just has not been
written yet. Wait for the next checkpoint flush (default interval: 60 minutes)
and re-run.

### Failed Verification

If the receipt does not exist or the cert hash is zero:

```
  RESULT: NOT VERIFIED
```

---

## Verifying the Cardano Anchor Independently

The cert daemon checkpoints Merkle roots to Cardano L1 by posting to an anchor
worker, which submits a transaction containing the root hash. You can verify
this independently by querying the Cardano blockchain.

### What is Checkpointed

Each checkpoint transaction includes a **manifest** in its metadata:

```json
{
  "materios_chain_id": "<genesis_hash_hex>",
  "cardano_network_id": "<cardano_genesis_hash_hex>",
  "from_block": 28100,
  "to_block": 28350,
  "count": 1,
  "root": "<merkle_root_hex>"
}
```

The `contentHash` and `rootHash` fields in the anchor payload are the Merkle
root of the batch. The `manifestHash` is `SHA256(json_manifest_sorted_keys)`.

### Querying Cardano

#### Using cardano-cli

If you have access to a Cardano node:

```bash
# Query the anchor address for transactions
docker exec cardano-relay cardano-cli query utxo \
  --address <anchor-address> \
  --mainnet --output-json
```

#### Using a Block Explorer

1. Go to [Cardanoscan](https://cardanoscan.io) or [Cexplorer](https://cexplorer.io).
2. Search for the anchor wallet address or transaction hash.
3. Inspect the transaction metadata for the checkpoint root hash.
4. Confirm the root hash matches the `Anchor root` value from `verify.py`.

#### Using Blockfrost API

```bash
# List transactions at the anchor address
curl -H "project_id: <your-blockfrost-key>" \
  "https://cardano-mainnet.blockfrost.io/api/v0/addresses/<anchor-address>/transactions"

# Get transaction metadata
curl -H "project_id: <your-blockfrost-key>" \
  "https://cardano-mainnet.blockfrost.io/api/v0/txs/<tx_hash>/metadata"
```

### Cross-Referencing

To fully close the loop:

1. Run `verify.py` and note the **Anchor root** hash.
2. Find the corresponding Cardano transaction (by timestamp, anchor address, or
   metadata search).
3. Extract the root hash from the transaction metadata.
4. Confirm the Cardano root hash matches the Materios anchor root hash.

If they match, you have a complete proof chain from the original data receipt
through the Materios availability certificate all the way to Cardano L1
settlement.

---

## Trust Assumptions and Limitations

### Assumptions

1. **Honest threshold.** The verification relies on at least one honest
   committee member in the threshold set. If `threshold` out of `N` committee
   members all collude, they could attest to data that is not actually
   available. The current configuration (2-of-2) requires both attesters to be
   honest.

2. **Materios node integrity.** The RPC node you connect to must serve correct
   state. A malicious or compromised node could return forged storage values.
   Mitigation: run your own Materios node, or cross-reference multiple
   independent nodes.

3. **Cardano finality.** The Cardano checkpoint is only as final as the Cardano
   chain itself. In practice, Cardano transactions are considered irreversible
   after a few blocks (the Ouroboros protocol guarantees probabilistic finality
   within minutes).

4. **Data availability at attestation time.** The availability certificate
   proves that committee members could fetch and verify the data *at the time
   they attested*. It does not guarantee perpetual availability. The
   `retention_days` field in the certificate records the storage provider's
   retention commitment, but enforcement is out of scope for on-chain
   verification.

### Limitations

1. **Multi-leaf Merkle inclusion.** For batches containing more than one
   receipt, `verify.py` can confirm that an anchor exists but cannot prove
   Merkle inclusion without the full leaf list. The tool reports "exact
   (single-leaf batch)" for single-leaf matches. For multi-leaf batches, a
   Merkle inclusion proof (sibling hashes along the path) is needed for full
   verification. This feature is planned for a future release.

2. **Scan window.** The tool scans a fixed window of recent blocks (default:
   500) for anchor and certification events. If the receipt was certified or
   checkpointed outside this window, the events will not be found. Use
   `--scan-window N` with a larger value, or note that on-chain storage
   (steps 1-3) is still authoritative even if the event scan misses.

3. **K-confirmation delay.** Certified receipts are only eligible for
   checkpointing after 12 blocks of best-block growth past their inclusion
   block (~72 seconds at 6-second block times). A very recently certified
   receipt may show as `PARTIALLY VERIFIED` until the confirmation threshold
   is met and the next flush occurs.

4. **No data re-verification.** `verify.py` checks on-chain state and hashes.
   It does not re-fetch and re-verify the underlying data blobs. To verify
   data integrity yourself, you would need the blob manifest and storage
   locator to fetch each chunk and recompute the Merkle root against
   `base_root_sha256`.

5. **Clock dependency.** The `created_at_millis` and checkpoint timestamps
   depend on the block producer's clock. Substrate block timestamps can drift
   slightly from wall-clock time.

---

## Glossary

| Term | Definition |
|---|---|
| **Anchor** | An on-chain record that stores the Merkle root of a checkpoint batch. The same root is posted to Cardano L1. |
| **AnchorSubmitted** | Materios runtime event emitted when a checkpoint anchor is recorded on-chain. |
| **Attestation** | An on-chain declaration by a committee member that they have independently verified a receipt's data availability. Submitted via `attest_availability_cert`. |
| **Attestation Threshold** | The minimum number of independent attestations required before the chain issues an availability certificate. |
| **AvailabilityCertified** | Materios runtime event emitted when the attestation threshold is met for a receipt. Carries the `receipt_id` and `cert_hash`. |
| **Cert Daemon** | Off-chain service that polls the Materios chain for new receipts, verifies data blobs, builds dCBOR certificates, submits attestations, and flushes checkpoints to Cardano. |
| **Cert Hash** | `SHA-256` of the canonical CBOR (dCBOR) availability certificate. Stored on-chain in the receipt record's `availability_cert_hash` field. |
| **Chain ID** | The genesis block hash of the Materios chain. Used as a domain separator in checkpoint leaf hashes to prevent cross-chain replay. |
| **Checkpoint** | A batch of certified receipt leaf hashes organized into a Merkle tree whose root is submitted to Cardano L1. |
| **Checkpoint Leaf** | `SHA256("materios-checkpoint-v1" \|\| chain_id \|\| receipt_id \|\| cert_hash)`. A context-bound hash that uniquely ties a receipt's certification to a specific chain. |
| **Committee** | The set of accounts authorized to submit attestations. Stored in `OrinqReceipts.CommitteeMembers`. |
| **Content Hash** | SHA-256 hash of the full data payload associated with a receipt. |
| **dCBOR** | Deterministic CBOR -- a canonical encoding that ensures the same logical certificate always produces identical bytes (and therefore the same hash). |
| **Domain Separator** | The string `"materios-checkpoint-v1"` prepended to leaf hash inputs. Prevents hash collisions with other protocols using the same hash function. |
| **Finality Confirmations** | Number of blocks that must be built on top of a certified receipt's block before it becomes eligible for checkpointing (default: 12 blocks, ~72 seconds). |
| **Genesis Hash** | The hash of block 0 on the Materios chain. Uniquely identifies the chain instance and serves as the chain ID. |
| **K-Confirmation** | The model used to determine when a certified receipt is safe to checkpoint. "K" defaults to 12 blocks. |
| **Merkle Root** | The root hash of a binary SHA-256 Merkle tree. For odd leaf counts, the last leaf is duplicated before pairing. |
| **Ogmios** | A lightweight bridge that exposes Cardano node data via WebSocket/HTTP. Used by the cert daemon to query the current Cardano epoch. |
| **OrinqReceipts** | The Substrate pallet (runtime module) that manages receipts, attestations, certificates, and anchors. |
| **Receipt** | An on-chain record submitted via `orinqReceipts.submitReceipt` that declares metadata about a data payload (content hash, schema, storage locator, etc.). |
| **Receipt ID** | A 32-byte hex identifier for a receipt, used as the key in `OrinqReceipts.Receipts` storage. |
| **Root Verified (L3)** | The highest attestation level: the computed Merkle root of all data chunks matches the on-chain `base_root_sha256`. |
| **Scan Window** | The number of recent blocks that `verify.py` searches when looking for `AnchorSubmitted` and `AvailabilityCertified` events. Default: 500. |
| **Substrate** | A blockchain framework by Parity Technologies. Materios is built on Substrate. |
