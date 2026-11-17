# Materios — Operations Runbook

> The Cardano setup uses the upstream partner-chains v1.8.0 `smart-contracts`
> commands; `materios-node` has no wizards. See [GOVERNANCE.md](GOVERNANCE.md).

## Prerequisites

| Requirement       | Details                                                        |
|-------------------|----------------------------------------------------------------|
| Docker            | 24+ with Docker Compose v2                                     |
| Disk space        | 100 GB+ free (cardano-node chain data + DB Sync PostgreSQL)    |
| Memory            | 16 GB minimum (cardano-node is memory-intensive)               |
| Network           | Stable connection; initial sync downloads the full Cardano chain |
| materios-node     | Built from source (`cargo build --release -p materios-node`)   |

> **Sync time warning:** A full `cardano-node` sync from genesis takes 12-48 hours depending on hardware and network conditions. DB Sync must also catch up to chain tip after `cardano-node` is synced. Plan accordingly and do not proceed past Step 0 until sync is complete.

---

## Step 0: Start Infrastructure and Wait for Sync

```bash
docker compose up -d
```

This starts:
- `cardano-node` (testnet or mainnet, per your `.env` config)
- `postgres` (DB Sync backend)
- `cardano-db-sync` (indexes chain data into PostgreSQL)

### Gate: Confirm DB Sync Is at Chain Tip

```bash
# Check cardano-node sync progress
docker compose exec cardano-node cardano-cli query tip --testnet-magic 1

# Check DB Sync block height matches
docker compose exec postgres psql -U materios -d dbsync -c \
  "SELECT block_no, slot_no FROM block ORDER BY id DESC LIMIT 1;"
```

**Do not proceed until DB Sync's block height matches `cardano-node`'s tip.** Registering on-chain state before sync is complete will fail or produce inconsistent results.

---

## Steps 1-4: Keys, Governance, D-Parameter and Chain Spec

Follow the [GOVERNANCE.md](GOVERNANCE.md) initialization procedure, steps 1
to 5: each authority generates its partner-chain, aura and grandpa keys on
its own machine; `partner-chains-node smart-contracts` initializes governance
(spending the genesis UTXO, which cannot be undone) and publishes the
D-parameter and the permissioned candidates; and `materios-node build-spec`
writes the chain spec from the launch manifest
([MAINNET-GENESIS.md](MAINNET-GENESIS.md)).

---

## Step 5: Wait Two Cardano Epochs

After main-chain registration, the partner chain becomes active **two full Cardano epochs later** (each epoch is ~5 days on mainnet, shorter on testnet).

```bash
# Monitor epoch transitions
watch -n 60 'docker compose exec cardano-node \
  cardano-cli query tip --testnet-magic 1 | jq .epoch'
```

**Do not start the node before the registration epoch has been finalized.** The node will fail to validate its own authority set if started too early.

---

## Step 6: Start the Node

```bash
materios-node --chain mainnet-raw.json --base-path /data/materios --validator --name "materios-validator-1"
```

The node begins:
- Producing blocks (if selected as a block producer)
- Syncing with other partner chain nodes
- Listening for cross-chain events from Cardano

Logs stream to stdout by default. Use `--log-level debug` for troubleshooting.

---

## Step 7: Verify

### 7a. Check Node Health

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method":"system_health", "params":[]}' \
  http://localhost:9944 | jq .
```

Expected: `"isSyncing": false`, `"peers": <N>` (N >= 1 if multi-node).

### 7b. Submit a Test Receipt

```bash
# Using the receipt-builder CLI (once built)
receipt-builder submit \
  --input test-data/sample.jsonl \
  --endpoint ws://localhost:9944
```

### 7c. Query the Receipt Back

```bash
curl -s -H "Content-Type: application/json" \
  -d '{
    "id":1, "jsonrpc":"2.0",
    "method":"state_getStorage",
    "params":["<content_hash_storage_key>"]
  }' \
  http://localhost:9944 | jq .
```

If the response contains the receipt commitment, the pipeline is working end-to-end.

---

## Testing MOTRA on Dev Chain

This section covers how to verify the two-token model (MATRA/MOTRA) is functioning correctly on a local dev chain.

### Prerequisites

- Dev node running:
  ```bash
  ./target/release/materios-node --dev
  ```
- The dev chain pre-funds Alice and other test accounts with MATRA at genesis

### Verify MOTRA Parameters

Query the current MOTRA configuration (generation rate, decay rate, congestion rate, etc.):

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"motra_getParams","params":[],"id":1}' \
  http://localhost:9944 | jq
```

This returns the active parameters including `generation_per_matra_per_block`, `decay_rate_per_block`, `min_fee`, and the current `congestion_rate`.

### Check MOTRA Balance

Query the MOTRA balance for a specific account (example: Alice):

```bash
# Query balance for Alice (5GrwvaEF... in SS58)
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"motra_getBalance","params":["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"],"id":1}' \
  http://localhost:9944 | jq
```

The returned balance reflects lazy reconciliation — it is computed as of the current block, accounting for all pending generation and decay since the last on-chain interaction.

### Estimate Fee

Estimate the paid-call MOTRA fee from its call weight. The RPC adds the signed
base automatically; do not add it to the input. It has no signer/call identity,
so this generic quote does not describe a validated feeless committee duty.
The quote uses zero encoded length; add the configured per-byte charge for the
actual signed extrinsic.

```bash
# Estimate fee for a transaction with 50M ref_time weight
curl -s -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"motra_estimateFee","params":[50000000],"id":1}' \
  http://localhost:9944 | jq
```

### Full Test Flow

1. **Start dev node** — Alice is pre-funded with MATRA at genesis
2. **Wait a few blocks** for MOTRA generation to accrue (each block generates MOTRA proportional to MATRA holdings)
3. **Submit a receipt extrinsic** — observe that MOTRA balance decreases by the fee amount
4. **Query the receipt** to verify it was stored on-chain
5. **Check MOTRA total issued** via `motra_totalIssued`:
   ```bash
   curl -s -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"motra_totalIssued","params":[],"id":1}' \
     http://localhost:9944 | jq
   ```

### Observing Fee Payment

- A newly funded account starts with zero generated MOTRA. For immediate first
  fees, fund it with MATRA, have a sponsor call `set_delegatee(Some(account))`,
  then have the sponsor reconcile after generation accrues. `Delegatees` routes
  that new generation to the account; existing sponsor MOTRA is not transferred.
  Alternatively, wait until the account's own post-funding accrual covers its fee.
- Nonzero MATRA top-ups enter the earning base at reconciliation. Claim before
  moving MATRA to realize the completed holding interval. On the upgrade that adds
  holding checkpoints, unchanged legacy balances begin earning from the upgrade block;
  unproven historical generation is discarded, while stored MOTRA and delegation remain.
- On a dev chain with block time ~6s and default generation rate, accounts accumulate MOTRA quickly.
- Use `motra_getParams` to see the current congestion rate — it should be 0 (or near-zero) on an empty dev chain since block fullness is well below the 50% target.
- To test congestion-based fee increases, submit many transactions in rapid succession to fill blocks above the target threshold.

---

## Preprod Deployment

This section covers deploying Materios to Cardano preprod with the upstream partner-chains `smart-contracts` commands. For detailed governance and D-parameter documentation, see [GOVERNANCE.md](GOVERNANCE.md).

### Prerequisites Checklist

Before starting the preprod deployment, confirm all of the following:

- [ ] `materios-node` binary built: `cargo build --release -p materios-node`
- [ ] Docker 24+ and Docker Compose v2 installed
- [ ] Environment variables configured (see [materios-ops](https://github.com/Flux-Point-Studios/materios-ops) private repo for templates)
- [ ] At least 100 GB free disk space for Cardano chain data
- [ ] At least 16 GB RAM available
- [ ] Funded Cardano preprod wallet (for genesis UTXO and registration transactions)
- [ ] Genesis UTXO identified and unspent on preprod

### Automated Boot (Recommended)

The `preprod-boot.sh` script orchestrates the full flow:

```bash
# From the materios-ops private repo:
bash preprod-boot.sh
```

This runs Steps 0-6 below in sequence, pausing for confirmation before the irreversible mainchain setup step.

### Manual Step-by-Step

#### Step 0: Start Infrastructure and Wait for Sync

```bash
docker compose up -d
```

Wait for Cardano DB Sync to reach chain tip. This takes **12-48 hours** on first sync. Monitor progress via the DB Sync logs.

#### Steps 1-4: Keys, Governance and D-Parameter

As in [GOVERNANCE.md](GOVERNANCE.md), steps 1 to 4, on Cardano preprod: the
preprod chain spec is built into the node (`--chain preprod`), so step 5
does not apply.

#### Step 5: Wait Two Cardano Epochs

On preprod, each epoch is ~1 day, so wait **~2 days** for the registration to finalize.

```bash
watch -n 60 'docker compose exec cardano-node \
  cardano-cli query tip --testnet-magic 1 | jq .epoch'
```

#### Step 6: Start the Node

With the preprod chain spec:

```bash
materios-node \
  --chain preprod \
  --base-path /data/materios \
  --validator \
  --name "materios-validator-1"
```

#### Step 7: Verify

```bash
# Health check
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' | jq

# Sync state
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_syncState","params":[],"id":1}' | jq
```

### Expected Timelines

| Phase                          | Duration (Preprod) | Duration (Mainnet) |
|--------------------------------|--------------------|--------------------|
| Initial Cardano sync           | 12-48 hours        | 12-48 hours        |
| Key generation + configuration | 15-30 minutes      | 15-30 minutes      |
| Epoch wait after registration  | ~2 days            | ~10 days           |
| First block production         | Minutes after node start | Minutes after node start |

### Monitoring Checklist

After the node is running, verify these on a regular basis:

- [ ] **Block height advancing**: `system_syncState` shows increasing `currentBlock`
- [ ] **Peer connections**: `system_health` shows `peers >= 1` (for multi-node setups)
- [ ] **Not syncing**: `system_health` shows `isSyncing: false` once caught up
- [ ] **MOTRA parameters active**: `motra_getParams` returns expected configuration
- [ ] **DB Sync at tip**: Cardano DB Sync block height matches `cardano-node` tip
- [ ] **Finalization progressing**: Block finalization is not stalled (check GRANDPA logs)
- [ ] **Disk space**: Monitor free disk on Cardano data volume and partner chain base path

### Rollback Procedure

If genesis setup fails or produces an inconsistent state:

1. **Stop all services**: `docker compose down` and stop the partner chain node
2. **Purge partner chain data**: `materios-node purge-chain --chain preprod -y`
3. **Identify a new genesis UTXO** on Cardano preprod (the original one is spent)
4. **Re-run the full flow** from Step 0 with the new UTXO
5. **If DB Sync is corrupted**: remove the PostgreSQL volume (`docker volume rm ops_postgres-data`) and re-sync from scratch

Note: On preprod, re-syncing Cardano from scratch is feasible (12-48h). On mainnet, consider restoring from a DB Sync snapshot instead.

---

## Troubleshooting

### Node fails to start with "authority not found"

- Confirm you waited the full two Cardano epochs after Step 4.
- Verify the registration transaction landed on-chain: check DB Sync for your governance address.

### DB Sync is stuck or behind

```bash
docker compose logs --tail 100 cardano-db-sync
```

Common causes:
- PostgreSQL out of disk space
- `cardano-node` socket not mounted correctly
- Schema migration needed after toolkit upgrade

### Node produces blocks but they are not finalized

- Check that GRANDPA keys were correctly inserted into the keystore (Step 1).
- Ensure at least 2/3 of validators are online and reachable.
- Review GRANDPA voter logs: `--log-level grandpa=debug`.

### "Duplicate receipt" error on submission

This is expected if the same `content_hash` was already submitted. The pallet rejects duplicates by design. Use a fresh input or check the existing receipt with the content hash index.

### High memory usage from cardano-node

`cardano-node` routinely uses 8-12 GB of RAM. This is normal. If the system is swapping, increase available memory or reduce other workloads on the host.

### Connection refused on port 9944

- Verify the node is running: `docker compose ps` or `ps aux | grep materios-node`
- Check that `--rpc-port 9944` and `--rpc-external` flags are set.
- Firewall rules may be blocking the port.
