# Lean yaci-store deployment for the Materios Ariadne follower

The validation pilot runs the `applications/all` build (every store, pruning off,
`-Xmx9g`) for byte-diff parity — that's **53 GB**, *heavier* than db-sync's 27 GB.
This is the **deployment** config: only the stores the follower actually reads,
with safe pruning. Target footprint **~8–15 GB** (preprod), well under db-sync.

## What the follower actually reads (validated against the crate's SQL)

`address_utxo`, `tx_input`, `datum`, `block`, `epoch_nonce`, `transaction`
(metadata columns only), `epoch_stake`. Everything else (`assets`,
`transaction_scripts`, `transaction_metadata`, `script`, governance) is dead weight.
`epoch_stake` is the one input Mithril replaces (Tier 2 below).

## `application.properties` (lean core)

```properties
# Cardano node (n2n) + Postgres — unchanged from your pilot
store.cardano.host=<cardano-relay>
store.cardano.port=3001
store.cardano.protocol-magic=1
spring.datasource.url=jdbc:postgresql://<pg>:5432/yaci_store?currentSchema=public

# --- enable ONLY the follower's stores ---
store.utxo.enabled=true
store.blocks.enabled=true
store.epoch.enabled=true
store.epoch-nonce.enabled=true
store.transaction.enabled=true
store.transaction.save-cbor=false      # default false; keeps tx metadata, drops the CBOR body (the bulk)
store.transaction.save-witness=false   # default false

# --- drop everything the follower never queries ---
store.assets.enabled=false
store.script.enabled=false
store.metadata.enabled=false
store.governance.enabled=false
store.epoch-aggr.enabled=false

# --- PRUNING: the disk win ---
# Keep all UNSPENT utxos + everything spent within k=2160 blocks (the follower's
# as-of-stable-block depth). Spent-deeper-than-k is never queried → pruned.
store.utxo.pruning-enabled=true
store.utxo.pruning-safe-blocks=2160
store.utxo.pruning.interval=600
store.utxo.pruning-batch-size=3000
# Block CBOR: retain ~recent, prune old bodies (headers stay).
store.blocks.cbor-pruning-enabled=true
store.blocks.cbor-retention-slots=43200

store.auto-index-management=true
```

## Stake input — pick a tier

### Tier 1 — self-contained (no Mithril; `application-ledger-state.properties`)
Keeps `adapot` to materialize `epoch_stake` locally. Correct today, but `adapot`
is the heaviest/most-RAM-hungry module (the reward replay).
```properties
store.account.enabled=true
store.account.stake-address-balance-enabled=true
store.adapot.enabled=true
store.adapot.epoch-stake-pruning-enabled=true   # prune stale epoch-stake snapshots
store.governance-aggr.enabled=false
```

### Tier 2 — Mithril stake (#370) — the lightest + trustless — IMPLEMENTED
Drop the `ledger-state` profile entirely (no `adapot`, no `account`): the follower's
`get_stake_distribution` reads a **Mithril-certified** per-pool stake distribution
instead of `epoch_stake`. Removes the reward-calc RAM, `stake_address_balance`, and
the trust-in-the-local-DB assumption. Built behind the `mithril-stake` cargo
feature (off → yaci `epoch_stake`; on → Mithril). The Tier-2 yaci profile drops
the stake stores entirely:
```properties
# Tier-2: NO ledger-state profile. epoch_stake is supplied by Mithril, so
# adapot/account stay OFF — this is the heaviest module you no longer pay for.
store.account.enabled=false
store.adapot.enabled=false
```
Enable + configure (see NOTES.md "Mithril-stake seam" for full detail):
```bash
# build with the feature
cargo build -p yaci-follower --features "block-source,candidate-source,native-token,mc-hash,sidechain-rpc,mithril-stake"
# node runtime env (preprod)
export MITHRIL_AGGREGATOR_ENDPOINT="https://aggregator.release-preprod.api.mithril.network/aggregator"
export MITHRIL_GENESIS_VERIFICATION_KEY=$(curl -fsSL https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)
export MITHRIL_CLIENT_BIN=/path/to/mithril-client   # pinned binary (distribution 2617.0+)
```
Mainnet: swap to `release-mainnet` aggregator + vkey (magic 764824073).
**Epoch alignment (locked):** Mithril epoch N == db-sync `epoch_no` / yaci
`active_epoch` N+2 — proven byte-identical per-pool + total on two preprod pairs.
**Retention caveat:** the aggregator keeps ~20 epochs of stake distributions; an
epoch older than the window must fall back to the yaci `epoch_stake` path.

## Required index (the tip-tracking fix)

yaci-store ships no index on `address_utxo(owner_addr)`, so the per-block candidate
query is a parallel seq-scan (~15 s/block — a node can't track tip). Add it:
```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_address_utxo_owner_addr ON address_utxo (owner_addr);
```
Measured: query plan 1,915,173 → 3,652 (~525×). (db-sync has the analogous gap on
`tx_out(address)` — a known partner-chains follower footgun. Worth upstreaming to Bloxbean.)

## Wire the materios-node onto yaci

```bash
MAIN_CHAIN_FOLLOWER=yaci
YACI_DATABASE_URL=postgres://<user>:<pw>@<yaci-pg>:5432/yaci_store
# node features: block-source,candidate-source,native-token,mc-hash,sidechain-rpc
```
(The committed wiring needs the metrics-type fix in `node/src/main_chain_follower.rs`
to compile — see #442.)

## Honest caveats

- **RAM floor is cardano-node (~4–8 GB on preprod), not the follower.** yaci-lean
  cuts the *follower's* footprint (disk a lot, RAM some) vs db-sync's 16 GB+, so a
  **trustless** SPO is viable on ~8 GB instead of 16 GB+ — but not on 4 GB. A 4 GB box
  only works with a *remote/shared* follower (trading some trustlessness).
- The ~8–15 GB target is computed from the pilot's per-table breakdown + the pruning
  math; **the first real lean sync confirms the exact number** (and validates that the
  disabled stores don't break any follower query — run the 16-test suite against it).
- MAINNET: revert `get_epoch_of_data_storage` to `epoch − 2` (see NOTES.md); the disk
  win is far larger there (db-sync ~1 TB → lean yaci ~150–300 GB).
