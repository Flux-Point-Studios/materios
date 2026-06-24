# Lean yaci-store deployment for the Materios Ariadne follower

The validation pilot runs the `applications/all` build (every store, pruning off,
`-Xmx9g`) for byte-diff parity — that's **53 GB**. This is the **deployment**
config: only the stores the follower reads, with safe pruning.

**Honest footprint (measured on the preprod pilot): ~23–25 GB** — roughly db-sync
parity (27 GB), NOT a dramatic disk win. The irreducible floor is `transaction`
(8.7 G) + `block` (6.3 G) + inline datums (4.3 G) + pruned `address_utxo`
(18 G → ~3.6 G). The genuine wins are **operational** (5 fewer stores), **RAM**
(Tier-2 drops the `adapot` reward-replay — the heap hog — for a far smaller `-Xmx`
than db-sync needs), and **trustless stake** (Tier-2). The big *disk* win is a
mainnet story (db-sync ~1 TB), not preprod.

## What the follower actually reads (validated against the crate's SQL)

`address_utxo` (with `inline_datum` / `amounts` / `owner_addr` denormalized onto the
row — there is no standalone `datum` table query), `tx_input`, `block`, `epoch_nonce`,
`transaction`, `epoch_stake`. Everything else (`assets`, `transaction_scripts`,
`transaction_metadata`, `script`, governance) is dead weight. `epoch_stake` is the one
input Mithril replaces (Tier 2 below).

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
store.transaction.save-cbor=false      # already default false on beta3 (no tx-CBOR column to drop)
store.transaction.save-witness=false   # already default false on beta3

# --- drop everything the follower never queries ---
store.assets.enabled=false
store.script.enabled=false
store.metadata.enabled=false
store.governance.enabled=false
store.epoch-aggr.enabled=false

# --- PRUNING (utxo — the only real disk lever) ---
# Keep all UNSPENT utxos + everything spent within k=2160 blocks (the follower's
# as-of-stable-block depth). Spent-deeper-than-k is never queried → pruned from
# BOTH address_utxo and tx_input. Measured on preprod: ~80% of address_utxo rows
# prune (18 G → ~3.6 G). transaction/block/inline-datums stay (irreducible ~19 G).
store.utxo.pruning-enabled=true
store.utxo.pruning-safe-blocks=2160
store.utxo.pruning.interval=600
store.utxo.pruning-batch-size=3000
# NB: block/tx CBOR pruning is a NO-OP on beta3 (saveCbor/saveWitness default false
# → no CBOR columns exist to prune). Deliberately omitted.

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

- **RAM floor is cardano-node (~4–8 GB on preprod), not the follower.** On preprod the
  follower DISK is ~parity with db-sync; the follower-side win is RAM (Tier-2 drops the
  adapot reward-replay → a much smaller heap than db-sync's appetite) + trustless stake.
  A 4 GB box still won't self-host (cardano-node floor) — it needs a *remote/shared*
  follower (trading some trustlessness).
- The **~23–25 GB** figure is from the pilot's per-table breakdown + the measured pruning
  ratio (~80% of `address_utxo` prunes). The store-disable safety is **validated** (no
  cross-store dependency starves a follower table — every store is independently
  `@ConditionalOnProperty`-gated; `address_utxo` denormalizes amounts/inline_datum/owner_addr
  onto the row). A first real lean sync confirms the exact GB end-to-end (run the
  16-test suite against it).
- MAINNET: revert `get_epoch_of_data_storage` to `epoch − 2` (see NOTES.md); the disk
  win is far larger there (db-sync ~1 TB → lean yaci ~150–300 GB).
