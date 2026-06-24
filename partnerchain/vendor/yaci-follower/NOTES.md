# yaci-follower

A third main-chain-follower backend for the Materios partner-chains node. Reads
Cardano main-chain data from a **yaci-store 3.0.0-beta3** (`applications/all`
build) Postgres instead of cardano-db-sync. Mirrors the structure and public
trait surface of `vendor/db-sync-follower` verbatim; only the SQL and the
Postgres column types differ.

## Status

Done and exercised against the live `.230` preprod pilot DB:

- **epoch nonce** — `epoch_nonce.nonce` (hex `varchar`). Proven byte-identical
  to db-sync `epoch_param.nonce`. Golden: epoch 7 ==
  `67d682b519036ae9e5d9b0e624ba3cddc4426bebebc56ba96f1287897c7f051c`.
- **epoch stake** — `epoch_stake`, filtered on **`active_epoch`** (see below).
  Golden: active_epoch 92 == 285 pools / 239 375 391 050 590 lovelace.
- **UTxO + inline datums** — `address_utxo.inline_datum` (hex CBOR `text`) +
  spend-tracking via `tx_input`. Decoded through the verbatim
  `partner-chains-plutus-data` path; D-param / registration datums ride this.
- All four `*DataSource` traits implemented and wired into the node behind
  `MAIN_CHAIN_FOLLOWER=yaci` (`node/src/main_chain_follower.rs`).

Tests: 10 pure-logic/unit tests run in CI; 5 `#[ignore]`d DB-integration tests
run against `YACI_DATABASE_URL` and all pass against the live `.230` pilot
(epoch-nonce golden, stake active_epoch-92 golden, raw-epoch off-by-two guard,
unknown-epoch-None, UTxO+datum decode). With `mithril-stake`: +7 offline unit
tests (bech32 decode, epoch-alignment lock, parse/cache) and +1 `#[ignore]`d
live golden (`mithril_stake_distribution_matches_db_sync_golden_active_epoch_297`)
that fetches a **cert-verified** Mithril SD and asserts per-pool + total parity
with db-sync `epoch_no` 297.

## The `active_epoch` convention (the #1 footgun)

yaci `epoch_stake` has BOTH `epoch` and `active_epoch`, where
`active_epoch = epoch + 2`. db-sync parity (its `epoch_no`) is against
**`active_epoch`**. `get_stake_distribution` filters `active_epoch`. Filtering
the raw `epoch` column is wrong and off by two Cardano epochs — there is a
dedicated integration test (`raw_epoch_column_does_not_match_active_epoch_golden`)
that fails if anyone "fixes" the query back onto `epoch`.

## Schema mapping vs cardano-db-sync

| input            | db-sync                          | yaci-store                                  |
|------------------|----------------------------------|---------------------------------------------|
| hashes           | `bytea`                          | lowercase hex `varchar` (`parse_hash32/28`) |
| datum CBOR       | JSONB `datum.value`              | hex `text` `inline_datum` (`DbDatum`)       |
| block time       | `timestamp`                      | unix-seconds `bigint` (`block_time_to_naive`) |
| spends           | `tx_in` join                     | `tx_input(tx_hash, output_index, spent_at_block)` |
| token at policy  | `ma_tx_out`/`multi_asset`        | `address_utxo.amounts` JSONB `policy_id`    |
| pool id          | `pool_hash.hash_raw` (`[u8;28]`) | `epoch_stake.pool_id` hex (= same 28 bytes) |

## Mithril-stake seam (#370, trustless — IMPLEMENTED behind `mithril-stake`)

`db_model::get_stake_distribution` is the seam: with the `mithril-stake` cargo
feature it reads a **Mithril-certified** per-pool stake distribution instead of
the yaci `epoch_stake` query, with **no caller change** (same
`Vec<StakePoolEntry>`). Mithril GA certifies exactly the `(pool_hash, stake)`
Ariadne snapshot — the one follower input otherwise only as trustworthy as the
local yaci-store DB. The nonce and the datum/address inputs are NOT
Mithril-certifiable, so Mithril complements (does not replace) the yaci/db-sync
follower. Enabling Tier-2 lets the deployment drop the heaviest yaci module
(`adapot`/`epoch_stake`, the reward replay) entirely.

### Client path: CLI, not the crate (decision)

We shell the pinned `mithril-client` binary (`cardano-stake-distribution
download <epoch> --json`), not the `mithril-client` Rust crate. yaci-follower is
a **member of the pinned partner-chains workspace** (`polkadot-stable2409-4`,
`sidechain-domain` v1.5.1). The crate pulls a heavy, independent crypto stack
(mithril-stm, blst, reqwest/rustls) whose resolver-2 unification would force the
node build to compile blst + mithril crypto on the live validator box — exactly
the heavy compile the SAFETY rules forbid. The CLI keeps the dep footprint to
`serde_json`, and the binary is already used by OPERATOR_KIT (#368/#369). The
certificate chain is still verified **in-process by the binary** against the
genesis vkey before any stake value is read (steps 2-3 of its output: "verifying
the certificate chain" / "Verify that the Cardano stake distribution is signed
in the associated certificate"). Verification is the whole point and is not
skipped.

### Epoch alignment — the #445-style footgun, EMPIRICALLY LOCKED

Mithril labels its stake distribution by the epoch in which the snapshot is
*taken*; that stake becomes *active* two epochs later. db-sync `epoch_no`
(== yaci `active_epoch`) is the *active* epoch. So:

```text
mithril_epoch = active_epoch - 2
```

Proven byte-identical against the .230 db-sync on two independent preprod pairs
(per-pool AND total):

| Mithril epoch | db-sync `epoch_no` | pools (non-zero) | total lovelace      |
|---------------|--------------------|------------------|---------------------|
| 294           | 296                | 412              | 1 606 572 572 988 498 |
| 295           | 297                | 415              | 1 608 793 594 792 982 |

0 per-pool mismatches, 0 pools only-in-Mithril. db-sync additionally carries
zero-stake pools (74 at epoch_no 297) that Mithril omits; they carry **zero
Ariadne weight**, so the certified set is the active set. The offset is locked by
`mithril_stake::tests::epoch_alignment_offset_is_two` (offline) and the live
golden `mithril_stake_distribution_matches_db_sync_golden_active_epoch_297`
(cert-verified) — both fail if anyone changes the offset.

### Retention-window caveat

The preprod aggregator retains ~20 epochs of `cardano-stake-distribution`
(observed window 276–295, ≈100 days at 5-day preprod epochs). A follower asking
for `active_epoch` whose `active_epoch - 2` has aged out of the window gets a
download error and must fall back to the yaci `epoch_stake` path (build without
`mithril-stake`) for that historical epoch. In steady-state operation the
follower only needs the current/just-past epoch, which is always in-window.

### Enabling Tier-2

1. Build the follower with `mithril-stake` (implies `candidate-source`):
   `cargo build -p yaci-follower --features "block-source,candidate-source,native-token,mc-hash,sidechain-rpc,mithril-stake"`.
2. Drop the yaci `ledger-state` profile (no `adapot`, no `account`) — see
   LEAN-DEPLOYMENT.md Tier-2.
3. Set the runtime env for the node process:
   - `MITHRIL_AGGREGATOR_ENDPOINT`
   - `MITHRIL_GENESIS_VERIFICATION_KEY` (the network's genesis vkey)
   - `MITHRIL_CLIENT_BIN` (path to the pinned `mithril-client`; defaults to
     `mithril-client` on `PATH`)

   Preprod:
   ```bash
   export MITHRIL_AGGREGATOR_ENDPOINT="https://aggregator.release-preprod.api.mithril.network/aggregator"
   export MITHRIL_GENESIS_VERIFICATION_KEY=$(curl -fsSL https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)
   ```
   Mainnet (magic 764824073):
   ```bash
   export MITHRIL_AGGREGATOR_ENDPOINT="https://aggregator.release-mainnet.api.mithril.network/aggregator"
   export MITHRIL_GENESIS_VERIFICATION_KEY=$(curl -fsSL https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/release-mainnet/genesis.vkey)
   ```

The per-epoch result is cached in-process (a Mithril SD is fixed once its
certificate is signed), so the `mithril-client` is invoked at most once per
`active_epoch`.

## Remaining / not in this session

- **D-param + permissioned-candidates token UTxOs**: the query
  (`get_token_utxo_for_epoch`) is implemented and the datum-decode is proven,
  but the live `.230` pilot DB currently holds NO UTxO carrying the preprod
  D-param policy `38dddaf5…` or permissioned-candidates policy `ef2890d1…`
  (they are not present in this yaci instance's UTxO/assets set). Add a
  golden integration test for `get_ariadne_parameters` once the pilot DB
  indexes a config tx carrying those tokens (or point a test at mainnet/another
  preprod yaci instance that has them).
- **native-token illiquid-supply** queries are ported and compile but are not
  yet covered by a live golden test (no illiquid-supply transfers in the pilot
  set to assert against).
- **`get_highest_block`** filters on `block_time` directly (yaci has no slot
  index need); db-sync additionally bounded by slot for index efficiency. The
  yaci `idx_block_slot`/time bounds are equivalent for correctness.
- **MAINNET**: `get_epoch_of_data_storage` returns the request epoch verbatim
  (preprod early-launch relaxation, mirroring the db-sync-follower patch).
  Mainnet must revert to `epoch - 2`.

## Build hygiene

Scoped + niced only — never a full node/workspace build on Gemtek (live
validator):

```
nice -n 19 cargo check -p yaci-follower --features "block-source,candidate-source,native-token,mc-hash,sidechain-rpc"
nice -n 19 cargo test  -p yaci-follower --features "block-source,candidate-source,native-token,mc-hash,sidechain-rpc"
# DB-integration (tunnel to the .230 pilot, then):
YACI_DATABASE_URL=postgres://yaci:***@127.0.0.1:15432/yaci_store \
  nice -n 19 cargo test -p yaci-follower --features "…" -- --ignored
```
