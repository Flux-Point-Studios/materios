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
unknown-epoch-None, UTxO+datum decode).

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

## Mithril-stake seam (trustless upgrade path)

`db_model::get_stake_distribution` carries a comment marking the seam: a
Mithril-certified per-pool stake distribution can replace this one query
without touching any caller. Mithril GA certifies exactly the `(pool_hash,
stake)` Ariadne snapshot — the one follower input that is otherwise only as
trustworthy as the local yaci-store DB. yaci stake is byte-identical to db-sync
today; Mithril is the later composition that removes the trust-in-the-local-DB
assumption. The nonce and the datum/address inputs are NOT Mithril-certifiable,
so Mithril complements (does not replace) the yaci/db-sync follower.

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
