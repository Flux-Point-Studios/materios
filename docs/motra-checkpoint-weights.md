# MOTRA accounting and dispatch weights

Balance changes carry their checkpoint costs in the owning dispatch's declared
weight. `CheckWeight` admits the complete bound before execution; Utility,
Multisig and RootTimelock preserve inner calls' weights and refunds.

A checkpoint benchmark performs two free-balance changes on one account, as a
signer reward followed by escrow distribution can do. The key is read and
written once in the database; repeated overlay accesses remain in execution
time. System.Account belongs to the base Currency weight and is whitelisted;
the MOTRA checkpoint is not. Its cost is **148,885,000 ref_time / 3,533 proof
bytes**: 23,885,000 execution plus one RocksDB read and write. The database terms
use `max(T::DbWeight, RocksDbWeight)` separately for reads and writes.

Reconciliation uses directed fixed-point exponentiation, bounded by 64 rounds,
and decays generation within the holding interval. It settles a delegatee's
existing stored balance before crediting sponsorship at the current block;
the independent holding checkpoint preserves pending generation. Claim,
delegation and fee benchmarks include nonzero stored balances, distinct
caller/recipient clocks and intervals of 100,000, 1,000,000 and u32::MAX blocks.
An additional legacy baseline read covers the fallback branch even when the
longer two-clock benchmark uses an existing checkpoint.

The complete fee path (reconcile, burn, post-dispatch refund) is added once to
`RuntimeBlockWeights.base_extrinsic`. Validation uses discarded storage and is
outside block execution. The minimum and length fee remain paid; the dispatch
weight fee is refunded at the pre-dispatch congestion rate. `TotalBurned` is
net of the amount actually credited. `FeeRefunded` is appended to the event
enum. Existing calls, storage encodings, SignedExtra and transaction version 5
are unchanged.

## Currency path audit

| Runtime entry point | Potential account mutations budgeted |
| --- | --- |
| Balances transfer variants | 2 |
| Balances set balance, burn, force unreserve | 1 |
| Balances upgrade accounts | Number of supplied accounts |
| Balances force adjust total issuance | 0; no account data changes |
| Vesting vested transfers | 3; sender, recipient, recipient's lock update |
| Other Vesting calls | 1; lock update can repair a legacy account |
| Multisig create/approve-create, complete, cancel | 1 reserve/unreserve; inner call charged separately |
| Other Multisig calls | 0; inner call charged separately |
| Recovery create, initiate, remove | 1 reserve/unreserve |
| Recovery close | 2 for repatriation, including self-repatriation's unreserve |
| Other Recovery calls | 0; recovered dispatch carries its inner weight |
| Treasury payout | 2 for PayFromAccount's transfer |
| Treasury spend hook | 2 per approval plus 1 pot settlement; `MaxApprovals = 100` |
| Other Treasury calls | 0; approvals/asset-spend records only |
| IntentSettlement bond/release | 1 reserve/unreserve |
| IntentSettlement slash | 4 across two repatriations |
| Other IntentSettlement calls/hooks | 0; settlement records and vouchers do not mutate MATRA |
| Billing topups | 1 withdrawal |
| Billing execute withdrawal | 2; deposit and possible overflow rollback withdrawal |
| Other Billing calls | 0; billing-credit storage only |
| Receipt submit/resubmit, privileged cert, bond/unbond, fee expiry | 1 reserve/unreserve |
| Receipt slash | 2 for repatriation |
| Receipt attestation | `MaxCommitteeSize + 2` distinct accounts at admission; actual changed accounts on success; zero for non-threshold and late attests |
| Receipt era rewards | Hook returns one mutation budget per validator/treasury deposit actually attempted |
| Fee-router pot migration | 4; two transfers |
| Perp removal migration | One per released bond plus 2 for its pot transfer; at most 1,000 bond entries per upgrade |
| Native token transfer inherent | 0; runtime handler records the observation without minting MATRA |
| Genesis | No block admission; hooks write state without registering block weight |


Billing topups and successful withdrawals return their actual checkpoint count;
failed overflow rollback retains the admission bound. Receipt submission v1/v2,
privileged certification, bond/unbond, slash, expiry and attestation return
actual weight. Threshold attestation snapshots unique signer, treasury and
escrow-payer balances and counts the accounts whose free balance changes. The
96-signer maximum with reward and fee distribution changes 97 accounts, for
both an existing treasury and the dead-treasury refund path. Non-threshold and
late attestations return the measured base without checkpoints. Bad-hash
slashing has its own measured base and counts its changed accounts.

Runtime regressions commit fixtures before dispatch and inspect real checkpoint
writes across fifteen Billing/receipt paths, plus maximum committee payouts.
Existing property tests retain every Balances call, reserve/unreserve, legacy
repair, u128 limits, failed dispatch and checkpoint invariants. `try_state`
rejects a holding above current free MATRA or a future checkpoint block.

Receipt era rewards run every 14,400 blocks; their returned initialization
weight includes every attempted balance mutation. The separate author-map
traversal remains outside these checkpoint bounds.

## Measurements and reproducibility

Gemtek: AMD Ryzen 7 7730U, 8 cores / 16 threads, 28 GiB RAM, Linux
6.17.0-22-generic. Rust 1.85.0, SDK c455194a, frame-omni-bencher 0.7.0
(benchmark CLI 43.0.0). All local heavy work uses the shared Cargo build lock,
`nice -n 10`, four jobs and an isolated target directory.

From `partnerchain/`, set `CARGO_TARGET_DIR` to the isolated target and
`WASM_BUILD_WORKSPACE_HINT` to this checkout's `partnerchain/` directory:

```sh
cargo build -p materios-runtime --features runtime-benchmarks --locked
frame-omni-bencher v1 benchmark pallet \
  --runtime "$CARGO_TARGET_DIR/debug/wbuild/materios-runtime/materios_runtime.wasm" \
  --pallet pallet_motra --extrinsic '*' \
  --steps 20 --repeat 20 --external-repeat 3 --output-analysis max \
  --map-size 1000000 --additional-trie-layers 2 \
  --genesis-builder runtime --genesis-builder-preset development \
  --json-file motra-benchmarks.json
```

The receipt command substitutes `--pallet pallet_orinq_receipts` and its own
JSON output. Reconciliation and receipt attestation samples are retained in
`pallets/motra/benchmarking/reconciliation-samples.json` and
`pallets/orinq-receipts/benchmarking/attestation-samples.json`; templates beside
them generate the weight functions using `--json-input`, `--template` and
`--output`, followed by `rustfmt --edition 2021`. The prior checkpoint run used
50 steps, 100 repeats and five external repeats; its raw JSON is retained as
`checkpoint-samples.json`. Runtime tests pin the checkpoint, claim, delegation
and fee ref_time and database counts to those samples, bound every measured
reconciliation case, and derive proof bounds independently from StorageInfo.

Measured Wasm SHA-256:

- MOTRA: `792e66e68c2c864389cd7e59c13b3a4581ec8d31f5aeefef31732a783845d279`
- Receipts: `80f2ec8f84762507082bccb2953d3a2be414fa5139bd0e7361cd7f99d9a8be0b`
- Prior checkpoint: `a91044ae7c4583cb877e236bf8729429dd7e3f653c44ca3a976123cc7a1e9657`

| Measured MOTRA path | Execution ref_time | Unique reads/writes | Charged ref_time |
| --- | ---: | ---: | ---: |
| Claim | 197,014,000 | 9 / 6, plus legacy read | 1,047,014,000 |
| Set delegatee | 198,657,000 | 9 / 7, plus legacy read | 1,148,657,000 |
| Reconcile u32::MAX | 198,197,000 | 9 / 6, plus legacy read | 1,048,197,000 |
| Reconcile 100,000 | 106,833,000 | 9 / 6, plus legacy read | bounded by reconcile above |
| Reconcile 1,000,000 | 112,053,000 | 9 / 6, plus legacy read | bounded by reconcile above |
| Legacy reconcile | 138,794,000 | 10 / 6 | bounded by reconcile above |
| Fee pre + post | 189,660,000 | 10 / 7, plus legacy read | 1,164,660,000 |

Map proofs sum `max_size + 7*495` per independent key; values sum
`max_size + 3*495`. Reconciliation covers System.Account, Params, two balances,
two clocks, checkpoint, delegatee, TotalIssued and LegacyAccrualStart: 29,346
bytes. The fee path adds TotalBurned: 30,847 bytes. This avoids taking only the
largest prefix when multiple independent prefixes are accessed.

Receipt measurements cover n=1..96 signers, normal and dead-treasury payout,
non-threshold submission and bad-hash slashing. Non-threshold execution is
48,973,000; threshold execution is the maximum of
`129,230,520 + 55,051,141*n` and `157,357,000 + 49,530,379*n`.
Their base proofs exclude the separately charged checkpoints: 20,083 bytes
non-threshold, 43,329 + 7,122*n threshold, 29,185 bad-hash.

## Capacity

The Normal block budget is 1,500,000,000,000 ref_time. The signed base is
107,074,000 generic execution plus 1,164,660,000 fee work = **1,271,734,000**.

| Dispatch | Call ref_time | Including signed base |
| --- | ---: | ---: |
| transfer_keep_alive | 335,929,000 | 1,607,663,000 |
| claim_motra | 1,047,014,000 | 2,318,748,000 |
| set_delegatee | 1,148,657,000 | 2,420,391,000 |
| Attest non-threshold actual | 48,973,000 | 1,320,707,000 |
| Attest 96-signer threshold actual (97 checkpoints) | 19,855,985,056 | 21,127,719,056 |
| Attest admission bound (98 checkpoints) | 20,004,870,056 | 21,276,604,056 |

Transfers fit **933/block** by ref_time before other initialization, length or
proof limits. A real CheckWeight/pre-dispatch/call/post-dispatch loop admits
**1,120 non-threshold attests**, versus 70 with no actual-weight refunds under
these new measured declarations and about 34 at the reviewed head. The ideal
actual-only ceiling is 1,135; admission must leave room for a possible threshold
call. This does **not** equal pre-#68's 14,007: that figure used an unpriced fee
extension and a 15,000-ref_time attestation base. Restoring that number while
reserving full worst-case fee work per separate extrinsic is incompatible with
the present block budget. This remains an explicit acceptance decision, not a
reason to understate execution cost.

A real maximum Utility/as_derivative batch runs 1,411 dormant delegated claims
at u32::MAX. Tests check every inner clock and compare the sum of worst Wasm
claim samples (400,639,340,000 ref_time) against its declared total
1,499,275,194,121. The isolated native run took 983,750,068,000 ref_time (0.984 seconds), within
the declared bound. Concurrent test scheduling is not a runtime cost measurement.

## Remaining database-weight dependency

`System.DbWeight = ()` is unchanged; [#71](https://github.com/Flux-Point-Studios/materios/issues/71)
owns the runtime-wide fix. Within this PR:

- `runtime/src/balance_weights.rs` preserves SDK base weights for Balances,
  Vesting, Multisig, Recovery, Treasury and IntentSettlement. Their underlying
  `T::DbWeight` reads/writes remain zero; only MOTRA checkpoint additions have
  the RocksDB floor.
- Receipt attestation base functions use `T::DbWeight`; their non-MOTRA
  storage remains zero-priced. Threshold DB samples include checkpoint keys
  that are also covered by the separate checkpoint surcharge, so a future
  nonzero DbWeight must reconcile that conservative duplication.
- Receipt bond, unbond, slash and expiry annotations and their actual weights
  retain zero `T::DbWeight` terms (including the free-balance snapshots used for
  refunds). The checkpoint addition does not price their base storage work.
- Billing topups/withdrawal and receipt submission v1/v2 and privileged
  certification use hand-authored flat base weights with no database terms;
  the added checkpoint budget does not repair them.
- Reward-hook base work retains configured database terms; author-map work is
  not covered by the checkpoint increment.
- Capacity and exact-weight regression numbers use today's zero base database
  terms. The checkpoint property test proves the added MOTRA delta, not full
  Currency cost. These expected numbers must move with #71.

MOTRA checkpoint, reconciliation and fee weights use the RocksDB floor and do
not depend on zero DbWeight. The fee-router/perp-removal migrations already
use a RocksDB floor for their base work and add the checkpoint increments.

Settlement #51 must merge before #68. Both oracle and settlement currently
resolve to ff0efeddad5dfa3a948f6b4e425b4546e39fbbe4; after #51 merges, both pins
must move together to its merged main commit and validation must be repeated.
No merge, deployment or enactment is authorized by this round.
