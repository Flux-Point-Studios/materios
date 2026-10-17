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
use `T::DbWeight`; the runtime selects RocksDbWeight. The prior local floor
has been removed without changing these checkpoint prices.

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

## Capacity with runtime database pricing

The Normal block budget is 1,500,000,000,000 ref_time. The signed base is
107,074,000 generic execution plus 1,164,660,000 fee work = 1,271,734,000.

| Dispatch | Call ref_time | Including signed base |
| --- | ---: | ---: |
| transfer_keep_alive |460,929,000|1,732,663,000|
| claim_motra |1,047,014,000|2,318,748,000|
| set_delegatee |1,148,657,000|2,420,391,000|
| Attest non-threshold actual |273,973,000|1,545,707,000|
| Attest 96-signer threshold actual (97 checkpoints) |45,105,985,056|46,377,719,056|
| Attest admission bound (98 checkpoints) |45,254,870,056|46,526,604,056|

Transfers fit 865/block by ref_time before initialization, length or proof
limits. A real CheckWeight/pre-dispatch/call/post-dispatch loop admits 941
non-threshold attests. Existing Utility.batch admits 3,705 such attestations
in 318 signed batches with a shrinking final width, versus 15,138 before global
storage pricing. Every inner receipt and signer is checked. The installed
daemon submits individually; this is protocol capacity, not live TPS.

The maximum dormant-claim batch runs 1,211 claims, down from 1,411: the
Utility wrapper now prices its database work. The MOTRA claim weight itself
is unchanged. The aggregate hook/migration safety audit has unresolved blockers.
See [runtime database weights](runtime-db-weights.md) for the complete
before/after call and fee tables, exact capacity assumptions and counterexamples.

## Conditional Currency refunds

All receipt and Billing calls that refund checkpoint surcharges retain a
measured execution base. The raw `benchmarking/currency-samples.json` files
cover zero and positive Currency operations, a full 96-member committee,
maximal content-index input, both receipt versions and creation of a Billing
withdrawal recipient. The base takes the largest observed execution sample
across these branches, retaining the measured positive-branch CPU cost even
when a zero branch refunds every checkpoint. This prevents utility batches
from recycling checkpoint refunds against the former 20,000–30,000-ref_time
receipt bases.

| Retained base | ref_time | Proof bytes | Base reads/writes |
|---|---:|---:|---:|
| Submit receipt v1/v2 | 101,874,000 | 28,238 | 6/7 |
| Privileged certification | 67,549,000 | 14,578 | 3/4 |
| Bond | 53,642,000 | 7,122 | 2/2 |
| Unbond | 81,425,000 | 11,681 | 3/2 |
| Slash attestor | 110,751,000 | 18,264 | 6/5 |
| Expire escrow | 70,634,000 | 16,067 | 5/3 |
| Billing topup self | 55,787,000 | 8,623 | 3/3 |
| Billing topup for | 48,853,000 | 8,623 | 3/3 |
| Billing withdrawal | 75,884,000 | 8,627 | 3/3 |

These measurements use the same FRAME command above with `--steps 20
--repeat 20 --external-repeat 3`, once for `pallet_orinq_receipts` and once
for `pallet_billing`. Measurement Wasm SHA256:
`586c62ba2c0902aeef64a9397f6422523c3d067956079253e95fc3a3c4923353`.
Each retained base is the maximum `extrinsic_time * 1000` in its samples;
v1/v2 share the component-wise maximum. Proof bounds sum the independent
StorageInfo bounds listed in `proof_storage`, with seven trie layers per map
and three per value. The runtime test recomputes the CPU/proof bounds from
the samples and runtime StorageInfo, then checks the dispatch base and DB counts under a nonzero test schedule.
The recorded checkpoint key is removed from base DB counts and charged by
the separate checkpoint surcharge. Billing additionally accounts for
`Balances.TotalIssuance`, which the standard benchmark whitelist excludes.

## Runtime database schedule

The runtime selects RocksDbWeight. Balances, Vesting, Multisig, Recovery,
Treasury, IntentSettlement and receipt/Billing generated base DB terms now
carry that schedule. MOTRA and runtime migration/classifier work no longer
have independent RocksDB floors.

Threshold attestation DB counts exclude the separately charged n+1 checkpoint
keys: 14+2n reads and 9+2n writes. Every original benchmark DB sample is checked
under an independent nonzero test schedule. Proof and execution measurements
are unchanged. Existing flat-weight calls and unbounded/underpriced hooks are
not repaired by setting DbWeight; [the runtime audit](runtime-db-weights.md)
records the outstanding merge/genesis blockers.

Settlement #51 merged as `feb79e00510d0083de67bc3219e442f802cd1101` on
2026-10-17. The #68 base still pins oracle and settlement together to its
reviewed head `ff0efeddad5dfa3a948f6b4e425b4546e39fbbe4`; updating those pins
belongs to that base branch's review flow. This stacked draft must absorb
any later base update by signed merge and repeat validation. No merge,
deployment or enactment is authorized by this audit.
