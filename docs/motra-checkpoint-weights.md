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

Paid transactions price the complete signed ref_time, the feeless duty work
the call commits validators to, and length as work:
`min_fee + R * (base_extrinsic + call_weight + deferred_duty_weight + length * weight_per_byte) / 1_000_000 + length_fee_per_byte * length`,
where `weight_per_byte` is the Normal ref_time budget over the Normal length
budget.
The signed base contains ExtrinsicBaseWeight and the complete MOTRA fee path.
The flat minimum is an additional floor; it does not replace congestion pricing
of the signed base. Arithmetic uses the SDK's wide rational multiplication.
Post-dispatch refunds retain the signed base, length work, minimum and length
charge at the pre-dispatch rate, including at saturation; the deferred duty
work is never refunded. Credit is bounded by max_balance;
TotalBurned and FeeRefunded reflect only the amount actually credited.

Paid pool priority is `min_fee + R * base_extrinsic / 1_000_000`, capped at
u64::MAX-2. Length and refundable call declarations earn no extra priority.
This deliberately gives equal priority to ordinary paid calls at a given R.
The guardian remains at u64::MAX with its existing per-signer tag.

R measures the fuller of two dimensions, each against its Normal budget and
saturating at one. Weight is Normal plus Operational consumption: a block full
of Normal traffic reads 100% as before, and Operational traffic, which may take
the whole block beyond the Normal share, raises R as well. Length is the
encoded bytes of every extrinsic, which all classes share. A block half full
by each reads half full. Mandatory weight is excluded. The guardian's taken-first veto
is excluded too: the fee extension moves its consumed weight to the Mandatory
class after dispatch, leaving the block total unchanged.

Operational-class calls are refused before payment, in pool validation and
again in pre_dispatch, unless the guardian's veto takes them first or the
runtime's `paid_operational::admits` names the signer's path. A call that fails
before running keeps its declared weight, so an unnamed Operational call such
as `Utility.with_weight` around `cancel_all`, or `System.kill_prefix` with a
chosen key count, would otherwise fill the block for the minimum fee. The
runtime test `operational_sweep_names_every_operational_call_and_wrapper`
decodes every call variant and pins the Operational set and the wrapper set,
so a new Operational call or wrapper fails CI until its path is decided.

| Operational call | Who may pay for it |
|---|---|
| `RootTimelock.cancel`, `fast_track`, `cancel_all`, `approve` | The guardian, taken first |
| `Sudo.sudo` | The sudo key, for calls `SudoRootGate` lets run at once |
| `RootTimelock.enact` (inner Operational) | Anyone, for a ready, unexpired task with the matching hash |
| `System.apply_authorized_upgrade` | Anyone, while that code is authorized; the unsigned path is unchanged |
| `IntentSettlement` committee calls: `attest_intent`, `request_voucher`, `settle_claim`, `expire_policy_mirror`, `credit_deposit`, `settle_batch_atomic`, `attest_batch_intents`, `request_batch_vouchers`, `attest_settle`, `attest_batch_settle`, `attest_expire_policy`, `supersede_settlement_request` | An attestation committee member |
| `IntentSettlement` keeper and watcher calls: `request_settle`, `request_batch_settle`, `request_expire_policy`, `post_settlement_bond`, `release_settlement_bond`, `slash_bad_settlement_evidence` | Anyone; bounded declared weight, metered by R |
| `Utility.batch`, `batch_all`, `force_batch` | The signer, when non-empty and every inner call is admitted |
| `Utility.as_derivative`, `Multisig.as_multi_threshold_1`, `Recovery.as_recovered` | As the derived, multisig or recovered account; a rescuer must be that account's proxy |
| `System.set_heap_pages`, `set_code`, `set_code_without_checks`, `set_storage`, `kill_storage`, `kill_prefix`, `authorize_upgrade`, `authorize_upgrade_without_checks`; `Treasury.remove_approval`; `IntentSettlement.set_pool_utilization`, `set_min_signer_threshold`; `Utility.with_weight`, `dispatch_as`; `Sudo.sudo_unchecked_weight`, `sudo_as`; `RootTimelock.enact_approved` | Nobody: Root reaches them through the timelock or the exempt sudo path |

Settlement committee duties stay paid at the flat paid priority. Each carries
the full M-of-N signature bundle, so it is one transaction per settled item. A
failed settlement attest leaves its item pending, so a feeless path would need
the complete bundle verified in pool validation to stop free replays, and the
pallet's signature checks are internal.

Receipt submissions price the certification they trigger. For each
`submit_receipt` or `submit_receipt_v2` a call carries, at any wrapper depth,
the deferred duty weight at threshold `t` is `t` duty bases
(ExtrinsicBaseWeight), `t - 1` non-threshold attests at the largest signer
count before payout, and the payout attest with `t + 2` balance changes.
Each submission's own weight also carries the threshold read this makes.

Canonical committee attestation is a feeless validator duty at the fixed
priority u64::MAX-1, independent of R and batch width. ChargeMotra calls the
runtime's IsSubType classifier before reconciliation or payment, both in pool
validation and pre_dispatch. A duty requires a current committee member, an
existing uncertified receipt, the canonical hash and no prior attestation by
that signer. Invalid duties never increment InsufficientMotraFailures.
Pool tags contain signer and receipt; batches cannot repeat a receipt.
Wrong hashes are rejected because bad-hash dispatch otherwise does not consume
a signer slot and would permit unlimited free retries. The dispatch's late
certification no-op remains a backstop for paid wrappers and privileged paths.

Nonempty Utility.batch and Utility.batch_all containing only direct attests
receive the same policy and one tag per new attest. A batch may also carry
stale attests, for a certified receipt or one this member already signed,
which dispatch as benign no-ops, but no more of them than new ones; a batch
with no new attest is refused. Mixed, nested and other wrappers
retain paid behavior; no arbitrary inner call inherits the exemption. A pure
batch cannot certify or remove a member for a different inner receipt before
its turn: receipt IDs are unique and every hash is canonical. Pre-dispatch
rechecks reject pool entries invalidated by certification or committee changes.
The fee extension releases only its unused fee_path base budget for a duty;
signature, Utility and measured attestation work remain charged to block weight.
The measurements include the complete ChargeMotra duty pre/dispatch/post path.

Existing calls, storage encodings, SignedExtra and transaction version 5 are
unchanged by this work.

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
| IntentSettlement request, batch request, supersede | 0; measured on this runtime with the reserve and any displaced bond's refund, checkpoints included |
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
both an existing treasury and the dead-treasury refund path. Non-threshold
attestations return a measured function of the actual signer count; late calls
retain the maximum non-threshold bound, without checkpoints. Bad-hash
slashing has its own measured base and counts its changed accounts.

Runtime regressions commit fixtures before dispatch and inspect real checkpoint
writes across fifteen Billing/receipt paths, plus maximum committee payouts.
Existing property tests retain every Balances call, reserve/unreserve, legacy
repair, u128 limits, failed dispatch and checkpoint invariants. `try_state`
rejects a holding above current free MATRA or a future checkpoint block.

Receipt era rewards run every 14,400 blocks; their returned initialization
weight includes every attempted balance mutation. The separate author-map
traversal remains outside these checkpoint bounds.

## Measurements and capacity

Gemtek Ryzen 7 7730U, Rust 1.85.0, SDK c455194a. Builds and benchmarks use the
shared Cargo lock, nice10, four jobs and a target exclusive to this worktree.
Measurement Wasm SHA-256: `d9d3f7a2f803b59add58daf84a883fe231ea8c6a71c248ac2a3c4d80d2b3d8d3`.
Run the following from `partnerchain/` with the isolated CARGO_TARGET_DIR and
WASM_BUILD_WORKSPACE_HINT set, inside the shared-lock/nice wrapper.

```sh
cargo build -p materios-runtime --features runtime-benchmarks --locked
frame-omni-bencher v1 benchmark pallet --runtime <measurement.wasm> \
  --pallet pallet_orinq_receipts \
  --extrinsic 'attest_non_threshold,attest_repeated,attest_threshold,attest_dead_treasury,attest_bad_hash' \
  --steps 20 --repeat 20 --external-repeat 3 --output-analysis max \
  --map-size 1000000 --additional-trie-layers 2 \
  --genesis-builder runtime --genesis-builder-preset development \
  --json-file attestation-benchmarks.json
```

The fee-path run uses the same arguments with `--pallet pallet_motra
--extrinsic fee_path`. Raw samples are committed beside the weight functions.
Regenerate the coefficients and their formatting with
`python3 pallets/motra/benchmarking/generate_fee_weights.py`. It starts from
FRAME's `--output-analysis max` statistical fit and never lowers its base or
slope. For non-threshold attests, it anchors the base at the larger of the FRAME
base and zero-prior-signers median, then raises the slope to cover the median at
every measured signer count. For the other paths it retains the FRAME slope
and raises the intercept to cover those medians. This is a statistical fit,
not a worst-observed-sample bound: non-threshold medians span about 80–88 µs,
while isolated samples reach 144 µs. All raw samples remain committed.

Non-threshold measurements vary prior signers from 0 to 95; duplicate backstops
vary from 1 to 96. Valid non-threshold, threshold and dead-treasury measurements
execute ChargeMotra pre_dispatch, real runtime dispatch and ChargeMotra
post_dispatch, including classifier/tag allocation and unused fee-base release.
Returned weights also cover the duplicate-backstop fit. Runtime tests compare
the per-count medians independently and derive proof bounds from StorageInfo.
The complete paid fee-path bound uses its largest execution sample plus floored
database costs and the legacy read. These policies distinguish execution
estimates from hard storage/proof bounds; neither claims block-import latency.

| Capacity under the normal block budget | Count |
|---|---:|
| Separately signed transfers | 920 |
| Separately signed non-threshold attests | 7873 |
| Non-threshold attests in pure Utility batches | 16121 in 878 batches |

The attestation loops execute CheckWeight, ChargeMotra, real runtime dispatch
and both post-dispatch paths; each recorded signer and receipt is checked.
Admission reserves the threshold payout bound, then refunds unused call and
fee work. The batched regression must meet round four's 15,138 count. These
are protocol capacity measurements, not live TPS or daemon rollout claims.
DbWeight=() is unchanged and #71 must recalculate capacity after its fix.

The maximum dormant-claim batch remains a native TestExternalities execution
regression backed by independent Wasm samples. Its native elapsed time excludes
RocksDB and import/commit work and is not evidence of full block-import latency.

## Fee and priority evidence

Fees below are MOTRA (15 decimals). Length is the SCALE-encoded signed
extrinsic length with an sr25519 signature, immortal era and nonce zero.
Where two figures appear, the first is the fee after the post-dispatch refund
and the second the escrow taken before dispatch; elsewhere they are equal.
Non-members and the Operational stuffer (`Utility.with_weight` around
`cancel_all` from a non-guardian) are invalid before payment. At R=0, only
minimum and length remain. `submit_receipt` is priced with the certification
of a 3-member committee at threshold 2. Since length is priced as work, a
transfer at R=1e9 costs 0.001684018191, 3.25% above round five's 0.001630994.

| R | Call | Bytes | Fee (MOTRA) | Priority |
|---|---|---:|---:|---:|
| 0 | transfer | 139 | 0.000001139 | 1000000000 |
| 0 | remark | 106 | 0.000001106 | 1000000000 |
| 0 | attest_member | 169 | 0 | 18446744073709551614 |
| 0 | attest_non_member | 169 | Rejected | — |
| 0 | submit_receipt | 395 | 0.000001395 | 1000000000 |
| 0 | claim | 105 | 0.000001105 | 1000000000 |
| 0 | set_delegatee | 138 | 0.000001138 | 1000000000 |
| 0 | Operational stuffer | 114 | Rejected | — |
| 1,000,000,000 | transfer | 139 | 0.001684018191 | 1294926000000 |
| 1,000,000,000 | remark | 106 | 0.001336605458 | 1294926000000 |
| 1,000,000,000 | attest_member | 169 | 0 | 18446744073709551614 |
| 1,000,000,000 | attest_non_member | 169 | Rejected | — |
| 1,000,000,000 | submit_receipt | 395 | 0.003323116122 / 0.003472001122 | 1294926000000 |
| 1,000,000,000 | claim | 105 | 0.002382099245 | 1294926000000 |
| 1,000,000,000 | set_delegatee | 138 | 0.002496363722 | 1294926000000 |
| 1,000,000,000 | Operational stuffer | 114 | Rejected | — |
| 50,000,000,000 | transfer | 139 | 0.08414509855 | 64697300000000 |
| 50,000,000,000 | remark | 106 | 0.0667760789 | 64697300000000 |
| 50,000,000,000 | attest_member | 169 | 0 | 18446744073709551614 |
| 50,000,000,000 | attest_non_member | 169 | Rejected | — |
| 50,000,000,000 | submit_receipt | 395 | 0.1660874511 / 0.1735317011 | 64697300000000 |
| 50,000,000,000 | claim | 105 | 0.11905081725 | 64697300000000 |
| 50,000,000,000 | set_delegatee | 138 | 0.1247624241 | 64697300000000 |
| 50,000,000,000 | Operational stuffer | 114 | Rejected | — |

Length is a priced and metered dimension. A byte of signed extrinsic stands
for the Normal ref_time budget over the Normal length budget
(1.5e12 / 3,932,160, 381,469 ref_time per byte), so a block filled by either
dimension costs alike, and R reads the fuller of the two.

The 1,000-full-block empty-remark simulation reaches R=50,000,000,000 at a total
cost of 38,868.07 MOTRA at 128 bytes per remark, with the same R-priced
formula as a transfer at every step. A zero-MOTRA member then certifies a
receipt through the fee extension and runtime dispatch. Regressions also
reproduce and close priority inflation from early-failing Utility batches and
multisig max_weight.

Stuffers from R=0 over 1,000 blocks, each admitted as the author would admit
it (`stuffers_of_weight_or_length_ramp_r_like_the_remark_ramp`). Each must
raise R at least as fast as the remark ramp at every block and cost the same
order:

| Stuffer | Bytes | Weight share | Length share | Final R | Cost (MOTRA) |
|---|---:|---:|---:|---:|---:|
| Remark ramp (weight) | 108 | 74.98% | 2.39% | 49,978,920,005 | 38,631.10 |
| `request_batch_settle`, 0 entries | 124 | 99.96% | 3.33% | 50,000,000,000 | 51,598.46 |
| `request_batch_settle`, 256 entries | 37,245 | 99.54% | 54.70% | 50,000,000,000 | 77,047.77 |
| Normal-length-filling remark | 3,932,160 | 0.14% | 75% (all of Normal's) | 50,000,000,000 | 37,536.71 |

Shares are of the whole block. Before round six, the first keeper stuffer
cost 1.66 MOTRA over the same 1,000 blocks with R at zero. The 256-entry
stuffer cost 5.35 MOTRA, and the length-filling remark cost its minimum and
length fees, 0.00393 MOTRA per block, both with R at zero. Either length stuffer shut out every Normal
transaction, since all classes share the block length and Normal's cap is
3,932,160 bytes.

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
- All refunded receipt Currency bases (submission v1/v2, privileged
  certification, bond, unbond, slash and expiry) and Billing topups/withdrawal
  use measured execution but configured `T::DbWeight` for base storage.
  Those DB terms remain zero; separate checkpoint work retains the RocksDB
  floor. Billing's unrelated dispatches retain their prior flat weights.
- Reward-hook base work retains configured database terms; author-map work is
  not covered by the checkpoint increment.
- Capacity and exact-weight regression numbers use today's zero base database
  terms. The checkpoint property test proves the added MOTRA delta, not full
  Currency cost. These expected numbers must move with #71.

MOTRA checkpoint, reconciliation and fee weights use the RocksDB floor and do
not depend on zero DbWeight. The fee-router/perp-removal migrations already
use a RocksDB floor for their base work and add the checkpoint increments.

Both pallet-intent-settlement and pallet-oracle pin settlement #55's merge
commit `0757de35efa52d983c9203a683307827d76ae338`. Its settlement weights were
generated on this runtime, MOTRA checkpoints included, so the adapter adds no
checkpoint to the fourteen slots #55 introduced. Their storage terms, checkpoint
keys among them, are priced through `T::DbWeight`, which stays zero until #71.
Bond, release and slash keep their earlier 1/4/1 checkpoint budgets on top of
their now-measured bases.

Genesis-relevant fee-path layout work is tracked in
[#75](https://github.com/Flux-Point-Studios/materios/issues/75); legacy sponsorship,
hook accounting and the unused reconcile API in
[#76](https://github.com/Flux-Point-Studios/materios/issues/76); settlement's weight
examples and Pays::No documentation in
[settlement #53](https://github.com/Flux-Point-Studios/materios-intent-settlement/issues/53).
