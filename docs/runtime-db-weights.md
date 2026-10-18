# Runtime database weights

`frame_system::Config::DbWeight` is `RocksDbWeight`: 25,000,000 ref_time per
storage read and 100,000,000 per write. The runtime derived it from
`SolochainDefaultConfig`, whose `DbWeight = ()` priced every `T::DbWeight` term
in every pallet at zero. Only the SDK's `()` weight implementations (System,
Timestamp, GRANDPA) and a few runtime-local paths priced storage, each from
`RocksDbWeight` directly: MOTRA's checkpoint, reconciliation and fee weights,
the runtime migrations, the Root timelock classifier and the certification
threshold read. Those paths now read the runtime's `DbWeight`, and their
weights are unchanged (`motra_and_runtime_storage_prices_are_unchanged`).

Baseline: main at `67ec3d9`, spec 242 / transaction version 6, unreleased.
No call, storage or extrinsic encoding changes, so the spec and transaction
versions stay.
Nothing here is deployed or enacted.

## What changes

- **Storage is priced.** `type DbWeight = RocksDbWeight;`
  (`storage_access_is_priced_at_rocksdb_cost`).
- **One call may declare its class budget less a 1% initialization
  reservation.** `max_extrinsic` was `None` for Normal and Operational, so
  pool validation admitted any declaration up to the class total, including
  Operational declarations that no block with any initialization can include.
  `avg_block_initialization(1%)`, Polkadot's ratio, sets Normal to
  1,478,706,074,000 and Operational to 1,978,706,074,000; a declaration one
  unit above either is refused before dispatch, in ref_time and in proof size.
  The reservation covers every block a full committee initializes (below).
- **Local RocksDB floors are gone.** `checkpoint_weights.rs`,
  `reconciliation_weights.rs` and their templates, `migrations.rs`,
  `root_gate.rs` and `motra_duty::threshold_read` take the runtime's schedule.
  Under a synthetic schedule (1 per read, 10,000 per write) every MOTRA weight
  now moves with it (`benchmark_motra_weights_price_storage_at_the_configured_schedule`).
- **Threshold attestations charge each checkpoint once.** Their samples record
  `15 + 3n` reads and `10 + 3n` writes, which include the MOTRA checkpoint of
  the n signers and of the treasury or refunded submitter. `balance_mutations`
  already charges those, so the template subtracts `1 + n` reads and writes:
  97 of each, 12,125,000,000 ref_time, at n = 96
  (`benchmark_threshold_attestation_charges_each_checkpoint_once`).
- **Receipt hooks price their storage.** Each block, `OrinqReceipts::on_initialize`
  reads Aura's authorities and the era start, records the author and checks
  every authority's first-selection stamp; the era distribution reads and
  writes each author's entry, account and lifetime reward. Both now return
  that work (`receipts_initialization_prices_the_author_and_every_authority`,
  `the_reward_era_prices_its_storage_and_fits_a_block_at_its_author_bound`,
  which count the keys each hook writes from the storage overlay).
- **A runtime upgrade keeps attestations in flight.** The receipts pallet's
  `on_runtime_upgrade` cleared the whole `Attestations` map on every upgrade,
  a leftover of the spec 219 canonical-certificate migration. Every stored
  entry has carried a canonical hash since, so each upgrade only discarded
  attestation progress, and its cost grew with the map: 20,001 entries charged
  more than a block. The seeding of missing parameters remains
  (`on_runtime_upgrade_keeps_attestations_in_flight`,
  `a_runtime_upgrade_fits_a_block_whatever_the_attestations_in_flight`).
- **Settlement's bond slots carry no extra checkpoint budget.**
  `post_settlement_bond`, `slash_bad_settlement_evidence` and
  `release_settlement_bond` were generated on this runtime with the MOTRA
  checkpoints of the balances they move (one, two and one keys). The adapter's
  extra 1/4/1 checkpoint units charged them twice once storage was priced; they
  are zero now, and the slots must cover their checkpoint keys
  (`checkpoint_settlement_weights_add_no_checkpoints`, #85).

## Safety

### Every call fits its class

`every_call_fits_its_class_limit` walks `RuntimeCall`'s scale-info registry,
encodes every variant at its worst case, decodes it and asks the runtime for
its `DispatchInfo`. All 142 constructible variants fit; the two GRANDPA
equivocation reports take an uninhabited key-owner proof and cannot be
encoded.

- **Bounded (118).** Every list a call's weight depends on is encoded at its
  pallet's bound: 96 receipt committee members, 32 session validators, 256
  settlement batch entries and claim or intent ids, 96 settlement signatures,
  9 Multisig co-signatories, 9 Recovery friends, 256 Billing prune ids, a
  16 KiB TEE payload, and a remark that fills the Normal block length. A new
  call that takes a list fails the test until its bound is decided.
- **Caller-sized (20).** Nested calls, a caller-supplied weight or count, or an
  unbounded list: Sudo, Multisig `as_multi*` and `approve_as_multi`, Utility,
  Recovery `as_recovered`, RootTimelock `schedule`/`enact*`, System
  `set_storage`/`kill_storage`/`kill_prefix`, Balances `upgrade_accounts`.
  They have no finite worst case; `CheckWeight` refuses any of them declared
  above its class limit before dispatch
  (`every_caller_sized_call_is_refused_above_its_class_limit`).
- **Mandatory (4)** inherents are compared with the whole block.

| Worst case | Call | ref_time | Share of its limit |
|---|---|---:|---:|
| Operational | IntentSettlement.attest_batch_settle, 256 claims and 96 signatures | 525,621,460,684 | 26.564% (18.598% before) |
| Normal | IntentSettlement.submit_batch_intents, 256 entries | 383,996,419,345 | 25.968% (23.450% before) |
| Mandatory | SessionCommitteeManagement.set | 382,064,398 | 0.019% |

No call became un-includable. Every Operational call a signer may pay for is
bounded and fits (`every_paid_operational_call_is_bounded_and_fits_its_class`).
A pure attestation batch, the feeless duty form, fits up to 32 attestations
(74 before) and a 33rd is refused at validation
(`the_widest_duty_batch_fits_and_a_wider_one_is_refused`). The cert-daemon
submits each attestation as its own extrinsic (operator-kit
`daemon/substrate_client.py`, `submit_availability_cert`), so its real width
is one.

### Every hook fits the block

| Block | Declared | Share of the block | Test |
|---|---:|---:|---|
| Initialization of a 32-seat committee's blocks, inherents included, over three epochs | at most 12,941,850,327 | 0.65% (reservation 1%) | `every_block_of_a_full_committee_initializes_within_its_reservation` |
| Session rotation | the whole block, plus the above | Mandatory only | same |
| Receipt reward era, 800 authors | 419,991,885,000 | 21.00%; fits twice over up to 1,907 authors | `the_reward_era_prices_its_storage_and_fits_a_block_at_its_author_bound` |
| Treasury spend period, 100 approvals | 71,283,411,920 | 3.56% | `the_treasury_spend_period_fits_a_block` |
| Runtime upgrade, every migration | 5,818,360,000 | 0.29%, whatever the attestations in flight | `a_runtime_upgrade_fits_a_block_whatever_the_attestations_in_flight` |
| `on_idle` | 0 | none | `no_pallet_takes_idle_time` |

Partner-chains' session pallet declares the whole block for a rotation, as
FRAME's session pallet does. That reserves the block for its inherents; the
rotation's own work is bounded by the 32 seats.

The reward era pays every author of the era. Authors are bounded by the seats
times the sessions an era spans: at 600-slot sessions, 32 seats over 25
sessions, 800 authors. The distribution's Wasm execution is not benchmarked,
so its declared weight must fit the block twice over. That holds up to 1,907
authors: with registered seats open and 32 seats, sessions of at least 249
slots. The launch preflight seats only permissioned candidates, so at launch
an era has at most 32 authors.

### Outside this change

These remain and are not changed by pricing storage:

- MOTRA's `on_finalize` congestion update reserves no weight
  ([#76](https://github.com/Flux-Point-Studios/materios/issues/76)).
- Hand weights that never call `T::DbWeight`, so no schedule reaches them
  ([#88](https://github.com/Flux-Point-Studios/materios/issues/88)):
  `IntentSettlement`'s `settle_claim`, `expire_policy_mirror`,
  `credit_deposit`, `set_pool_utilization`, `set_min_signer_threshold` and
  `request_expire_policy`, both `Oracle` calls (materios-intent-settlement
  `0757de3`), 6 `Billing` calls, both `TeeAttestation` calls, and
  partner-chains' `BlockRewards`, `NativeTokenManagement` and session-key
  calls. Their storage stays unpriced until each is benchmarked.
- The treasury's per-block inactive-funds update returns no weight (SDK).

## Capacity

Normal-class ceilings, 1.5e12 ref_time, and Operational, 2e12; not live TPS.

| Workload | Before | After |
|---|---:|---:|
| Separately signed `transfer_keep_alive` | 920 | 854 |
| `submit_receipt` / `submit_receipt_v2`, declared | 955 | 619 |
| Separately signed non-threshold attestations, refunded (the cert-daemon's form) | 7,873 | 3,544 |
| Non-threshold attestations in pure Utility batches, refunded | 16,121 in 878 batches | 4,454 in 511 batches |
| Attestations admitted at their declared weight | 69 | 31 |
| `IntentSettlement.post_settlement_bond` | 1,325 | 1,136 |
| `IntentSettlement.release_settlement_bond` | 1,319 | 955 |
| `IntentSettlement.request_settle` | 1,413 | 819 |
| `IntentSettlement.request_batch_settle`, 256 entries | 77 | 8 |
| `IntentSettlement.attest_intent` | 1,276 | 1,016 |
| `IntentSettlement.attest_settle` | 176 | 163 |
| `IntentSettlement.attest_batch_intents`, 256 ids | 142 | 20 |
| `IntentSettlement.attest_batch_settle`, 256 claims | 5 | 3 |
| `IntentSettlement.settle_batch_atomic`, 256 entries | 140 | 25 |

Settlement's figures start from main's weights, settlement #55's generated
slots with the 1/4/1 checkpoint units on the bond paths.

An attestation's actual weight is now 409,979,500 with its signed base
(187,808,600 before), of which its five reads and one write take 225,000,000.
A block certifies about 3,544 / t receipts at threshold t from separate
extrinsics. The attestation figures were re-measured when certification came
to count only current committee members
([#89](https://github.com/Flux-Point-Studios/materios/issues/89)); see
[MOTRA accounting and dispatch weights](motra-checkpoint-weights.md).

## Fees

`min_fee + R * (base_extrinsic + call_weight + deferred_duty_weight + length * 381,469) / 1_000_000 + length_fee_per_byte * length`,
with the genesis `min_fee` of 1,000,000,000, `length_fee_per_byte` of
1,000,000 and R = 0. The signed base, 1,293,926,000, and the per-byte work are
unchanged. MOTRA has 15 decimals. At R = 0 a fee is its minimum and length
charge, so no fee changes at genesis.

Typical calls through the fee extension, after the post-dispatch refund (the
second figure is the escrow taken before dispatch, where they differ):

| R | Call | Bytes | Before | After | × |
|---:|---|---:|---:|---:|---:|
| 1,000,000,000 | transfer_keep_alive | 139 | 0.001684018 | 0.001809018 | 1.07 |
| 1,000,000,000 | remark | 106 | 0.001336605 | 0.001336605 | 1.00 |
| 1,000,000,000 | submit_receipt, threshold 2 of 3 | 395 | 0.003323116 / 0.003472001 | 0.006341609 / 0.006490494 | 1.91 |
| 1,000,000,000 | claim_motra | 105 | 0.002382099 | 0.002382099 | 1.00 |
| 1,000,000,000 | set_delegatee | 138 | 0.002496364 | 0.002496364 | 1.00 |
| 50,000,000,000 | transfer_keep_alive | 139 | 0.084145099 | 0.090395099 | 1.07 |
| 50,000,000,000 | remark | 106 | 0.066776079 | 0.066776079 | 1.00 |
| 50,000,000,000 | submit_receipt, threshold 2 of 3 | 395 | 0.166087451 / 0.173531701 | 0.317012072 / 0.324456322 | 1.91 |
| 50,000,000,000 | claim_motra | 105 | 0.119050817 | 0.119050817 | 1.00 |
| 50,000,000,000 | set_delegatee | 138 | 0.124762424 | 0.124762424 | 1.00 |

A committee member's attestation stays feeless.

A submission prepays its committee's certification, so its escrow tracks the
threshold (`pricing_submission_escrow_grows_with_the_threshold`, 96 members,
R = 1e9):

| Threshold | Before | After | × |
|---:|---:|---:|---:|
| 1 | 0.003085976 | 0.005628789 | 1.82 |
| 2 | 0.003472766 | 0.006491258 | 1.87 |
| 16 | 0.009041880 | 0.018609404 | **2.06** |
| 64 | 0.030351199 | 0.061054491 | **2.01** |
| 96 | 0.046448156 | 0.090245134 | 1.94 |

**More than 2×** (R = 1e9, at each call's worst case):

- `submit_receipt` and `submit_receipt_v2` at thresholds from 16 to 64,
  through the attestation storage their certification prepays;
- `OrinqReceipts.attest_availability_cert` on a paid path (a wrapper), 2.19×;
  direct duties stay feeless;
- `IntentSettlement.request_batch_settle` at 256 entries, 5.95×: a
  permissionless keeper call, 0.040 → 0.239 MOTRA;
- `IntentSettlement.attest_batch_intents` at 256 ids, 5.01×, and
  `settle_batch_atomic` at 256 entries, 3.66×, both paid by a committee
  member;
- `RootTimelock.cancel_all`, 4.12×, the guardian's veto, which is taken first
  whatever its fee.

The per-call table below prices each call at its audited worst case before
refunds, with the signed length of that encoding.

## Stuffing

`stuffers_of_weight_or_length_ramp_r_like_the_remark_ramp` fills 1,000 blocks
from R = 0 with each stuffer, admitted as the author admits it. Every stuffer
raises R at least as fast as the remark ramp at every block. The two
storage-priced Normal stuffers
fill the block in coarser steps and stop short of the remark ramp's fullness
by up to one call; the test requires their final R within 5% of the remark
ramp's and their cost within its 0.9×–10× band.

| Stuffer | Weight share before → after | Final R before → after | Cost (MOTRA) before → after |
|---|---:|---:|---:|
| Remark ramp | 74.98% | 49,978,920,005 | 38,631.10 |
| `request_batch_settle`, 0 entries | 99.96% → 99.97% | 50,000,000,000 | 51,598.46 → 51,351.52 |
| `request_batch_settle`, 256 entries | 99.54% → 89.80% (length 54.70% → 5.68%) | 50,000,000,000 | 77,047.77 → 47,695.23 |
| Normal-length remark | 0.14% | 50,000,000,000 | 37,536.71 |
| `transfer_keep_alive` | 74.97% → 74.93% | 49,964,440,000 → 49,909,744,445 | 38,658.58 → 38,507.24 |
| One block-filling `upgrade_accounts` | 75.00% → 73.99% | 49,995,726,001 → 48,650,172,222 | 40,264.20 → 37,483.83 |

No stuffer got cheaper per share of the block it holds than the remark ramp
(515 MOTRA per percent) by more than the step of its own call:

- `request_batch_settle` at 256 entries declares 223,211,611,664 ref_time, so
  8 copies fit where 77 did. They hold 89.80% of the weight and 5.68% of the
  length, where 77 held 99.54% and 54.70%, and pay 531 MOTRA per percent of
  weight held, 3% above the remark ramp. Its total cost fell 38% because it
  no longer buys half the block's length.
- `transfer_keep_alive` pays 0.3% less per share (0.1% more before).
- The single `upgrade_accounts` now declares at most the Normal per-call
  limit, so it holds 1% less of the block (the initialization reservation)
  and R ramps 2.7% slower; it pays 1.7% less per share than the remark ramp,
  against 4.2% more before.

## Reproducing

From `partnerchain/`, with an isolated `CARGO_TARGET_DIR`, inside the shared
build lock and `nice -n 10`:

```sh
SKIP_WASM_BUILD=1 cargo test -p materios-runtime --lib --locked -- --nocapture --test-threads 1
```

`AUDIT` lines carry each call's class, envelope, weight and signed length;
`PRICING`, `SUBMISSION`, the capacity and stuffer lines carry the rest. The
before figures come from the same tests on `67ec3d9`.

## Per-call weights and fees

Fees are MOTRA at each call's audited worst case, before refunds; the R = 0
fee is unchanged.

| Call | Class | Envelope | ref_time before | ref_time after | × | Bytes | Fee R=0 | Fee R=1e9 before → after | Fee R=5e10 before → after | >2× |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| System.remark | Normal | bounded | 1,522,840,707 | 1,522,840,707 | 1.00 | 3,932,160 | 0.00393316 | 1.50674707 → 1.50674707 | 75.144628647 → 75.144628647 |  |
| System.set_heap_pages | Operational | bounded | 229,109,000 | 229,109,000 | 1.00 | 113 | 0.000001113 | 0.001567254 → 0.001567254 | 0.078308163 → 0.078308163 |  |
| System.set_code | Operational | bounded | 82,130,651,000 | 82,130,651,000 | 1.00 | 106 | 0.000001106 | 0.083466119 → 0.083466119 | 4.173251742 → 4.173251742 |  |
| System.set_code_without_checks | Operational | bounded | 82,130,651,000 | 82,130,651,000 | 1.00 | 106 | 0.000001106 | 0.083466119 → 0.083466119 | 4.173251742 → 4.173251742 |  |
| System.set_storage | Operational | caller-sized | 2,192,000 | 2,192,000 | 1.00 | 106 | 0.000001106 | 0.00133766 → 0.00133766 | 0.066828792 → 0.066828792 |  |
| System.kill_storage | Operational | caller-sized | 2,159,000 | 2,159,000 | 1.00 | 106 | 0.000001106 | 0.001337627 → 0.001337627 | 0.066827142 → 0.066827142 |  |
| System.kill_prefix | Operational | caller-sized | 130,399,281 | 130,399,281 | 1.00 | 110 | 0.00000111 | 0.001467397 → 0.001467397 | 0.073315454 → 0.073315454 |  |
| System.remark_with_event | Normal | bounded | 5,472,042,574 | 5,472,042,574 | 1.00 | 3,932,160 | 0.00393316 | 1.510696272 → 1.510696272 | 75.342088741 → 75.342088741 |  |
| System.authorize_upgrade | Operational | bounded | 109,643,000 | 109,643,000 | 1.00 | 137 | 0.000001137 | 0.001456967 → 0.001456967 | 0.07279265 → 0.07279265 |  |
| System.authorize_upgrade_without_checks | Operational | bounded | 109,643,000 | 109,643,000 | 1.00 | 137 | 0.000001137 | 0.001456967 → 0.001456967 | 0.07279265 → 0.07279265 |  |
| System.apply_authorized_upgrade | Operational | bounded | 88,011,595,000 | 88,011,595,000 | 1.00 | 106 | 0.000001106 | 0.089347063 → 0.089347063 | 4.467298942 → 4.467298942 |  |
| Timestamp.set | Mandatory | bounded | 158,684,000 | 158,684,000 | 1.00 | 106 | — | — | — |  |
| Grandpa.note_stalled | Normal | bounded | 103,000,000 | 103,000,000 | 1.00 | 113 | 0.000001113 | 0.001441145 → 0.001441145 | 0.072002713 → 0.072002713 |  |
| Balances.transfer_allow_death | Normal | bounded | 346,133,000 | 471,133,000 | 1.36 | 139 | 0.000001139 | 0.001694222 → 0.001819222 | 0.084655299 → 0.090905299 |  |
| Balances.force_transfer | Normal | bounded | 347,714,000 | 597,714,000 | 1.72 | 172 | 0.000001172 | 0.001708425 → 0.001958425 | 0.085363805 → 0.097863805 |  |
| Balances.transfer_keep_alive | Normal | bounded | 335,929,000 | 460,929,000 | 1.37 | 139 | 0.000001139 | 0.001684018 → 0.001809018 | 0.084145099 → 0.090395099 |  |
| Balances.transfer_all | Normal | bounded | 345,155,000 | 470,155,000 | 1.36 | 139 | 0.000001139 | 0.001693244 → 0.001818244 | 0.084606399 → 0.090856399 |  |
| Balances.force_unreserve | Normal | bounded | 166,118,000 | 291,118,000 | 1.75 | 154 | 0.000001154 | 0.001519944 → 0.001644944 | 0.075940665 → 0.082190665 |  |
| Balances.upgrade_accounts | Normal | caller-sized | 16,588,000 | 16,588,000 | 1.00 | 106 | 0.000001106 | 0.001352056 → 0.001352056 | 0.067548592 → 0.067548592 |  |
| Balances.force_set_balance | Normal | bounded | 168,814,000 | 293,814,000 | 1.74 | 139 | 0.000001139 | 0.001516903 → 0.001641903 | 0.075789349 → 0.082039349 |  |
| Balances.force_adjust_total_issuance | Normal | bounded | 6,594,000 | 6,594,000 | 1.00 | 107 | 0.000001107 | 0.001342444 → 0.001342444 | 0.067067966 → 0.067067966 |  |
| Balances.burn | Normal | bounded | 169,596,000 | 169,596,000 | 1.00 | 107 | 0.000001107 | 0.001505446 → 0.001505446 | 0.075218066 → 0.075218066 |  |
| Sudo.sudo | Normal | caller-sized | 11,866,744 | 36,866,744 | 3.11 | 108 | 0.000001108 | 0.001348099 → 0.001373099 | 0.067350678 → 0.068600678 |  |
| Sudo.sudo_unchecked_weight | Normal | caller-sized | 0 | 0 | inf | 110 | 0.00000111 | 0.001336998 → 0.001336998 | 0.066795489 → 0.066795489 |  |
| Sudo.set_key | Normal | bounded | 9,663,000 | 134,663,000 | 13.94 | 138 | 0.000001138 | 0.00135737 → 0.00148237 | 0.067812724 → 0.074062724 |  |
| Sudo.sudo_as | Normal | caller-sized | 12,140,744 | 37,140,744 | 3.06 | 141 | 0.000001141 | 0.001360995 → 0.001385995 | 0.067993835 → 0.069243835 |  |
| Sudo.remove_key | Normal | bounded | 9,127,000 | 134,127,000 | 14.70 | 105 | 0.000001105 | 0.001344212 → 0.001469212 | 0.067156467 → 0.073406467 |  |
| Multisig.as_multi_threshold_1 | Normal | caller-sized | 22,501,848 | 197,501,848 | 8.78 | 397 | 0.000001397 | 0.001469268 → 0.001644268 | 0.073394949 → 0.082144949 |  |
| Multisig.as_multi | Normal | caller-sized | 193,959,845 | 493,959,845 | 2.55 | 402 | 0.000001402 | 0.001642638 → 0.001942638 | 0.082063221 → 0.097063221 |  |
| Multisig.approve_as_multi | Normal | caller-sized | 180,190,233 | 305,190,233 | 1.69 | 431 | 0.000001431 | 0.00163996 → 0.00176496 | 0.0819279 → 0.0881779 |  |
| Multisig.cancel_as_multi | Normal | bounded | 181,865,524 | 306,865,524 | 1.69 | 436 | 0.000001436 | 0.001643548 → 0.001768548 | 0.082107036 → 0.088357036 |  |
| Utility.batch | Operational | caller-sized | 2,694,370 | 52,694,370 | 19.56 | 106 | 0.000001106 | 0.001338162 → 0.001388162 | 0.06685391 → 0.06935391 |  |
| Utility.as_derivative | Normal | caller-sized | 10,776,744 | 185,776,744 | 17.24 | 110 | 0.00000111 | 0.001347774 → 0.001522774 | 0.067334327 → 0.076084327 |  |
| Utility.batch_all | Operational | caller-sized | 12,948,874 | 62,948,874 | 4.86 | 106 | 0.000001106 | 0.001348417 → 0.001398417 | 0.067366635 → 0.069866635 |  |
| Utility.dispatch_as | Normal | caller-sized | 8,589,744 | 8,589,744 | 1.00 | 110 | 0.00000111 | 0.001345587 → 0.001345587 | 0.067224977 → 0.067224977 |  |
| Utility.force_batch | Operational | caller-sized | 4,879,712 | 54,879,712 | 11.25 | 106 | 0.000001106 | 0.001340347 → 0.001390347 | 0.066963177 → 0.069463177 |  |
| Utility.with_weight | Normal | caller-sized | 0 | 0 | inf | 110 | 0.00000111 | 0.001336998 → 0.001336998 | 0.066795489 → 0.066795489 |  |
| Treasury.spend_local | Normal | bounded | 12,681,000 | 362,681,000 | 28.60 | 139 | 0.000001139 | 0.00136077 → 0.00171077 | 0.067982699 → 0.085482699 |  |
| Treasury.remove_approval | Operational | bounded | 6,567,000 | 131,567,000 | 20.03 | 106 | 0.000001106 | 0.001342035 → 0.001467035 | 0.067047542 → 0.073297542 |  |
| Treasury.spend | Normal | bounded | 14,842,000 | 264,842,000 | 17.84 | 139 | 0.000001139 | 0.001362931 → 0.001612931 | 0.068090749 → 0.080590749 |  |
| Treasury.payout | Normal | bounded | 359,061,000 | 984,061,000 | 2.74 | 109 | 0.000001109 | 0.001695676 → 0.002320676 | 0.084729465 → 0.115979465 |  |
| Treasury.check_status | Normal | bounded | 12,480,000 | 137,480,000 | 11.02 | 109 | 0.000001109 | 0.001349095 → 0.001474095 | 0.067400415 → 0.073650415 |  |
| Treasury.void_spend | Normal | bounded | 11,427,000 | 136,427,000 | 11.94 | 109 | 0.000001109 | 0.001348042 → 0.001473042 | 0.067347765 → 0.073597765 |  |
| Vesting.vest | Normal | bounded | 187,673,238 | 462,673,238 | 2.47 | 105 | 0.000001105 | 0.001522758 → 0.001797758 | 0.076083779 → 0.089833779 |  |
| Vesting.vest_other | Normal | bounded | 189,575,721 | 589,575,721 | 3.11 | 138 | 0.000001138 | 0.001537282 → 0.001937282 | 0.07680836 → 0.09680836 |  |
| Vesting.vested_transfer | Normal | bounded | 526,274,160 | 926,274,160 | 1.76 | 174 | 0.000001174 | 0.00188775 → 0.00228775 | 0.094329962 → 0.114329962 |  |
| Vesting.force_vested_transfer | Normal | bounded | 528,526,615 | 1,053,526,615 | 1.99 | 207 | 0.000001207 | 0.001902624 → 0.002427624 | 0.095072042 → 0.121322042 |  |
| Vesting.merge_schedules | Normal | bounded | 190,693,587 | 590,693,587 | 3.10 | 113 | 0.000001113 | 0.001528839 → 0.001928839 | 0.076387392 → 0.096387392 |  |
| Vesting.force_remove_vesting_schedule | Normal | bounded | 192,732,245 | 592,732,245 | 3.08 | 142 | 0.000001142 | 0.001541969 → 0.001941969 | 0.077042484 → 0.097042484 |  |
| OrinqReceipts.submit_receipt | Normal | bounded | 275,759,000 | 1,125,759,000 | 4.08 | 395 | 0.000001395 | 0.00172176 → 0.00257176 | 0.086019658 → 0.128519658 |  |
| OrinqReceipts.set_availability_cert | Normal | bounded | 216,434,000 | 691,434,000 | 3.19 | 169 | 0.000001169 | 0.001575997 → 0.002050997 | 0.078742582 → 0.102492582 |  |
| OrinqReceipts.set_committee | Normal | bounded | 10,000 | 200,010,000 | 20001.00 | 3,183 | 0.000004183 | 0.002512335 → 0.002712335 | 0.125411774 → 0.135411774 |  |
| OrinqReceipts.attest_availability_cert | Normal | bounded | 20,225,691,650 | 45,935,723,240 | 2.27 | 169 | 0.000001169 | 0.021585255 → 0.047295287 | 1.079205465 → 2.364707044 | ! |
| OrinqReceipts.submit_anchor | Normal | bounded | 10,000 | 125,010,000 | 12501.00 | 233 | 0.000001233 | 0.001384051 → 0.001509051 | 0.069142147 → 0.075392147 |  |
| OrinqReceipts.submit_receipt_v2 | Normal | bounded | 275,759,000 | 1,125,759,000 | 4.08 | 492 | 0.000001492 | 0.00175886 → 0.00260886 | 0.087869879 → 0.130369879 |  |
| OrinqReceipts.join_committee | Normal | bounded | 10,000 | 150,010,000 | 15001.00 | 137 | 0.000001137 | 0.001347334 → 0.001497334 | 0.067311 → 0.074811 |  |
| OrinqReceipts.leave_committee | Normal | bounded | 10,000 | 250,010,000 | 25001.00 | 137 | 0.000001137 | 0.001347334 → 0.001597334 | 0.067311 → 0.079811 |  |
| OrinqReceipts.set_attestation_reward_per_signer | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 121 | 0.000001121 | 0.001341215 → 0.001441215 | 0.067005808 → 0.072005808 |  |
| OrinqReceipts.set_era_cap_base | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 121 | 0.000001121 | 0.001341215 → 0.001441215 | 0.067005808 → 0.072005808 |  |
| OrinqReceipts.set_era_cap_baseline_attestor_count | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 109 | 0.000001109 | 0.001336625 → 0.001436625 | 0.066776915 → 0.071776915 |  |
| OrinqReceipts.bond | Normal | bounded | 202,527,000 | 452,527,000 | 2.23 | 121 | 0.000001121 | 0.001543732 → 0.001793732 | 0.077131658 → 0.089631658 |  |
| OrinqReceipts.unbond | Normal | bounded | 230,310,000 | 505,310,000 | 2.19 | 105 | 0.000001105 | 0.001565395 → 0.001840395 | 0.078215617 → 0.091965617 |  |
| OrinqReceipts.slash_attestor | Normal | bounded | 408,521,000 | 1,058,521,000 | 2.59 | 154 | 0.000001154 | 0.001762347 → 0.002412347 | 0.088060815 → 0.120560815 |  |
| OrinqReceipts.set_bond_requirement | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 121 | 0.000001121 | 0.001341215 → 0.001441215 | 0.067005808 → 0.072005808 |  |
| OrinqReceipts.set_receipt_submission_fee | Normal | bounded | 10,000 | 125,010,000 | 12501.00 | 121 | 0.000001121 | 0.001341215 → 0.001466215 | 0.067005808 → 0.073255808 |  |
| OrinqReceipts.set_receipt_submission_fee_floor | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 121 | 0.000001121 | 0.001341215 → 0.001441215 | 0.067005808 → 0.072005808 |  |
| OrinqReceipts.set_receipt_expiry_blocks | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 109 | 0.000001109 | 0.001336625 → 0.001436625 | 0.066776915 → 0.071776915 |  |
| OrinqReceipts.expire_receipt_fee | Normal | bounded | 219,519,000 | 644,519,000 | 2.94 | 137 | 0.000001137 | 0.001566843 → 0.001991843 | 0.07828645 → 0.09953645 |  |
| OrinqReceipts.set_bad_attest_slash_threshold | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 109 | 0.000001109 | 0.001336625 → 0.001436625 | 0.066776915 → 0.071776915 |  |
| OrinqReceipts.reset_candidate_liveness | Normal | bounded | 10,000 | 200,010,000 | 20001.00 | 137 | 0.000001137 | 0.001347334 → 0.001547334 | 0.067311 → 0.077311 |  |
| OrinqReceipts.set_core_eviction_enabled | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 106 | 0.000001106 | 0.001335478 → 0.001435478 | 0.066719692 → 0.071719692 |  |
| OrinqReceipts.set_contribution_window_enabled | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 106 | 0.000001106 | 0.001335478 → 0.001435478 | 0.066719692 → 0.071719692 |  |
| OrinqReceipts.set_break_glass_floor_enabled | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 106 | 0.000001106 | 0.001335478 → 0.001435478 | 0.066719692 → 0.071719692 |  |
| OrinqReceipts.set_slack_invariant_enabled | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 106 | 0.000001106 | 0.001335478 → 0.001435478 | 0.066719692 → 0.071719692 |  |
| OrinqReceipts.set_break_glass_aura_keys | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 3,179 | 0.000004179 | 0.002510805 → 0.002610805 | 0.125335477 → 0.130335477 |  |
| OrinqReceipts.set_pinned_committee | Normal | bounded | 20,000 | 100,020,000 | 5001.00 | 3,218 | 0.000004218 | 0.002525731 → 0.002625731 | 0.12607988 → 0.13107988 |  |
| OrinqReceipts.clear_pinned_committee | Normal | bounded | 10,000 | 100,010,000 | 10001.00 | 105 | 0.000001105 | 0.001335095 → 0.001435095 | 0.066700617 → 0.071700617 |  |
| Motra.set_delegatee | Normal | bounded | 1,148,657,000 | 1,148,657,000 | 1.00 | 106 | 0.000001106 | 0.002484125 → 0.002484125 | 0.124152042 → 0.124152042 |  |
| Motra.set_params | Normal | bounded | 15,000,000 | 15,000,000 | 1.00 | 213 | 0.000001213 | 0.001391392 → 0.001391392 | 0.069510158 → 0.069510158 |  |
| Motra.claim_motra | Normal | bounded | 1,047,014,000 | 1,047,014,000 | 1.00 | 105 | 0.000001105 | 0.002382099 → 0.002382099 | 0.119050817 → 0.119050817 |  |
| SessionCommitteeManagement.set | Mandatory | bounded | 232,064,398 | 382,064,398 | 1.65 | 3,250 | — | — | — |  |
| SessionCommitteeManagement.set_main_chain_scripts | Normal | bounded | 181,914,365 | 331,914,365 | 1.82 | 162 | 0.000001162 | 0.0015388 → 0.0016888 | 0.076883079 → 0.084383079 |  |
| BlockRewards.set_current_block_beneficiary | Mandatory | bounded | 0 | 0 | inf | 137 | — | — | — |  |
| PalletSession.set_keys | Normal | bounded | 959,558,000 | 959,558,000 | 1.00 | 170 | 0.00000117 | 0.002319504 → 0.002319504 | 0.115917856 → 0.115917856 |  |
| PalletSession.purge_keys | Normal | bounded | 792,476,000 | 792,476,000 | 1.00 | 105 | 0.000001105 | 0.002127561 → 0.002127561 | 0.106323917 → 0.106323917 |  |
| NativeTokenManagement.transfer_tokens | Mandatory | bounded | 0 | 0 | inf | 121 | — | — | — |  |
| NativeTokenManagement.set_main_chain_scripts | Normal | bounded | 1 | 1 | 1.00 | 135 | 0.000001135 | 0.001346559 → 0.001346559 | 0.067272351 → 0.067272351 |  |
| IntentSettlement.submit_intent | Normal | bounded | 1,365,428,000 | 2,040,428,000 | 1.49 | 114 | 0.000001114 | 0.002703955 → 0.003378955 | 0.135143187 → 0.168893187 |  |
| IntentSettlement.attest_intent | Operational | bounded | 273,095,676 | 673,095,676 | 2.46 | 233 | 0.000001233 | 0.001657137 → 0.002057137 | 0.082796431 → 0.102796431 |  |
| IntentSettlement.request_voucher | Operational | bounded | 10,084,316,676 | 10,734,316,676 | 1.06 | 9,528 | 0.000010528 | 0.015023407 → 0.015673407 | 0.750654493 → 0.783154493 |  |
| IntentSettlement.request_credit_refund | Normal | bounded | 1,357,664,000 | 2,007,664,000 | 1.48 | 113 | 0.000001113 | 0.002695809 → 0.003345809 | 0.134735913 → 0.167235913 |  |
| IntentSettlement.settle_claim | Operational | bounded | 8,707,481,676 | 8,707,481,676 | 1.00 | 9,388 | 0.000010388 | 0.013593027 → 0.013593027 | 0.67914232 → 0.67914232 |  |
| IntentSettlement.expire_policy_mirror | Operational | bounded | 30,000,000 | 30,000,000 | 1.00 | 137 | 0.000001137 | 0.001377324 → 0.001377324 | 0.0688105 → 0.0688105 |  |
| IntentSettlement.credit_deposit | Operational | bounded | 8,687,481,676 | 8,687,481,676 | 1.00 | 9,395 | 0.000010395 | 0.013575704 → 0.013575704 | 0.678275842 → 0.678275842 |  |
| IntentSettlement.set_pool_utilization | Operational | bounded | 10,000,000 | 10,000,000 | 1.00 | 129 | 0.000001129 | 0.001354265 → 0.001354265 | 0.067657904 → 0.067657904 |  |
| IntentSettlement.set_min_signer_threshold | Operational | bounded | 10,000,000 | 10,000,000 | 1.00 | 109 | 0.000001109 | 0.001346615 → 0.001346615 | 0.067276415 → 0.067276415 |  |
| IntentSettlement.settle_batch_atomic | Operational | bounded | 12,919,447,956 | 77,219,447,956 | 5.98 | 25,967 | 0.000026967 | 0.024145946 → 0.088445946 | 1.205975941 → 4.420975941 | ! |
| IntentSettlement.attest_batch_intents | Operational | bounded | 12,760,957,476 | 96,010,957,476 | 7.52 | 17,519 | 0.000018519 | 0.020756358 → 0.104006358 | 1.036910463 → 5.199410463 | ! |
| IntentSettlement.request_batch_vouchers | Operational | bounded | 384,399,003,564 | 474,299,003,564 | 1.23 | 61,807 | 0.000062807 | 0.409333191 → 0.499233191 | 20.463582009 → 24.958582009 |  |
| IntentSettlement.submit_batch_intents | Normal | bounded | 351,446,419,345 | 383,996,419,345 | 1.09 | 2,411 | 0.000003411 | 0.353663478 → 0.386213478 | 17.683006766 → 19.310506766 |  |
| IntentSettlement.request_settle | Operational | bounded | 120,780,000 | 1,145,780,000 | 9.49 | 298 | 0.000001298 | 0.001529682 → 0.002554682 | 0.076420486 → 0.127670486 |  |
| IntentSettlement.attest_settle | Operational | bounded | 10,058,508,676 | 10,958,508,676 | 1.09 | 9,355 | 0.000010355 | 0.014931432 → 0.015831432 | 0.746064214 → 0.791064214 |  |
| IntentSettlement.supersede_settlement_request | Operational | bounded | 10,109,284,676 | 11,384,284,676 | 1.13 | 9,468 | 0.000010468 | 0.015025427 → 0.016300427 | 0.750758426 → 0.814508426 |  |
| IntentSettlement.request_batch_settle | Operational | bounded | 24,561,611,664 | 223,211,611,664 | 9.09 | 37,245 | 0.000038245 | 0.040101596 → 0.238751596 | 2.003205773 → 11.935705773 | ! |
| IntentSettlement.attest_batch_settle | Operational | bounded | 371,721,460,684 | 525,621,460,684 | 1.41 | 17,519 | 0.000018519 | 0.379716861 → 0.533616861 | 18.984935624 → 26.679935624 |  |
| IntentSettlement.request_expire_policy | Operational | bounded | 35,000,000 | 35,000,000 | 1.00 | 277 | 0.000001277 | 0.00143587 → 0.00143587 | 0.071730923 → 0.071730923 |  |
| IntentSettlement.attest_expire_policy | Operational | bounded | 10,111,598,676 | 10,536,598,676 | 1.04 | 9,355 | 0.000010355 | 0.014984522 → 0.015409522 | 0.748718714 → 0.769968714 |  |
| IntentSettlement.post_settlement_bond | Operational | bounded | 214,781,000 | 465,896,000 | 2.17 | 153 | 0.000001153 | 0.001568225 → 0.00181934 | 0.078354741 → 0.090910491 |  |
| IntentSettlement.slash_bad_settlement_evidence | Operational | bounded | 9,390,844,676 | 9,820,304,676 | 1.05 | 9,356 | 0.000010356 | 0.014264151 → 0.014693611 | 0.712700088 → 0.734173088 |  |
| IntentSettlement.release_settlement_bond | Operational | bounded | 222,104,000 | 798,219,000 | 3.59 | 137 | 0.000001137 | 0.001569428 → 0.002145543 | 0.0784157 → 0.10722145 |  |
| TeeAttestation.submit_evidence | Normal | bounded | 1,000,000,000 | 1,000,000,000 | 1.00 | 16,560 | 0.00001756 | 0.008628613 → 0.008628613 | 0.430570192 → 0.430570192 |  |
| TeeAttestation.set_disabled | Normal | bounded | 1,000,000,000 | 1,000,000,000 | 1.00 | 106 | 0.000001106 | 0.002335468 → 0.002335468 | 0.116719192 → 0.116719192 |  |
| Billing.topup_self | Normal | bounded | 204,672,000 | 579,672,000 | 2.83 | 121 | 0.000001121 | 0.001545877 → 0.001920877 | 0.077238908 → 0.095988908 |  |
| Billing.topup_for | Normal | bounded | 197,738,000 | 572,738,000 | 2.90 | 153 | 0.000001153 | 0.001551182 → 0.001926182 | 0.077502591 → 0.096252591 |  |
| Billing.pay_request | Normal | bounded | 60,000,000 | 60,000,000 | 1.00 | 162 | 0.000001162 | 0.001416886 → 0.001416886 | 0.070787361 → 0.070787361 |  |
| Billing.governance_set_endpoint_price | Normal | bounded | 20,000,000 | 20,000,000 | 1.00 | 123 | 0.000001123 | 0.00136197 → 0.00136197 | 0.068043457 → 0.068043457 |  |
| Billing.request_withdrawal | Normal | bounded | 35,000,000 | 35,000,000 | 1.00 | 121 | 0.000001121 | 0.001376205 → 0.001376205 | 0.068755308 → 0.068755308 |  |
| Billing.execute_withdrawal | Normal | bounded | 373,654,000 | 748,654,000 | 2.00 | 105 | 0.000001105 | 0.001708739 → 0.002083739 | 0.085382817 → 0.104132817 |  |
| Billing.cancel_withdrawal | Normal | bounded | 25,000,000 | 25,000,000 | 1.00 | 105 | 0.000001105 | 0.001360085 → 0.001360085 | 0.067950117 → 0.067950117 |  |
| Billing.prune_paid_requests | Normal | bounded | 1,290,000,000 | 1,290,000,000 | 1.00 | 16,493 | 0.000017493 | 0.008892987 → 0.008892987 | 0.443792204 → 0.443792204 |  |
| Billing.governance_set_debits_enabled | Normal | bounded | 20,000,000 | 20,000,000 | 1.00 | 106 | 0.000001106 | 0.001355468 → 0.001355468 | 0.067719192 → 0.067719192 |  |
| Oracle.submit_price | Normal | bounded | 500,000,000 | 500,000,000 | 1.00 | 250 | 0.00000125 | 0.001890543 → 0.001890543 | 0.094465912 → 0.094465912 |  |
| Oracle.register_attestor | Normal | bounded | 100,000,000 | 100,000,000 | 1.00 | 169 | 0.000001169 | 0.001459563 → 0.001459563 | 0.072920882 → 0.072920882 |  |
| Recovery.as_recovered | Normal | caller-sized | 16,904,744 | 91,904,744 | 5.44 | 141 | 0.000001141 | 0.001365759 → 0.001440759 | 0.068232035 → 0.071982035 |  |
| Recovery.set_recovered | Normal | bounded | 7,578,000 | 107,578,000 | 14.20 | 171 | 0.000001171 | 0.001367906 → 0.001467906 | 0.068337931 → 0.073337931 |  |
| Recovery.create_recovery | Normal | bounded | 173,732,900 | 298,732,900 | 1.72 | 400 | 0.0000014 | 0.001621646 → 0.001746647 | 0.081013725 → 0.087263725 |  |
| Recovery.initiate_recovery | Normal | bounded | 176,926,000 | 326,926,000 | 1.85 | 138 | 0.000001138 | 0.001524633 → 0.001674633 | 0.076175874 → 0.083675874 |  |
| Recovery.vouch_recovery | Normal | bounded | 20,289,654 | 170,289,654 | 8.39 | 171 | 0.000001171 | 0.001380618 → 0.001530618 | 0.068973514 → 0.076473514 |  |
| Recovery.claim_recovery | Normal | bounded | 24,735,080 | 199,735,080 | 8.07 | 138 | 0.000001138 | 0.001372442 → 0.001547442 | 0.068566328 → 0.077316328 |  |
| Recovery.close_recovery | Normal | bounded | 332,030,649 | 582,030,649 | 1.75 | 138 | 0.000001138 | 0.001679737 → 0.001929737 | 0.083931107 → 0.096431107 |  |
| Recovery.remove_recovery | Normal | bounded | 179,664,547 | 329,664,547 | 1.83 | 105 | 0.000001105 | 0.00151475 → 0.00166475 | 0.075683345 → 0.083183345 |  |
| Recovery.cancel_recovered | Normal | bounded | 12,275,000 | 137,275,000 | 11.18 | 138 | 0.000001138 | 0.001359982 → 0.001484982 | 0.067943324 → 0.074193324 |  |
| RootTimelock.schedule | Normal | caller-sized | 50,006,000 | 575,006,000 | 11.50 | 108 | 0.000001108 | 0.001386239 → 0.001911239 | 0.069257641 → 0.095507641 |  |
| RootTimelock.cancel | Operational | bounded | 20,000,000 | 420,000,000 | 21.00 | 109 | 0.000001109 | 0.001356615 → 0.001756615 | 0.067776415 → 0.087776415 |  |
| RootTimelock.fast_track | Operational | bounded | 20,000,000 | 170,000,000 | 8.50 | 109 | 0.000001109 | 0.001356615 → 0.001506615 | 0.067776415 → 0.075276415 |  |
| RootTimelock.enact | Normal | caller-sized | 51,143,744 | 451,143,744 | 8.82 | 112 | 0.000001112 | 0.001388906 → 0.001788906 | 0.069390826 → 0.089390826 |  |
| RootTimelock.set_delay | Normal | bounded | 20,000,000 | 145,000,000 | 7.25 | 110 | 0.00000111 | 0.001356998 → 0.001481998 | 0.06779549 → 0.07404549 |  |
| RootTimelock.set_guardian | Normal | bounded | 20,000,000 | 220,000,000 | 11.00 | 106 | 0.000001106 | 0.001355468 → 0.001555468 | 0.067719192 → 0.077719192 |  |
| RootTimelock.cancel_all | Operational | bounded | 1,320,000,000 | 9,595,000,000 | 7.27 | 105 | 0.000001105 | 0.002655085 → 0.010930085 | 0.132700117 → 0.546450117 | ! |
| RootTimelock.prune | Normal | bounded | 20,000,000 | 370,000,000 | 18.50 | 109 | 0.000001109 | 0.001356615 → 0.001706615 | 0.067776415 → 0.085276415 |  |
| RootTimelock.approve | Operational | bounded | 20,000,000 | 145,000,000 | 7.25 | 106 | 0.000001106 | 0.001355468 → 0.001480468 | 0.067719192 → 0.073969192 |  |
| RootTimelock.enact_approved | Normal | caller-sized | 51,143,744 | 451,143,744 | 8.82 | 108 | 0.000001108 | 0.001387376 → 0.001787376 | 0.069314528 → 0.089314528 |  |
