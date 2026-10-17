# MOTRA checkpoint weight accounting

Balance changes never register weight after admission. The runtime adds account
checkpoint costs to the owning dispatch's `WeightInfo`, so `CheckWeight` admits
the complete cost and Utility, Multisig and RootTimelock retain it when summing
inner calls and returning actual weight.

`checkpoint_weight` uses the generated MOTRA `WeightInfo::checkpoint`. Its
benchmark executes the account-store path against an existing checkpoint with
`LegacyAccrualStart` set, including a preceding legacy free-balance repair.
Both visits use the same checkpoint key: one database read and one database
write, with the repeated overlay accesses included in measured execution time.
`System.Account` is whitelisted because its cost belongs to the base Balances
weight; `System.Number` uses FRAME's standard whitelist. The checkpoint key is
not whitelisted. Proof size uses storage information and `MaxEncodedLen`.
The database cost retains the RocksDB floor when `System.DbWeight` is zero.

`balance_weights::mutations(n)` adds one benchmarked checkpoint per account.
Transfers budget two, including a reaped sender; reserve and unreserve budget
one. Dust burns issuance (`DustRemoval = ()`) without crediting a third account.
Dispatch annotations are admission bounds: zero-value, self-transfer, failed,
and unchanged-balance calls can use fewer entries than their declared maximum.

System account creation no longer writes a MOTRA decay clock. A zero MOTRA
balance has no decay; reconciliation sets `LastTouched` when it generates MOTRA.
Existing sponsored balances retain their previous clock, including the default
zero clock when no reconciliation has occurred. First funding starts generation
at the holding checkpoint, independently of account creation time.
On the first delegated credit to an account with zero stored MOTRA and no decay
clock, reconciliation initializes the clock from its holding checkpoint (or zero
if never funded). This preserves its unclaimed MATRA generation interval and
pre-funding sponsorship history. A separate benchmark prices that work; transfers
do not pay for it.

The pinned SDK is `polkadot-sdk` revision `c455194a`. Its
[balances mutation helpers](https://github.com/paritytech/polkadot-sdk/blob/c455194a2ae2f613c1c671e00dbf397b83ed8171/substrate/frame/balances/src/lib.rs)
invoke `ensure_upgraded` before changing account data. Its
[Utility weight calculation and refunds](https://github.com/paritytech/polkadot-sdk/blob/c455194a2ae2f613c1c671e00dbf397b83ed8171/substrate/frame/utility/src/lib.rs)
both use the inner calls' dispatch information.
The settlement dependency routes its three bond calls through `WeightInfo`;
dispatch-information regressions in both repositories enforce that wiring,
including the existing operational class and fee policy.
No call indices, origins, SignedExtra fields or transaction-version changes are
needed.

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
| Receipt attestation | `3 * MaxCommitteeSize + 3`; signer mint and two-account fee distribution per signer, treasury distribution and fallback refund; also covers bad-attestation slashing |
| Receipt era rewards | Hook returns one mutation budget per validator/treasury deposit actually attempted |
| Fee-router pot migration | 4; two transfers |
| Perp removal migration | One per released bond plus 2 for its pot transfer; at most 1,000 bond entries per upgrade |
| Native token transfer inherent | 0; runtime handler records the observation without minting MATRA |
| Genesis | No block admission; hooks write state without registering block weight |

Receipt era rewards run once per 14,400 blocks and visit `BlocksAuthored`; each
block records at most one author. Their returned initialization weight includes
every balance mutation. This is an initialization cost, not an unchecked
dispatch surcharge; the existing author-map traversal is not benchmarked by
these checkpoint bounds.

Reconciliation includes the checkpoint and first delegated-credit clock budgets
in `claim_motra` and `set_delegatee`. Fee reconciliation is covered once per extrinsic by
`RuntimeBlockWeights.base_extrinsic`, before `ChargeMotra` runs. Validation
executes against discarded storage and does not consume a block. The account
store accepts only `u128` balances, so reading its free balance is infallible;
the generic projection path uses a saturating conversion.

The runtime regression dispatches a Utility batch that fills the remaining
block budget, checks its transfers and post-dispatch refund, rejects another
transfer, and finalizes within `max_block`. Separate tests check transfer and
Currency-caller dispatch budgets, returned reward-hook weight, absence of
unchecked hook/reconciliation weight, and preservation of `u128::MAX`. A property
test dispatches every Balances call plus reserve/unreserve against generated
normal and legacy states, commits setup before each call, observes actual
checkpoint keys in the storage overlay, and checks the declared weight covers
them. The base-weight match is exhaustive over the pinned Balances call enum.

## Gemtek measurement, 2026-10-17

Hardware: Gemtek (`deci-desktop`), AMD Ryzen 7 7730U, 8 cores / 16 threads,
28 GiB RAM, Linux 6.17.0-22-generic. Builds and execution run through
`flock /tmp/materios-cargo-build.lock nice -n 10`, with four Cargo jobs.
The Wasm uses Rust 1.85.0 and pinned SDK `c455194a`.
`frame-omni-bencher 0.7.0` embeds benchmark CLI 43.0.0.

From `partnerchain/`, with a worktree-specific `CARGO_TARGET_DIR` and
`WASM_BUILD_WORKSPACE_HINT` pointing to the worktree's `partnerchain/` directory:

```sh
cargo build -p materios-runtime --features runtime-benchmarks --locked
touch pallets/motra/src/checkpoint_weights.rs
frame-omni-bencher v1 benchmark pallet \
  --runtime "$CARGO_TARGET_DIR/debug/wbuild/materios-runtime/materios_runtime.wasm" \
  --pallet pallet_motra --extrinsic checkpoint \
  --steps 50 --repeat 100 --external-repeat 5 --output-analysis max \
  --map-size 1000000 --additional-trie-layers 2 \
  --genesis-builder runtime --genesis-builder-preset development \
  --template pallets/motra/benchmarking/checkpoint-weight.hbs \
  --output pallets/motra/src/checkpoint_weights.rs \
  --json-file checkpoint-benchmark.json
rustfmt --edition 2021 pallets/motra/src/checkpoint_weights.rs
```

The benchmark records one read and one write, 229 measured proof bytes, and a
68-byte maximum encoded map entry. The bound is `68 + 7 * 495 = 3,533` bytes
(five map trie layers plus two top-level layers). Measured execution is
23,885,000 ref_time; adding RocksDB's 25,000,000/read and 100,000,000/write gives
**148,885,000 ref_time / 3,533 proof bytes per account**. The generated file and
template retain these inputs; the runtime regression independently derives the
proof bound from `StorageInfo`.
The raw samples are retained in
`partnerchain/pallets/motra/benchmarking/checkpoint-samples.json.gz`.
The measured Wasm SHA-256 is
`a91044ae7c4583cb877e236bf8729429dd7e3f653c44ca3a976123cc7a1e9657`.

`initialize_delegatee_clock` is measured separately with a missing recipient
clock, a populated clock map, and an existing holding checkpoint. It measures
15,891,000 execution ref_time, two reads and one write: **165,891,000 total**.
The two independent storage proof bounds are 3,517 bytes (`LastTouched`, max_size
52) and 3,533 bytes (`AccrualCheckpoint`, max_size 68), totaling **7,050 bytes**.
The CLI selects a maximum across storage prefixes; the template sums the two
bounds for this benchmark. The regression independently sums `StorageInfo` bounds.
Reconciliation therefore reserves 314,776,000 ref_time / 10,583 proof bytes.
Reproduce with the same command using `--extrinsic initialize_delegatee_clock`,
`--output pallets/motra/src/delegatee_clock_weights.rs`, and a separate JSON path.
Raw samples are in `benchmarking/delegatee-clock-samples.json.gz` under the pallet.
Its measured Wasm SHA-256 is
`fdac7ed9d01787291c90857bf390e9f1db763e2629b74614f26509db26b1f23d`.

| Call | Before ref_time / proof bytes | After ref_time / proof bytes |
| --- | ---: | ---: |
| `transfer_keep_alive` | 1,238,159,000 / 87,593 | 335,929,000 / 10,659 |
| `transfer_allow_death` | 1,248,363,000 / 87,593 | 346,133,000 / 10,659 |
| `force_transfer` | 1,249,944,000 / 90,196 | 347,714,000 / 13,262 |
| reserve/unreserve checkpoint surcharge | 600,000,000 / 42,000 | 148,885,000 / 3,533 |
| settlement bond/release, including base | 1,100,000,000 / 42,000 | 648,885,000 / 3,533 |
| settlement slash, including base | 2,900,000,000 / 168,000 | 1,095,540,000 / 14,132 |

Reserve/unreserve are Currency methods, not standalone Balances dispatches;
their caller supplies the base weight. Settlement's base remains 500,000,000.

The same block-limit Utility batch test increases from **1,206 to 4,398
transfers** (3.65×), includes fee reconciliation and post-dispatch refunds,
rejects the next transfer, and finalizes at 2,000,000,000,000 ref_time. Its normal
dispatch budget is 75% of the block. This is an admission-capacity measurement,
not a live-network TPS claim. The earlier approximately 52k figure omitted
checkpoint costs and used the entire block's compute allowance; measured
checkpoint/database costs remain real, so that figure is not restored.
