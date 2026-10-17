# Runtime database weights: ce89715 → DbWeight audit candidate

**Safety verdict: incomplete / do not merge for genesis.** The database-pricing
change is measured, and all 141 encodable dispatchable variants are inventoried.
The full hook/migration safety statement requested by #71 is false for the
current substrate. Three executable counterexamples and additional source
findings are listed below. Green unit/CI results demonstrate the pricing
regressions and reproduce these blockers; they do not approve block safety.

Baseline: `ce897154df80816a0929e9917d693c1dd77fc84b` (PR #68).
Candidate remains unreleased spec241 / transaction5, stacked on #68. No deployment,
upgrade authorization, transaction broadcast or live validator change is part of
this work.

## What changes

`frame_system::Config::DbWeight = RocksDbWeight`: 25,000,000 ref_time/read and
100,000,000/write. Checkpoint/reconciliation/fee, migration and Root classifier
work now use this one runtime schedule. Their pre-existing RocksDB prices are
preserved. Tests pin checkpoint 148,885,000; reconciliation 1,048,197,000;
fee 1,164,660,000; claim 1,047,014,000; delegation 1,148,657,000.

Threshold attestation samples contain `15+3n` reads / `10+3n` writes. Each
threshold touches `n+1` checkpoint keys, priced separately; the retained base is
therefore `14+2n` reads / `9+2n` writes, in both normal and dead-treasury paths.
A nonzero synthetic schedule checks every committed benchmark sample. This
removes 97 duplicated reads and writes at n=96 (12,125,000,000 ref_time).

Normal/Operational `max_extrinsic` were both `None`. They now explicitly equal
the existing class total minus the signed base. This changes pool validation
for oversized individual calls, without increasing a block's dispatch budget.
It does **not** reserve or repair hook work. Mandatory inherents still require
separate aggregate accounting.

## Dispatch audit and its exact scope

The test walks `RuntimeCall`'s live scale-info registry, decodes every variant,
and asks its actual `GetDispatchInfo`. A committed baseline name set makes new
or removed dispatchables fail the audit. Both disabled GRANDPA equivocation
variants have uninhabited key-owner proofs and cannot be encoded; they are
explicitly identified, not silently omitted. The other 141 variants are covered.

Bounded weight-driving arguments: receipt committee 96; session committee 32
(the actual runtime MaxValidators, distinct from the 96 attestors); settlement
batch caps 256 and 96 signature slots; Multisig 9 other signatories; Recovery 9
friends; Billing prune 256; TEE payload 16 KiB; Vesting's declared MaxLocks 50 and
MAX_VESTING_SCHEDULES; Treasury's declared weights. Large remark cases use
3,932,000 bytes within the normal encoded-length limit. A separate test checks
both remark declarations at the full normal encoded-length ceiling, ignoring
envelope overhead to provide a conservative upper bound. Constants and current
storage determine the other finite declarations. The fixture uses smallest
encodings for fields that do not affect declared weight, not a claim that all
payloads have that length or execute successfully.

The rows marked `E` have an input-dependent admission envelope: storage-vector
counts, recursive calls, or caller-supplied Weight. Their sample is **not a
finite worst case**. Such APIs intentionally permit representations larger
than a block, and CheckWeight must reject those representations. Signed
Normal/Operational classes are tested for both ref_time and proof-size
rejection one unit above their cap. Utility capacity tests dispatch actual
inner calls and verify every stored signer and refund. Arbitrarily large
batches must be split; no universal claim that every possible batch fits is
made. The fixed-bound cases are checked against the actual max_extrinsic;
Mandatory cases are compared to max_block as they have no per-call cap.

Signed base: 1,271,734,000 ref_time / 30,847 proof bytes.
Normal max_extrinsic: 1,498,728,266,000; Operational: 1,998,728,266,000.
Largest finite declared case: **System.apply_authorized_upgrade**, 88,011,595,000 ref_time,
**4.403380% of its class cap**. No previously includable finite case becomes
un-includable. Parameter-dependent oversized calls are rejected at validation.
No finite global maximum exists for E rows before admission.

These are declared-weight checks, not a fresh CPU/proof benchmark of every
pallet. Some existing SDK `WeightInfo=()` fallbacks already used RocksDB before
this patch. NativeTokenManagement, BlockRewards, Oracle, TEE and several
settlement/Billing paths have flat weights; changing DbWeight cannot repair
missing DB terms in those declarations.

## Hook and migration blockers

| Path | Evidence / budget | Verdict |
|---|---|---|
| Partner-chains Session rotation, 32 authorities | Full runtime on_initialize plus base block returns 2,000,642,511,000 against 2,000,000,000,000; Session alone returns max_block, including max proof size | FAIL before inherents/finalize; pre-existing |
| Receipt canonical-cert migration |20,001 committed Attestations rows produce 2,000,725,000,000 ref_time; clear(u32::MAX,None) has no cap | FAIL; newly visible in charged weight with nonzero DB schedule |
| Receipt reward-era distribution | 14,400 distinct authors produce 2,144,102,885,000 ref_time; map traversal and cleanup have no per-hook cap | FAIL; pre-existing algorithm |
| Settlement legacy migrations | v0/v1 cap migrated rows, not scanned rows; skipped/already-marked rows can be arbitrarily numerous. v2 collects all request keys before its processing cap | No finite scan bound; dependency ff0efed |
| Settlement expiry sweep | ExpiryQueue is bounded 64, but the hook returns flat 10,000 per entry and accesses the PendingBatches vector (cap 10,000) | Missing DB/proof/work accounting; cannot certify wall-time safety |
| MOTRA finalization | Params/BlockWeight accesses and an optional event have no on_initialize reservation | Missing finalize budget |
| BlockRewards finalization / NativeTokenManagement inherent | Upstream flat-zero inherent declarations, beneficiary/reward storage work | Missing work budget; beneficiary state bound needs audit |
| Treasury | Spend proposals bounded 100 and WithMotra charges 201 mutation units (71,283,411,920 ref_time / 1,232,620 proof bytes); regular on_initialize can access account/inactive storage yet return zero | Finite spend bound, incomplete regular-hook accounting |
| Aura / GRANDPA / System / Sidechain / committee initialization | Bounded runtime authority state; source and real 32-authority rotation exercised | Cannot cure the aggregate rotation overrun above |
| Runtime fee sweep + timelock initialization + perp removal | Existing migrations bounded; perp 1000-key regression fits the block | Individually bounded, not proof of aggregate upgrade block |
| on_idle | No custom idle handler in the active pallet set | No separate custom idle work |

Required follow-up before genesis/merge: bounded and metered session rotation,
receipt era/clear cursors or another reviewed bounded distribution policy,
scan-bounded settlement migrations with a coherent dependency pin, and explicit
inherent/finalization accounting. Re-run a strict aggregate initialization +
inherent + finalize + migration budget gate. Increasing the block ceiling or
reducing declared weights without measured work is not a safety fix.

## Capacity

All counts below are normal-class ref_time ceilings / deterministic native
admission harness results, **not live TPS**. Hooks, proof/length, mixed traffic
and rotation can reduce them. No change was made to fee economics or daemon
submission behavior.

| Workload | Before | After |
|---|---:|---:|
| Separate transfer_keep_alive (declared call + signed base) |933|865|
| Real Utility transfer batch, full-budget fixture |4,395|3,216|
| Separate non-threshold attestations with actual-weight refunds |1,120|941|
| Utility attest batches, max width 1 (real daemon width if wrapped) |1,114|907|
| Utility attest batches, max width 32, shrinking tail |13,417|3,705|
| Utility attest batches, max width 96, shrinking tail |15,138|3,705|

The installed Gemtek cert-daemon image `local-7bbdeb9` was inspected read-only:
`submit_availability_cert` composes OrinqReceipts.attest_availability_cert and
one signed extrinsic, with no Utility wrapper. Its real on-chain batch width
is 1. The daemon's parallel receipt-processing batch is not an on-chain batch.
The width 1 Utility row is the requested comparison, not a deployment claim.

| Declared-capacity ceiling | Before calls/block | After calls/block | Class |
|---|---:|---:|---|
|OrinqReceipts.submit_receipt|985|632|Normal|
|IntentSettlement.post_settlement_bond|1,041|910|Operational|
|IntentSettlement.attest_intent|1,513|1,513|Operational|
|IntentSettlement.attest_batch_intents|957|957|Operational|
|IntentSettlement.settle_batch_atomic|358|28|Operational|

## Fees at genesis and under congestion

MOTRA has 15 decimals. The actual formula is
`min_fee + floor(rate * call_ref_time / 1,000,000) + length_fee_per_byte * signed_length`.
It prices dispatch weight, not the signed-base execution reservation; Pays::No
is not a waiver in ChargeMotra. Successful refunds replace declared dispatch
weight with actual weight; minimum/length charges remain.

Genesis: min_fee 1,000,000,000 base units; rate 0; length fee 1,000,000/byte.
These named fields were decoded from ce89715's compiled preprod genesis and
read from live preprod; the live rate at the audit read was 4. Thus genesis fees
are unchanged for the same encoded extrinsic. The table uses
an exactly SCALE-encoded immortal, nonce 0, AccountId-addressed sr25519 signed
extrinsic; the signature's bytes do not affect its length. Root/mandatory
entries are budget estimates only: they are not valid directly signed calls;
governance wrappers add their own weight and length. E rows use the audited
sample, and actual inner-call fees must be added.

There is **no finite long-run EMA rate cap**. At default 50% target, 10% smoothing
and max step 1,000,000,000, full blocks increase rate by approximately 50,000,000
per block. One day of 14,400 full blocks from zero can reach 720,000,000,000
(up to integer-rounding dust). We show rate 1,000,000,000 (about 20 full blocks)
and 720,000,000,000 (one sustained-full day), not a probability forecast.

`!` flags a greater-than 2× after/before fee at either nonzero scenario. Genesis
never has such an increase. This includes especially receipt submission,
threshold/non-threshold attestation, Billing topups/withdrawals, settlement
atomic batches and several RootTimelock paths. Decisions: accept these storage
prices and size MOTRA funding appropriately, or review fee parameters separately.
No unapproved congestion-parameter tuning is hidden in this change.

| Call | Class / envelope | ref_time before → after | Proof bytes | Genesis MOTRA | MOTRA at rate 1e9 before → after | MOTRA at rate 720e9 before → after | >2× |
|---|---|---:|---:|---:|---:|---:|:---:|
|System.remark|Normal|1,522,821,744 → 1,522,821,744|0|0.003933111|0.005455933 → 0.005455933|1.100364767 → 1.100364767||
|System.set_heap_pages|Operational|229,109,000 → 229,109,000|1,485|0.000001113|0.000230222 → 0.000230222|0.164959593 → 0.164959593||
|System.set_code|Operational|82,130,651,000 → 82,130,651,000|67,035|0.000001106|0.082131757 → 0.082131757|59.134069826 → 59.134069826||
|System.set_code_without_checks|Operational|82,130,651,000 → 82,130,651,000|67,035|0.000001106|0.082131757 → 0.082131757|59.134069826 → 59.134069826||
|System.set_storage|Operational / E|2,192,000 → 2,192,000|0|0.000001106|0.000003298 → 0.000003298|0.001579346 → 0.001579346||
|System.kill_storage|Operational / E|2,159,000 → 2,159,000|0|0.000001106|0.000003265 → 0.000003265|0.001555586 → 0.001555586||
|System.kill_prefix|Operational / E|130,399,281 → 130,399,281|204|0.00000111|0.000131509 → 0.000131509|0.093888592 → 0.093888592||
|System.remark_with_event|Normal|5,471,974,415 → 5,471,974,415|0|0.003933111|0.009405085 → 0.009405085|3.94375469 → 3.94375469||
|System.authorize_upgrade|Operational|109,643,000 → 109,643,000|0|0.000001137|0.00011078 → 0.00011078|0.078944097 → 0.078944097||
|System.authorize_upgrade_without_checks|Operational|109,643,000 → 109,643,000|0|0.000001137|0.00011078 → 0.00011078|0.078944097 → 0.078944097||
|System.apply_authorized_upgrade|Operational|88,011,595,000 → 88,011,595,000|67,035|0.000001106|0.088012701 → 0.088012701|63.368349506 → 63.368349506||
|Timestamp.set|Mandatory|158,684,000 → 158,684,000|1,493|0.000001106|0.00015979 → 0.00015979|0.114253586 → 0.114253586||
|Grandpa.note_stalled|Normal|103,000,000 → 103,000,000|0|0.000001113|0.000104113 → 0.000104113|0.074161113 → 0.074161113||
|Balances.transfer_allow_death|Normal|346,133,000 → 471,133,000|10,659|0.000001139|0.000347272 → 0.000472272|0.249216899 → 0.339216899||
|Balances.force_transfer|Normal|347,714,000 → 597,714,000|13,262|0.000001172|0.000348886 → 0.000598886|0.250355252 → 0.430355252||
|Balances.transfer_keep_alive|Normal|335,929,000 → 460,929,000|10,659|0.000001139|0.000337068 → 0.000462068|0.241870019 → 0.331870019||
|Balances.transfer_all|Normal|345,155,000 → 470,155,000|10,659|0.000001139|0.000346294 → 0.000471294|0.248512739 → 0.338512739||
|Balances.force_unreserve|Normal|166,118,000 → 291,118,000|7,126|0.000001154|0.000167272 → 0.000292272|0.119606114 → 0.209606114||
|Balances.upgrade_accounts|Normal / E|16,588,000 → 16,588,000|990|0.000001106|0.000017694 → 0.000017694|0.011944466 → 0.011944466||
|Balances.force_set_balance|Normal|168,814,000 → 293,814,000|7,126|0.000001139|0.000169953 → 0.000294953|0.121547219 → 0.211547219||
|Balances.force_adjust_total_issuance|Normal|6,594,000 → 6,594,000|0|0.000001107|0.000007701 → 0.000007701|0.004748787 → 0.004748787||
|Balances.burn|Normal|169,596,000 → 169,596,000|3,533|0.000001107|0.000170703 → 0.000170703|0.122110227 → 0.122110227||
|Sudo.sudo|Normal / E|11,866,744 → 36,866,744|1,517|0.000001108|0.000012975 → 0.000037975|0.008545164 → 0.026545164|!|
|Sudo.sudo_unchecked_weight|Normal / E|0 → 0|0|0.00000111|0.00000111 → 0.00000111|0.00000111 → 0.00000111||
|Sudo.set_key|Normal|9,663,000 → 134,663,000|1,517|0.000001138|0.000010801 → 0.000135801|0.006958498 → 0.096958498|!|
|Sudo.sudo_as|Normal / E|12,140,744 → 37,140,744|1,517|0.000001141|0.000013282 → 0.000038282|0.008742477 → 0.026742477|!|
|Sudo.remove_key|Normal|9,127,000 → 134,127,000|1,517|0.000001105|0.000010232 → 0.000135232|0.006572545 → 0.096572545|!|
|Multisig.as_multi_threshold_1|Normal / E|22,501,848 → 197,501,848|3,997|0.000001397|0.000023899 → 0.000198899|0.016202728 → 0.142202728|!|
|Multisig.as_multi|Normal / E|193,959,845 → 493,959,845|10,344|0.000001402|0.000195362 → 0.000495362|0.13965249 → 0.35565249|!|
|Multisig.approve_as_multi|Normal / E|180,190,233 → 305,190,233|10,344|0.000001431|0.000181621 → 0.000306621|0.129738399 → 0.219738399||
|Multisig.cancel_as_multi|Normal|181,865,524 → 306,865,524|10,344|0.000001436|0.000183302 → 0.000308302|0.130944613 → 0.220944613||
|Utility.batch|Operational / E|2,694,370 → 52,694,370|3,997|0.000001106|0.0000038 → 0.0000538|0.001941052 → 0.037941052|!|
|Utility.as_derivative|Normal / E|10,776,744 → 185,776,744|3,997|0.00000111|0.000011887 → 0.000186887|0.007760366 → 0.133760366|!|
|Utility.batch_all|Operational / E|12,948,874 → 62,948,874|3,997|0.000001106|0.000014055 → 0.000064055|0.009324295 → 0.045324295|!|
|Utility.dispatch_as|Normal / E|8,589,744 → 8,589,744|0|0.00000111|0.0000097 → 0.0000097|0.006185726 → 0.006185726||
|Utility.force_batch|Operational / E|4,879,712 → 54,879,712|3,997|0.000001106|0.000005986 → 0.000055986|0.003514499 → 0.039514499|!|
|Utility.with_weight|Normal / E|0 → 0|0|0.00000111|0.00000111 → 0.00000111|0.00000111 → 0.00000111||
|Treasury.spend_local|Normal|12,681,000 → 362,681,000|1,887|0.000001139|0.00001382 → 0.00036382|0.009131459 → 0.261131459|!|
|Treasury.remove_approval|Operational|6,567,000 → 131,567,000|1,887|0.000001106|0.000007673 → 0.000132673|0.004729346 → 0.094729346|!|
|Treasury.spend|Normal|14,842,000 → 264,842,000|3,501|0.000001139|0.000015981 → 0.000265981|0.010687379 → 0.190687379|!|
|Treasury.payout|Normal|359,061,000 → 984,061,000|13,274|0.000001109|0.00036017 → 0.00098517|0.258525029 → 0.708525029|!|
|Treasury.check_status|Normal|12,480,000 → 137,480,000|3,538|0.000001109|0.000013589 → 0.000138589|0.008986709 → 0.098986709|!|
|Treasury.void_spend|Normal|11,427,000 → 136,427,000|3,538|0.000001109|0.000012536 → 0.000137536|0.008228549 → 0.098228549|!|
|Vesting.vest|Normal|187,673,238 → 462,673,238|8,297|0.000001105|0.000188778 → 0.000463778|0.135125836 → 0.333125836|!|
|Vesting.vest_other|Normal|189,575,721 → 589,575,721|8,297|0.000001138|0.000190714 → 0.000590714|0.136495657 → 0.424495657|!|
|Vesting.vested_transfer|Normal|526,274,160 → 926,274,160|15,363|0.000001174|0.000527448 → 0.000927448|0.378918569 → 0.666918569||
|Vesting.force_vested_transfer|Normal|528,526,615 → 1,053,526,615|16,795|0.000001207|0.000529734 → 0.001054734|0.38054037 → 0.75854037||
|Vesting.merge_schedules|Normal|190,693,587 → 590,693,587|8,297|0.000001113|0.000191807 → 0.000591807|0.137300496 → 0.425300496|!|
|Vesting.force_remove_vesting_schedule|Normal|192,732,245 → 592,732,245|8,297|0.000001142|0.000193874 → 0.000593874|0.138768358 → 0.426768358|!|
|OrinqReceipts.submit_receipt|Normal|250,759,000 → 1,100,759,000|31,771|0.000001395|0.000252154 → 0.001102154|0.180547875 → 0.792547875|!|
|OrinqReceipts.set_availability_cert|Normal|216,434,000 → 691,434,000|18,111|0.000001169|0.000217603 → 0.000692603|0.155833649 → 0.497833649|!|
|OrinqReceipts.set_committee|Normal|10,000 → 200,010,000|0|0.000004183|0.000004193 → 0.000204193|0.000011383 → 0.144011383|!|
|OrinqReceipts.attest_availability_cert|Normal|20,004,870,056 → 45,254,870,056|1,073,275|0.000001169|0.020006039 → 0.045256039|14.403507609 → 32.583507609|!|
|OrinqReceipts.submit_anchor|Normal|10,000 → 125,010,000|0|0.000001233|0.000001243 → 0.000126243|0.000008433 → 0.090008433|!|
|OrinqReceipts.submit_receipt_v2|Normal|250,759,000 → 1,100,759,000|31,771|0.000001492|0.000252251 → 0.001102251|0.180547972 → 0.792547972|!|
|OrinqReceipts.join_committee|Normal|10,000 → 150,010,000|0|0.000001137|0.000001147 → 0.000151147|0.000008337 → 0.108008337|!|
|OrinqReceipts.leave_committee|Normal|10,000 → 125,010,000|0|0.000001137|0.000001147 → 0.000126147|0.000008337 → 0.090008337|!|
|OrinqReceipts.set_attestation_reward_per_signer|Normal|10,000 → 100,010,000|0|0.000001121|0.000001131 → 0.000101131|0.000008321 → 0.072008321|!|
|OrinqReceipts.set_era_cap_base|Normal|10,000 → 100,010,000|0|0.000001121|0.000001131 → 0.000101131|0.000008321 → 0.072008321|!|
|OrinqReceipts.set_era_cap_baseline_attestor_count|Normal|10,000 → 100,010,000|0|0.000001109|0.000001119 → 0.000101119|0.000008309 → 0.072008309|!|
|OrinqReceipts.bond|Normal|202,527,000 → 452,527,000|10,655|0.000001121|0.000203648 → 0.000453648|0.145820561 → 0.325820561|!|
|OrinqReceipts.unbond|Normal|230,310,000 → 505,310,000|15,214|0.000001105|0.000231415 → 0.000506415|0.165824305 → 0.363824305|!|
|OrinqReceipts.slash_attestor|Normal|408,521,000 → 1,058,521,000|25,330|0.000001154|0.000409675 → 0.001059675|0.294136274 → 0.762136274|!|
|OrinqReceipts.set_bond_requirement|Normal|10,000 → 100,010,000|0|0.000001121|0.000001131 → 0.000101131|0.000008321 → 0.072008321|!|
|OrinqReceipts.set_receipt_submission_fee|Normal|10,000 → 125,010,000|0|0.000001121|0.000001131 → 0.000126131|0.000008321 → 0.090008321|!|
|OrinqReceipts.set_receipt_submission_fee_floor|Normal|10,000 → 100,010,000|0|0.000001121|0.000001131 → 0.000101131|0.000008321 → 0.072008321|!|
|OrinqReceipts.set_receipt_expiry_blocks|Normal|10,000 → 100,010,000|0|0.000001109|0.000001119 → 0.000101119|0.000008309 → 0.072008309|!|
|OrinqReceipts.expire_receipt_fee|Normal|219,519,000 → 644,519,000|19,600|0.000001137|0.000220656 → 0.000645656|0.158054817 → 0.464054817|!|
|OrinqReceipts.set_bad_attest_slash_threshold|Normal|10,000 → 100,010,000|0|0.000001109|0.000001119 → 0.000101119|0.000008309 → 0.072008309|!|
|OrinqReceipts.reset_candidate_liveness|Normal|10,000 → 200,010,000|0|0.000001137|0.000001147 → 0.000201147|0.000008337 → 0.144008337|!|
|OrinqReceipts.set_core_eviction_enabled|Normal|10,000 → 100,010,000|0|0.000001106|0.000001116 → 0.000101116|0.000008306 → 0.072008306|!|
|OrinqReceipts.set_contribution_window_enabled|Normal|10,000 → 100,010,000|0|0.000001106|0.000001116 → 0.000101116|0.000008306 → 0.072008306|!|
|OrinqReceipts.set_break_glass_floor_enabled|Normal|10,000 → 100,010,000|0|0.000001106|0.000001116 → 0.000101116|0.000008306 → 0.072008306|!|
|OrinqReceipts.set_slack_invariant_enabled|Normal|10,000 → 100,010,000|0|0.000001106|0.000001116 → 0.000101116|0.000008306 → 0.072008306|!|
|OrinqReceipts.set_break_glass_aura_keys|Normal|10,000 → 100,010,000|0|0.000004179|0.000004189 → 0.000104189|0.000011379 → 0.072011379|!|
|OrinqReceipts.set_pinned_committee|Normal|20,000 → 100,020,000|0|0.000004218|0.000004238 → 0.000104238|0.000018618 → 0.072018618|!|
|OrinqReceipts.clear_pinned_committee|Normal|10,000 → 100,010,000|0|0.000001105|0.000001115 → 0.000101115|0.000008305 → 0.072008305|!|
|Motra.set_delegatee|Normal|1,148,657,000 → 1,148,657,000|29,346|0.000001106|0.001149763 → 0.001149763|0.827034146 → 0.827034146||
|Motra.set_params|Normal|15,000,000 → 15,000,000|0|0.000001213|0.000016213 → 0.000016213|0.010801213 → 0.010801213||
|Motra.claim_motra|Normal|1,047,014,000 → 1,047,014,000|29,346|0.000001105|0.001048119 → 0.001048119|0.753851185 → 0.753851185||
|SessionCommitteeManagement.set|Mandatory|232,064,398 → 382,064,398|4,538|0.00000425|0.000236314 → 0.000386314|0.167090617 → 0.275090617||
|SessionCommitteeManagement.set_main_chain_scripts|Normal|181,914,365 → 331,914,365|4,538|0.000001162|0.000183076 → 0.000333076|0.130979505 → 0.238979505||
|BlockRewards.set_current_block_beneficiary|Mandatory|0 → 0|0|0.000001137|0.000001137 → 0.000001137|0.000001137 → 0.000001137||
|PalletSession.set_keys|Normal|959,558,000 → 959,558,000|17,759|0.00000117|0.000960728 → 0.000960728|0.69088293 → 0.69088293||
|PalletSession.purge_keys|Normal|792,476,000 → 792,476,000|5,282|0.000001105|0.000793581 → 0.000793581|0.570583825 → 0.570583825||
|NativeTokenManagement.transfer_tokens|Mandatory|0 → 0|0|0.000001121|0.000001121 → 0.000001121|0.000001121 → 0.000001121||
|NativeTokenManagement.set_main_chain_scripts|Normal|1 → 1|0|0.000001135|0.000001135 → 0.000001135|0.000001136 → 0.000001136||
|IntentSettlement.submit_intent|Normal|500,000,000 → 500,000,000|0|0.000001114|0.000501114 → 0.000501114|0.360001114 → 0.360001114||
|IntentSettlement.attest_intent|Operational|50,000,000 → 50,000,000|0|0.000001233|0.000051233 → 0.000051233|0.036001233 → 0.036001233||
|IntentSettlement.request_voucher|Operational|100,000,000 → 100,000,000|0|0.000010528|0.000110528 → 0.000110528|0.072010528 → 0.072010528||
|IntentSettlement.request_credit_refund|Normal|500,000,000 → 500,000,000|0|0.000001113|0.000501113 → 0.000501113|0.360001113 → 0.360001113||
|IntentSettlement.settle_claim|Operational|50,000,000 → 50,000,000|0|0.000010388|0.000060388 → 0.000060388|0.036010388 → 0.036010388||
|IntentSettlement.expire_policy_mirror|Operational|30,000,000 → 30,000,000|0|0.000001137|0.000031137 → 0.000031137|0.021601137 → 0.021601137||
|IntentSettlement.credit_deposit|Operational|30,000,000 → 30,000,000|0|0.000010395|0.000040395 → 0.000040395|0.021610395 → 0.021610395||
|IntentSettlement.set_pool_utilization|Operational|10,000,000 → 10,000,000|0|0.000001129|0.000011129 → 0.000011129|0.007201129 → 0.007201129||
|IntentSettlement.set_min_signer_threshold|Operational|10,000,000 → 10,000,000|0|0.000001109|0.000011109 → 0.000011109|0.007201109 → 0.007201109||
|IntentSettlement.settle_batch_atomic|Operational|4,311,966,280 → 68,611,966,280|1,119,951|0.000026967|0.004338933 → 0.068638933|3.104642689 → 49.400642689|!|
|IntentSettlement.attest_batch_intents|Operational|818,000,000 → 818,000,000|0|0.000018519|0.000836519 → 0.000836519|0.588978519 → 0.588978519||
|IntentSettlement.request_batch_vouchers|Operational|2,610,000,000 → 2,610,000,000|0|0.000062807|0.002672807 → 0.002672807|1.879262807 → 1.879262807||
|IntentSettlement.submit_batch_intents|Normal|1,330,000,000 → 1,330,000,000|1,327,104|0.000003411|0.001333411 → 0.001333411|0.957603411 → 0.957603411||
|IntentSettlement.request_settle|Operational|40,000,000 → 40,000,000|0|0.000001282|0.000041282 → 0.000041282|0.028801282 → 0.028801282||
|IntentSettlement.attest_settle|Operational|60,000,000 → 60,000,000|0|0.000010355|0.000070355 → 0.000070355|0.043210355 → 0.043210355||
|IntentSettlement.request_batch_settle|Operational|2,088,000,000 → 2,088,000,000|0|0.000038229|0.002126229 → 0.002126229|1.503398229 → 1.503398229||
|IntentSettlement.attest_batch_settle|Operational|3,900,000,000 → 3,900,000,000|0|0.000018519|0.003918519 → 0.003918519|2.808018519 → 2.808018519||
|IntentSettlement.request_expire_policy|Operational|35,000,000 → 35,000,000|0|0.000001277|0.000036277 → 0.000036277|0.025201277 → 0.025201277||
|IntentSettlement.attest_expire_policy|Operational|55,000,000 → 55,000,000|0|0.000010355|0.000065355 → 0.000065355|0.039610355 → 0.039610355||
|IntentSettlement.post_settlement_bond|Operational|648,885,000 → 923,885,000|3,533|0.000001153|0.000650038 → 0.000925038|0.467198353 → 0.665198353||
|IntentSettlement.slash_bad_settlement_evidence|Operational|1,095,540,000 → 1,595,540,000|14,132|0.000010356|0.001105896 → 0.001605896|0.788799156 → 1.148799156||
|IntentSettlement.release_settlement_bond|Operational|648,885,000 → 1,023,885,000|3,533|0.000001137|0.000650022 → 0.001025022|0.467198337 → 0.737198337||
|TeeAttestation.submit_evidence|Normal|1,000,000,000 → 1,000,000,000|32,768|0.00001756|0.00101756 → 0.00101756|0.72001756 → 0.72001756||
|TeeAttestation.set_disabled|Normal|1,000,000,000 → 1,000,000,000|32,768|0.000001106|0.001001106 → 0.001001106|0.720001106 → 0.720001106||
|Billing.topup_self|Normal|204,672,000 → 579,672,000|12,156|0.000001121|0.000205793 → 0.000580793|0.147364961 → 0.417364961|!|
|Billing.topup_for|Normal|197,738,000 → 572,738,000|12,156|0.000001153|0.000198891 → 0.000573891|0.142372513 → 0.412372513|!|
|Billing.pay_request|Normal|60,000,000 → 60,000,000|8,192|0.000001162|0.000061162 → 0.000061162|0.043201162 → 0.043201162||
|Billing.governance_set_endpoint_price|Normal|20,000,000 → 20,000,000|4,096|0.000001123|0.000021123 → 0.000021123|0.014401123 → 0.014401123||
|Billing.request_withdrawal|Normal|35,000,000 → 35,000,000|4,096|0.000001121|0.000036121 → 0.000036121|0.025201121 → 0.025201121||
|Billing.execute_withdrawal|Normal|373,654,000 → 748,654,000|15,693|0.000001105|0.000374759 → 0.000749759|0.269031985 → 0.539031985|!|
|Billing.cancel_withdrawal|Normal|25,000,000 → 25,000,000|4,096|0.000001105|0.000026105 → 0.000026105|0.018001105 → 0.018001105||
|Billing.prune_paid_requests|Normal|1,290,000,000 → 1,290,000,000|66,560|0.000017493|0.001307493 → 0.001307493|0.928817493 → 0.928817493||
|Billing.governance_set_debits_enabled|Normal|20,000,000 → 20,000,000|4,096|0.000001106|0.000021106 → 0.000021106|0.014401106 → 0.014401106||
|Oracle.submit_price|Normal|500,000,000 → 500,000,000|50,000|0.00000125|0.00050125 → 0.00050125|0.36000125 → 0.36000125||
|Oracle.register_attestor|Normal|100,000,000 → 100,000,000|10,000|0.000001169|0.000101169 → 0.000101169|0.072001169 → 0.072001169||
|Recovery.as_recovered|Normal / E|16,904,744 → 91,904,744|3,997|0.000001141|0.000018046 → 0.000093046|0.012172557 → 0.066172557|!|
|Recovery.set_recovered|Normal|7,578,000 → 107,578,000|0|0.000001171|0.000008749 → 0.000108749|0.005457331 → 0.077457331|!|
|Recovery.create_recovery|Normal|173,732,900 → 298,732,900|7,349|0.0000014|0.000175133 → 0.000300133|0.125089088 → 0.215089088||
|Recovery.initiate_recovery|Normal|176,926,000 → 326,926,000|7,387|0.000001138|0.000178064 → 0.000328064|0.127387858 → 0.235387858||
|Recovery.vouch_recovery|Normal|20,289,654 → 170,289,654|3,854|0.000001171|0.000021461 → 0.000171461|0.014609722 → 0.122609722|!|
|Recovery.claim_recovery|Normal|24,735,080 → 199,735,080|3,854|0.000001138|0.000025873 → 0.000200873|0.017810396 → 0.143810396|!|
|Recovery.close_recovery|Normal|332,030,649 → 582,030,649|10,920|0.000001138|0.000333169 → 0.000583169|0.239063205 → 0.419063205||
|Recovery.remove_recovery|Normal|179,664,547 → 329,664,547|7,387|0.000001105|0.00018077 → 0.00033077|0.129359579 → 0.237359579||
|Recovery.cancel_recovered|Normal|12,275,000 → 137,275,000|3,545|0.000001138|0.000013413 → 0.000138413|0.008839138 → 0.098839138|!|
|RootTimelock.schedule|Normal / E|50,006,000 → 575,006,000|0|0.000001108|0.000051114 → 0.000576114|0.036005428 → 0.414005428|!|
|RootTimelock.cancel|Operational|20,000,000 → 420,000,000|0|0.000001109|0.000021109 → 0.000421109|0.014401109 → 0.302401109|!|
|RootTimelock.fast_track|Operational|20,000,000 → 170,000,000|0|0.000001109|0.000021109 → 0.000171109|0.014401109 → 0.122401109|!|
|RootTimelock.enact|Normal / E|51,143,744 → 451,143,744|0|0.000001112|0.000052256 → 0.000452256|0.036824608 → 0.324824608|!|
|RootTimelock.set_delay|Normal|20,000,000 → 145,000,000|0|0.00000111|0.00002111 → 0.00014611|0.01440111 → 0.10440111|!|
|RootTimelock.set_guardian|Normal|20,000,000 → 220,000,000|0|0.000001106|0.000021106 → 0.000221106|0.014401106 → 0.158401106|!|
|RootTimelock.cancel_all|Operational|1,320,000,000 → 9,595,000,000|0|0.000001105|0.001321105 → 0.009596105|0.950401105 → 6.908401105|!|
|RootTimelock.prune|Normal|20,000,000 → 370,000,000|0|0.000001109|0.000021109 → 0.000371109|0.014401109 → 0.266401109|!|
|RootTimelock.approve|Operational|20,000,000 → 145,000,000|0|0.000001106|0.000021106 → 0.000146106|0.014401106 → 0.104401106|!|
|RootTimelock.enact_approved|Normal / E|51,143,744 → 451,143,744|0|0.000001108|0.000052252 → 0.000452252|0.036824604 → 0.324824604|!|

Non-threshold attestation refunds: 48,973,000 → 273,973,000 ref_time. At 169
signed bytes, genesis 0.000001169 MOTRA stays unchanged; rate 1e9 costs
0.000050142 → 0.000275142 MOTRA (5.487×); rate 720e9 costs
0.035261729 → 0.197261729 (5.594×). A 96-signer threshold call with97 changed
accounts refunds one checkpoint from the98-account admission bound:
19,855,985,056 → 45,105,985,056 ref_time.

## Reproduction and references

From partnerchain, use an isolated CARGO_TARGET_DIR, CARGO_BUILD_JOBS=4,
WASM_BUILD_WORKSPACE_HINT pointing at that checkout, and serialize every heavy
command with `flock /tmp/materios-cargo-build.lock nice -n 10`.

- `SKIP_WASM_BUILD=1 cargo test -p materios-runtime --lib db_weights --locked -- --nocapture`
- `SKIP_WASM_BUILD=1 cargo test -p materios-runtime --lib motra_benchmarks --locked -- --nocapture`
- `SKIP_WASM_BUILD=1 cargo test -p materios-runtime --lib refund_ --locked -- --nocapture --test-threads=1`
- Full pallet/runtime/try-runtime/benchmark-feature/workspace/node/Wasm/chain-spec/preflight/offline-node and live metadata verification are recorded in the PR packet.

Baseline measurements rebuild ce89715 production sources with the same audit
harness and isolated target; the candidate sources are restored byte-for-byte.
No prior worktree's artifacts are shared. Temporary orchestration/report
scripts have no production callers and use the explicit one-off TDD exception.
New production behavior has RED→GREEN regressions.

Research/reuse queries: `rg -n 'motra|weight|orinq-receipts|billing' SUBSTRATE.md`;
`gh search code 'repo:paritytech/polkadot-sdk max_extrinsic'` (no indexed result);
web `site.paritytech.github.io polkadot sdk RuntimeDbWeight RocksDbWeight BlockWeights max_extrinsic`.
The registry's existing MOTRA/receipt hubs, benchmark samples, FRAME dispatch
metadata, CheckWeight and the existing refund harness supplied the primitives.
Pinned source c455194a was inspected for actual semantics rather than assuming
current upstream docs match the deployed SDK.

Primary references: [FRAME weight reference](https://paritytech.github.io/polkadot-sdk/master/polkadot_sdk_docs/reference_docs/frame_benchmarking_weight/index.html),
[SDK BlockWeights](https://github.com/paritytech/polkadot-sdk/blob/c455194a/substrate/frame/system/src/limits.rs),
[SDK CheckWeight](https://github.com/paritytech/polkadot-sdk/blob/c455194a/substrate/frame/system/src/extensions/check_weight.rs),
[partner-chains session](https://github.com/input-output-hk/partner-chains/blob/20e607f2/toolkit/pallets/partner-chains-session/src/lib.rs).
