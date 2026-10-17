# MOTRA checkpoint weight accounting

Balance changes never register weight after admission. The runtime adds account
checkpoint costs to the owning dispatch's `WeightInfo`, so `CheckWeight` admits
the complete cost and Utility, Multisig and RootTimelock retain it when summing
inner calls and returning actual weight.

`checkpoint_weight` is at least RocksDB's 4 reads + 1 write and 14,000 proof
bytes, even when `System.DbWeight` is zero. `balance_weights::mutations(n)`
reserves three checkpoints per account mutation: the balance checkpoint,
`OnNewAccount`'s decay-clock initialization, and a possible preceding legacy
`Balances::ensure_upgraded` free-balance repair. The bound deliberately includes
paths that cannot all occur on ordinary funded accounts. Dust burns issuance
(`DustRemoval = ()`) and does not credit another account.

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

Reconciliation has one additional checkpoint budget in `claim_motra` and
`set_delegatee`. Fee reconciliation is covered once per extrinsic by
`RuntimeBlockWeights.base_extrinsic`, before `ChargeMotra` runs. Validation
executes against discarded storage and does not consume a block. The account
store accepts only `u128` balances, so reading its free balance is infallible;
the generic projection path uses a saturating conversion.

The runtime regression dispatches a Utility batch that fills the remaining
block budget, checks its transfers and post-dispatch refund, rejects another
transfer, and finalizes within `max_block`. Separate tests check transfer and
Currency-caller dispatch budgets, returned reward-hook weight, absence of
unchecked hook/reconciliation weight, and preservation of `u128::MAX`.
