# SPO Rewards — The Materios Dual Stream

Running a Cardano stake pool **and** a Materios validator earns two reward streams from one operation:

| Stream | Token | Source | Paid by |
|---|---|---|---|
| **1. Staking** | ADA (tADA on preprod) | Your Cardano pool's normal staking rewards | Cardano — unchanged |
| **2. Block production + attestation** | MATRA (tMATRA on preprod) | Producing Materios blocks (and optionally attesting receipts) | Materios |

The same Cardano stake that makes you a competitive SPO is what registers you as a Materios block‑producer candidate (selected by the **Ariadne** protocol). You **add** the MATRA stream **without giving up** your ADA stream — Materios never holds, moves, or pays ADA.

## Stream 1 — ADA (Cardano), unchanged

You run your pool exactly as today: delegators stake ADA, your pool mints Cardano blocks and earns Cardano staking rewards. Materios is a separate Substrate partner chain; it does not touch your ADA rewards. This stream is independent and continues whether or not you are in the Materios committee.

## Stream 2 — MATRA (Materios)

MATRA (6 decimals) is emitted from two distinct reserves.

### Block production — 150,000,000 MATRA reserve

- Distributed once per **era** (`ERA_LENGTH = 14,400` blocks, ≈ 24 h).
- The per‑era emission is governance‑tunable (currently `REWARD_PER_ERA` ≈ 102.74 MATRA).
- Each era's emission splits **85% to validators / 15% to treasury** — the treasury share (`TreasuryEmissionShare`) is runtime‑tunable; 15% is the default, so validators receive the 85% complement.
- The validator pool is paid **pro‑rata by blocks authored** that era.
- **No slashing.** A missed block is simply a missed reward — never a penalty against your stake or balance.

### Attestation — 50,000,000 MATRA reserve

A second MATRA stream for verifying receipts. Committee membership is **bonded and governance‑admitted** — not open self‑registration:

1. **Post a bond.** Call `bond(amount)` (a signed call from your own account) for at least `BondRequirement` (genesis default **1,000 MATRA**, governance‑tunable). The bond backs honest attestation: provably‑bad attestations are slashed from it, and a bond that drops below `BondRequirement` auto‑ejects the attestor.
2. **Get admitted.** `join_committee(member)` is **root / governance‑only** — an operator cannot self‑join, and a direct signed call returns `BadOrigin`. Governance adds your bonded account to the committee.
3. **Earn.** As a member, run a `cert-daemon` and receive **10 MATRA per signer per certified receipt**, paid on certification, capped per era by `EraCapBase` (default **50,000 MATRA/era**). The cap scales with committee size, so adding attestors shares the emission rather than inflating it.

## Why it's a "dual stream"

You are not choosing between Cardano and Materios. One pool, one set of keys, one box — two reward tokens:

- Your **stake** earns ADA on Cardano (as always) **and** earns you Materios block‑production rights.
- Materios rewards that block production in **MATRA**, on top.
- The Materios explorer shows both streams side‑by‑side per pool (tMATRA + tADA).

## How selection works (so you actually produce blocks)

Materios uses Partner Chains' **Ariadne** committee selection, governed by the **D‑parameter** `D = (permissioned, registered)`:

- The chain opens gradually: `D = (N, 0)` → `(2, 1)` → `(1, 2)` → `(0, N)`.
- **Registered SPO candidates** (you, via Cardano mainchain registration) fill the `registered` slots.
- Full mechanics + the D‑parameter roadmap: [`docs/GOVERNANCE.md`](GOVERNANCE.md).

## Where this lives in the code

- **Reward distribution:** [`partnerchain/pallets/orinq-receipts/src/lib.rs`](../partnerchain/pallets/orinq-receipts/src/lib.rs) — `on_initialize` era settlement (`REWARD_PER_ERA`, `VALIDATOR_RESERVE`, `TreasuryEmissionShare`) and the attestation payout (`EraCapBase`, per‑signer reward).
- **Committee selection:** [`docs/GOVERNANCE.md`](GOVERNANCE.md) + `partnerchain/vendor/authority-selection-inherents/`.
- **Reward summary table:** [README → Validator Rewards](../README.md#validator-rewards).

---

*MATRA / ADA are shown as tMATRA / tADA on preprod (testnet).*
