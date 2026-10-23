# Agent Work Settlement — Paying AI Agents On-Chain for Verifiably Useful Work

> **Status:** Draft RFC (v0.1). Nothing in this document is implemented yet unless
> explicitly marked as shipped. Terminology follows `docs/ARCHITECTURE.md` (design
> decisions D1–D8) and the intent-settlement spec
> ([materios-intent-settlement/docs/spec-v1.md](https://github.com/Flux-Point-Studios/materios-intent-settlement/blob/main/docs/spec-v1.md)).

## 0. Summary

This RFC specifies how AI agents earn MATRA on Materios for doing **objectively
verifiable useful work** — inference jobs, code tasks with test oracles, data
pipeline runs, combinatorial optimization — without touching the consensus layer.

The design deliberately rejects "proof of useful work as consensus." The academic
record is clear that coupling open-ended useful work to chain security fails: the
work's utility does not feed the security budget (SoK,
[eprint 2025/1814](https://eprint.iacr.org/2025/1814)), subjective scoring degrades
into judge-gaming (Bittensor's
[weight-copying problem](https://docs.learnbittensor.org/concepts/weight-copying-in-bittensor)),
and even the strongest construction (IOG's Ofelimos,
[eprint 2021/1379](https://eprint.iacr.org/2021/1379)) remains undeployed research
four years after publication. What *is* buildable today is a **work marketplace
settled on-chain with verifiable receipts** — and Materios already owns most of the
rails:

| Rail | Where it lives today | Role in agent work |
|---|---|---|
| Receipt commitments (hashes, roots, schema hashes) | `pallet-orinq-receipts` | Work evidence |
| Bonded, governance-admitted attestor committee | `pallet-orinq-receipts` + operator-kit cert daemon | Verification quorum |
| Availability certificates (dCBOR/SCALE, 202-byte) | `AVAILABILITY_CERT_SPEC.md` + cert daemon | Proof the work artifacts are retrievable |
| Escrow → attest → settle → bond → slash pipeline | `materios-intent-settlement` (live on preprod) | Task escrow & payout |
| ZK claims over committed receipts | Midnight coprocessor (`audit-claims.compact`) | Privacy-preserving verification lane |
| Two-token economics (MATRA capital / MOTRA fees) | `pallet-motra` | Payment vs. gas separation |

Agent work settlement is therefore specified as a **thin new pallet plus one new
receipt schema class**, not a new chain or consensus change.

---

## 1. Motivation

Materios already pays operators for one narrow kind of useful work: cert-daemon
attestors earn tMATRA per certified availability receipt. That mechanism proves
the shape — *bonded worker performs a check anyone can re-run, quorum certifies,
chain pays instantly from a capped pool*. This RFC generalizes the shape from
"verify a blob is available" to "perform a task whose output can be objectively
re-verified," so that autonomous agents (not just infrastructure daemons) become
first-class earners on the chain.

Target use cases, in rough order of arrival:

1. **Inference-for-hire** — a requester escrows MATRA for a batch of LLM/model
   inference over committed inputs; agents race or claim; output verified by
   sampled deterministic re-execution.
2. **Code tasks with test oracles** — bounty-style tasks where "done" is defined
   by a committed test suite run in a pinned container image.
3. **Data pipeline runs** — canonicalization/transform jobs whose outputs are
   Merkle-committed and spot-checkable (the receipt-builder pipeline itself is
   the reference workload).
4. **Optimization instances** — Ofelimos' one clean insight, imported without the
   consensus baggage: optimization solutions are cheap to *score* even when
   expensive to *find*. Requesters pay for the best committed solution above a
   threshold.

## 2. Design Principles

These extend D1–D8 from `ARCHITECTURE.md` and are numbered AW-D1… for
cross-referencing in reviews.

### AW-D1: Work pays; it never secures

Block production stays Aura+GRANDPA with Cardano anchoring. Nothing about task
volume, work quality, or verification outcomes can influence block authorship,
finality, or fork choice.

**Rationale:** the security-budget disconnect is the central negative result of
the PoUW literature (eprint 2025/1814). Externally-valuable work subsidizes
attackers as much as honest actors. Keeping consensus boring means a gamed work
metric can, at worst, misroute a bounded reward pool — never reorg the chain.

### AW-D2: Objective verifiers only (v1)

Every task class admitted in v1 must define a **deterministic verification
predicate**: given the task spec and the agent's committed output, any honest
verifier computes the same accept/reject verdict. Subjective quality scoring
("was this helpful?", "is this good writing?") is explicitly out of scope until
a dispute-game design exists (§10).

**Rationale:** subjective scoring is where live systems bleed. Bittensor's
validators copy each other's published scores rather than evaluate
([Opentensor working paper, 2024](https://docs.learnbittensor.org/papers/BT_Weight_Copier-29May2024.pdf));
commit-reveal patches help but the cat-and-mouse is structural. Deterministic
predicates make wrong verdicts *provable*, which makes verifier slashing safe.

### AW-D3: Commit-reveal verdicts

Verifiers first publish `H(verdict ‖ salt ‖ verifier_id)`, then reveal after the
commit window closes. A reveal that doesn't match the commit, or a missing
reveal, is treated as abstention and strikes toward `Unavailability` slashing.

**Rationale:** even with objective predicates, lazy verifiers could copy the
first published verdict instead of re-executing. Commit-reveal forces
independent computation — the direct lesson from Bittensor's weight-copier.

### AW-D4: Requester-funded escrow (v1); no protocol subsidy yet

Tasks are paid from MATRA escrowed by the requester at posting time. There is
**no** protocol-minted reward per task in v1.

**Rationale:** this dissolves PoUW's "who supplies the problems?" attack surface.
When the payer is the party who wants the output, self-dealing is economically
neutral (you pay yourself with your own funds, minus burned MOTRA fees). A
protocol-matched subsidy pool (mirroring the attestation pool) is attractive for
bootstrapping but is Sybil-bait — an agent posting tasks to itself would farm
the subsidy. Deferred to §10 with explicit gating conditions.

### AW-D5: Commitments only, receipts through the existing pipeline

Work inputs/outputs never touch the chain. Agents build work receipts with the
existing receipt-builder (JCS canonicalization per D3, content hash before
compression per D2, schema hash per D8) and submit through
`pallet-orinq-receipts`. The agent-work pallet stores only `receipt_id` links
and settlement state.

**Rationale:** the hard constraint from `ARCHITECTURE.md` holds. It also means
availability certification (cert daemon, existing lane) is a *precondition* for
verification: verifiers can always fetch what they're asked to re-check.

### AW-D6: Every economic actor is bonded

Agents bond to claim tasks; verifiers are bonded, governance-admitted committee
members (same admission pattern as `join_committee` on the attestation
committee); keepers that drive settlement post the intent-settlement-style
settlement bond. Provably-wrong behavior slashes; unavailability strikes.

**Rationale:** bonds are the Sybil resistance. The `post_settlement_bond` →
`slash_bad_settlement_evidence` → `release_settlement_bond` pattern is already
exercised on preprod (autonomous slash at block #206180) — reuse it, don't
reinvent it.

### AW-D7: Sample-based re-execution

Verification cost must be a small fraction of work cost. For batch tasks,
verifiers re-execute a pseudo-random sample of items (seeded from the block hash
at receipt inclusion, so the sample is unpredictable at work time), not the full
batch. Optimization tasks are the ideal case: scoring a solution is cheap even
though finding it is expensive.

**Rationale:** verification asymmetry is the property that made hash-PoW work.
Task classes are *admitted* to v1 precisely when they preserve it.

### AW-D8: Payment in MATRA, gas in MOTRA

Escrow, agent payouts, verifier fees, and bonds are MATRA (transferable
capital). All extrinsic fees stay MOTRA and burn per the existing fee model.

**Rationale:** preserves the two-token separation — agents accumulate capital
they can actually move, while chain usage still burns capacity.

---

## 3. Actors

| Actor | Bond | Earns | Slashed for |
|---|---|---|---|
| **Requester** | none (escrow at post) | the work output | — (escrow forfeits to agent on valid work) |
| **Agent** | `AgentBond` per claimed task | escrowed payment on `Accepted` | claiming then submitting work that fails verification, or missing the deadline |
| **Verifier** | committee bond (governance-admitted) | per-task verification fee (slice of escrow) | provably-wrong verdict (re-execution mismatch), unavailability strikes, double-sign |
| **Keeper** | settlement bond (intent-settlement pattern) | settlement fee | bad settlement evidence (existing slash path) |
| **Watcher** | none | slash share on successful fraud proof | — |

An **agent** is any account — the protocol doesn't care whether a human or an
autonomous process holds the key. Agent identity/reputation metadata (model
hashes, operator DID) lives in the work receipt, not in chain state.

## 4. Task Classes (v1) and Their Verification Predicates

Each class is identified by a `class_id` and a `schema_hash` (D8) for its task
spec and work receipt schemas.

| `class_id` | Task | Deterministic predicate | Verifier cost model |
|---|---|---|---|
| `infer.det.v1` | Batch inference with pinned open weights, temperature 0, pinned seed, pinned runtime image digest | Re-execute sampled items; output hashes must match the committed output Merkle leaves exactly | O(sample) forward passes |
| `code.oracle.v1` | Produce a patch/artifact passing a committed test suite | Run tests in the pinned container image against the committed artifact; pass-bitmap hash must match claim | One CI run per verifier |
| `data.pipe.v1` | Canonicalize/transform committed inputs (receipt-builder-style pipelines) | Recompute sampled chunks; leaf hashes must match committed output root | O(sample) transforms |
| `opt.score.v1` | Find a solution to a committed optimization instance with objective ≥ threshold (or best-of-window) | Recompute `f(solution)`; compare to claimed score | One objective evaluation (cheap by construction) |
| `avail.cert.v1` | *(shipped)* Verify blob availability | Existing cert daemon flow | Existing |

Admission rule for future classes: a class enters the registry only with (a) a
deterministic predicate, (b) a verifier cost bound sublinear in work cost, and
(c) a pinned execution environment (image digest + weights hash + seed policy)
sufficient for bit-reproducibility. Closed-weight API models fail (c) — they
cannot be admitted to the re-execution tier and must wait for the attested/ZK
lanes (§8).

## 5. Lifecycle

```
Requester                     Chain (pallet-agent-work)            Agent                    Verifier committee
   │  post_task(spec_hash,        │                                  │                            │
   │  escrow, deadline, policy)   │                                  │                            │
   ├─────────────────────────────►│  escrow locked                   │                            │
   │                              │◄─────────────────────────────────┤ claim_task(id) + bond      │
   │                              │                                  │                            │
   │                              │        (off-chain: agent executes task, builds work          │
   │                              │         receipt via receipt-builder, uploads blobs)          │
   │                              │                                  │                            │
   │                              │◄─────────────────────────────────┤ submit_receipt (orinq)     │
   │                              │◄─────────────────────────────────┤ submit_work(id,receipt_id) │
   │                              │                                  │                            │
   │                              │   cert daemon availability attestation (existing lane)       │
   │                              │◄─────────────────────────────────────────────────────────────┤
   │                              │                                  │      commit_verdict(id, H) │
   │                              │◄─────────────────────────────────────────────────────────────┤
   │                              │                                  │  reveal_verdict(id,v,salt) │
   │                              │◄─────────────────────────────────────────────────────────────┤
   │                              │   quorum reached                 │                            │
   │                              │◄── settle_task(id) ── keeper (permissionless, bonded)        │
   │   output root final          │   escrow → agent + verifier fees │                            │
   │◄─────────────────────────────┤   agent bond released            │                            │
```

State machine per task:

```
Posted ──claim──► Claimed ──submit_work──► Submitted ──avail cert──► Verifiable
   │                 │                        │                          │
   │ deadline        │ deadline               │ deadline                 │ quorum ACCEPT ─► Accepted ─settle─► Paid
   ▼                 ▼                        ▼                          │ quorum REJECT ─► Rejected (bond slash,
Expired          Expired (bond            Expired (bond                  │                   escrow refund)
(refund)         partial-slash)           partial-slash)                 ▼ no quorum by deadline ─► Stalled (governance)
```

Timeout behavior: every transition has a deadline; `expire_task` is
permissionless (keeper-driven) so funds never strand. `Stalled` (committee
failed to reach quorum) refunds the requester, releases the agent bond, and
strikes non-revealing verifiers — the agent is not punished for verifier
liveness failures.

## 6. On-Chain Design — `pallet-agent-work` (sketch)

Conventions follow `orinq-receipts`: `H256` ids, `[u8; 32]` hashes,
`created_at_millis: u64` runtime timestamps (D6), SCALE types with
`MaxEncodedLen`, bounded collections everywhere.

### 6.1 Types

```rust
pub type TaskId = H256;          // H(spec_hash ‖ requester ‖ nonce)

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, ...)]
pub struct TaskRecord<AccountId, Balance> {
    pub class_id: [u8; 32],            // registered task class
    pub spec_hash: [u8; 32],           // JCS content hash of the task spec blob
    pub spec_receipt_id: [u8; 32],     // orinq receipt committing the spec + inputs
    pub escrow: Balance,               // MATRA locked at post
    pub verifier_fee_bps: u16,         // slice of escrow paid to revealing verifiers
    pub agent_bond: Balance,           // required to claim
    pub sample_rate_bps: u16,          // AW-D7 sampling density
    pub quorum: u8,                    // M of the committee
    pub claim_deadline_millis: u64,
    pub work_deadline_millis: u64,
    pub verify_deadline_millis: u64,
    pub requester: AccountId,
    pub status: TaskStatus,
    pub created_at_millis: u64,
}

#[derive(...)]
pub enum TaskStatus {
    Posted, Claimed, Submitted, Verifiable,
    Accepted, Rejected, Paid, Expired, Stalled,
}

#[derive(...)]
pub struct WorkSubmission<AccountId> {
    pub agent: AccountId,
    pub work_receipt_id: [u8; 32],     // orinq receipt for the work output
    pub output_root: [u8; 32],         // Merkle root of output leaves
    pub claimed_score: u64,            // opt.score.v1 objective (fixed-point); 0 otherwise
    pub sample_seed_block: u32,        // block whose hash seeds AW-D7 sampling
    pub created_at_millis: u64,
}

#[derive(...)]
pub enum Verdict { Accept, Reject /* reason code in event */ }

#[derive(...)]
pub struct VerdictCommit {
    pub commitment: [u8; 32],          // H(verdict ‖ salt ‖ verifier)
    pub created_at_millis: u64,
}
```

### 6.2 Work certificate

Mirrors the 202-byte availability cert discipline (`types.rs`, operator-kit
`cert_builder.py` symmetry): a fixed-width SCALE struct with domain separator
`"materios-work-cert-v1"` padded to 32 bytes, fields
`{domain, chain_id, task_id, work_receipt_id, output_root, claimed_score,
verdict, quorum, schema_version}`. Signed by each revealing verifier; the
aggregate is the settlement evidence a keeper presents to `settle_task` and, on
fraud, the input to the slash path. Byte-exact layout is a schema change — same
pinning rules as the availability cert.

### 6.3 Extrinsics

| Call | Index | Origin | Notes |
|---|:---:|---|---|
| `register_task_class` | 0 | Root | admit `class_id` + spec/receipt schema hashes (AW-D2 gate) |
| `post_task` | 1 | Signed | locks escrow; validates class registered, deadlines ordered |
| `cancel_task` | 2 | Signed (requester) | only in `Posted`; full refund |
| `claim_task` | 3 | Signed (agent) | reserves `agent_bond`; first-come or auction per class config |
| `submit_work` | 4 | Signed (claiming agent) | requires orinq receipt to exist; sets sample seed block = current |
| `commit_verdict` | 5 | Signed (committee) | only after availability cert on the work receipt |
| `reveal_verdict` | 6 | Signed (committee) | checked against commitment; tallies quorum |
| `settle_task` | 7 | Signed (bonded keeper) | pays agent + verifier fees, releases bonds, emits `WorkCertified` |
| `expire_task` | 8 | Signed (anyone) | drives deadline transitions; refund/strike logic |
| `slash_bad_work_verdict` | 9 | Signed (watcher) | evidence = re-execution transcript hash + dissenting cert; M-of-N committee co-signs, mirroring `slash_bad_settlement_evidence` (treasury + watcher share) |
| `join_verifier_committee` / `leave_verifier_committee` | 10/11 | Root | governance-admitted, bonded — identical admission shape to attestation committee |

Events: `TaskPosted`, `TaskClaimed`, `WorkSubmitted`, `VerdictCommitted`,
`VerdictRevealed`, `WorkCertified { task_id, agent, payout }`, `WorkRejected`,
`TaskExpired`, `VerifierSlashed { reason }`.

Reuse note: an alternative to a new pallet is extending
`materios-intent-settlement`'s `pallet-intent-settlement` with a `WorkTask`
intent kind — it already owns escrow, M-of-N attestation, vouchers, bonds, and
slashing. The pallet boundary decision belongs to implementation review; this
RFC only fixes the state machine, predicates, and economics. (Recommendation:
prototype inside intent-settlement to avoid re-auditing an escrow path, split
out later if the surface grows.)

## 7. Work Receipt Schema (`agent-work.v1`)

JCS-canonicalized JSON (D3), content-hashed before compression (D2), schema
identified by hash (D8). Indicative shape:

```json
{
  "schema": "agent-work.v1",
  "task": { "task_id": "0x…", "class_id": "opt.score.v1", "spec_hash": "0x…" },
  "agent": {
    "account": "5F…",
    "operator_did": "did:web:example.com",
    "runtime": {
      "image_digest": "sha256:…",
      "model_weights_hash": "0x…",
      "seed": 42,
      "temperature": 0
    }
  },
  "inputs":  { "root": "0x…", "count": 1024 },
  "outputs": { "root": "0x…", "count": 1024, "leaf_hash": "sha256" },
  "metrics": { "claimed_score": "1287.5000", "wall_ms": 184223 },
  "timestamps": { "started_ms": 0, "finished_ms": 0 }
}
```

The `runtime` block is what makes AW-D2 re-execution possible; a receipt whose
class requires bit-reproducibility but omits any pinning field is rejected at
schema validation (cert daemon side), before it ever reaches a verifier.

## 8. Verification Lanes (now → later)

| Lane | Trust model | Status |
|---|---|---|
| **L0 — Availability** | M-of-N bonded attestors confirm blobs are fetchable | Shipped (cert daemon) |
| **L1 — Deterministic re-execution** | M-of-N bonded verifiers, commit-reveal, sampled | This RFC, v1 |
| **L2 — ZK claims** | Midnight Compact circuit proves predicates over committed receipts (e.g. `claimed_score ≥ threshold`, output-root consistency) without re-execution | Extend `audit-claims.compact`; replaces quorum for circuit-expressible predicates |
| **L3 — Attested execution** | TEE quote binds output root to a pinned image + weights; admits closed-weight/API-model tasks that L1 cannot | Exploratory |

L2 is the strategic lane: every predicate moved into a circuit removes verifier
committee load *and* its collusion surface. The existing Poseidon path (D4) in
receipt-builder exists precisely to make output roots cheap inside circuits.

## 9. Economics & Threat Notes

- **Payout split:** `escrow = agent_payout + verifier_fee_bps + keeper_fee`.
  Verifier fees divide equally among revealing verifiers whose verdict matched
  the quorum outcome; dissenters matching a later successful fraud proof are
  made whole retroactively from the slash.
- **Agent griefing (claim-and-abandon):** partial bond slash on work-deadline
  expiry compensates the requester for lost time; remainder returns to the
  agent. Bond floor per class prevents free option-taking on hot tasks.
- **Verifier collusion:** the residual risk in L1. Mitigations layered:
  commit-reveal (AW-D3), unpredictable sampling (AW-D7), permissionless
  watchers with slash bounties (anyone can re-execute and prove a wrong
  verdict — the predicate's determinism is what makes the fraud proof
  compelling), and the L2 roadmap which removes the committee from
  circuit-expressible classes entirely.
- **Requester griefing (unverifiable spec):** the spec blob is itself an orinq
  receipt with an availability cert *before* any agent can claim — an agent
  never bonds against a task whose inputs it cannot fetch.
- **What this deliberately is not:** consensus work (AW-D1), protocol-subsidized
  emissions (AW-D4), subjective scoring (AW-D2), or any form of incentivized
  outreach/messaging — paying for unsolicited wallet messages is spam by
  construction, is trivially Sybil-farmed, and would poison the receipt
  system's credibility. It stays excluded at the task-class admission rule.

## 10. Open Questions

1. **Subsidy pool.** A protocol-matched pool (mirroring the 50M attestation
   reserve, with per-era caps) would bootstrap supply-side liquidity, but is
   self-dealing bait. Gate candidates: match only tasks where requester and
   agent fail an association heuristic; match proportional to burned MOTRA;
   cap per-agent per-era. Needs its own economic review before any reserve is
   allocated.
2. **Auction vs. first-claim.** v1 assumes first-claim-with-bond. Sealed-bid
   claim auctions (price discovery for agent work) fit the commit-reveal
   machinery but complicate deadlines. `opt.score.v1` may instead want
   *open-window best-score-wins* with no exclusive claim at all.
3. **Pallet boundary.** New `pallet-agent-work` vs. a `WorkTask` intent kind in
   `pallet-intent-settlement` (see §6.3 reuse note).
4. **Dispute-game lane for subjective tasks.** If ever admitted, subjective
   classes need an escalation game (opt-in arbiters, appeal bonds) — not
   quorum scoring. Explicitly out of v1.
5. **Agent reputation.** Certified `WorkCertified` events are a natural
   substrate for an off-chain reputation index; whether any of it should feed
   on-chain parameters (e.g. reduced bonds for proven agents) is deferred.

## 11. Phased Roadmap

| Phase | Deliverable | Repo(s) |
|---|---|---|
| 0 | This RFC review + task-class registry schema | `materios` |
| 1 | `agent-work.v1` receipt schema in receipt-builder + cert daemon validation; end-to-end demo paying an agent via existing intent-settlement escrow driven manually | `materios`, `materios-operator-kit` |
| 2 | Escrow/verdict state machine on-chain (pallet-boundary decision per §10.3); keeper support | `materios-intent-settlement` or `materios` |
| 3 | L2 ZK verification for `opt.score.v1` threshold claims | `materios` (midnight/) |
| 4 | Agent runtime integration — task discovery, claim, execute, receipt, submit loop | `materios-gateway`, `t-backend` |

## 12. References

- Fitzi, Kiayias, Panagiotakos, Russell — *Ofelimos: Combinatorial Optimization
  via Proof-of-Useful-Work*, Crypto 2022. <https://eprint.iacr.org/2021/1379>
- *SoK: Is Proof-of-Useful-Work Really Useful?*, 2025.
  <https://eprint.iacr.org/2025/1814>
- *Efficient and PoUW-Friendly Local-Search for Distributed Consensus* (FRLS),
  2025. <https://eprint.iacr.org/2025/2091>
- Opentensor — *Weight Copying in Bittensor*, working paper, 2024.
  <https://docs.learnbittensor.org/papers/BT_Weight_Copier-29May2024.pdf>
- *Proof of Useful Attestation: A Consensus Primitive for Attestation-Native
  Chains*, 2026. <https://arxiv.org/abs/2605.25844>
- Materios: `docs/ARCHITECTURE.md` (D1–D8), `docs/AVAILABILITY_CERT_SPEC.md`,
  `docs/SPO_REWARDS.md`; intent-settlement `docs/spec-v1.md`.
