# Native ZK research record

This is a specification pass at `52829ca46323cf22b3e0feece3adc33cb4edb095`.
No runtime, node, chain specification, running service, or external contract is changed.
No recommendation is a CEO selection or an authorization to spend or activate.

## Evidence and reuse

**E-brief.** The local `materios-zk-grill/BRIEF.md` requests native ZK,
shielded/unshielded MATRA, a hybrid ledger, preprod first, forkless delivery,
optional Midnight and first-class verification of other chains. It requests RED
scaffolds and a local commit only. The baseline study is dated October 16, 2026;
the direction it records is dated October 17. Dates do not establish approval.

**E-lock-brief.** `/home/deci/.local/state/codex-tasks/materios-zk-lock/BRIEF.md`
directs the four authority decisions to use `defaulted` DENY holds and limits
implementation to PREPROD. The installed FluxPoint 1.42.0 `commands/grill-me.md`
allows a safe conditional or deny-by-default choice to resolve unknown facts.
Its unchanged `scripts/specification.py` accepts only `defaulted` and
`user-confirmed` at lock time. This resolves the prior drafting conflict without
granting authority. Separate CEO decisions remain required for counsel, audit,
spend and mainnet, as listed in the [future approval packet](native-zk-handoff.md#future-ceo-approval-packet).
The existing `ActivationGates` scaffold is extended to cover mainnet pallet
enablement and hold coverage; no new runtime or launch-gate implementation is
introduced. Rechecked registry overlap with
`rg -n -i 'materios|zkverify|sapling|verifier|shielded|utxo' /home/deci/work/SUBSTRATE.md`:
launch-preflight, runtime-build and root-timelock remain the reusable enforcement
surfaces for the future driver. Existing upstream research and technical
baselines are unchanged by this authority-only revision.

**E-study.** Read the complete `zk-decision.md` from workflow
`wf_f78daa70-9b0`, and the architecture, risk and optionality results of its
composable-primitives, shield-first and Midnight-compatible designs. Reused the
research journal's source links and reviewed the losing designs' objections.
The full Midnight ledger design requires native ledger code and off-trie state;
it conflicts with forkless ledger semantics. Shield-first demonstrates a narrower
delivery slice, but delays the multi-chain consumer. The hub-first design fits
the stated thesis provided its first release is narrow and has actual consumers.

The study reports a native arkworks verification measurement of 2.41 ms and a
no_std build. This pass did not reproduce either and has no benchmark artifact
from that run. Neither establishes Sapling bundle cost in Materios Wasm.
Published hardware timings, the proposed five-week delivery, and a claimed
sevenfold host speedup are not local measurements or delivery commitments.

**E-code.** Read `partnerchain/runtime/src/lib.rs`, workspace/runtime manifests,
`partnerchain/pallets/motra/src/lib.rs`, and the current test inventory. The SDK
is `polkadot-stable2409-4`, runtime spec version 240, transaction version 5;
explicit pallet indices end at 25 with vacant indices 5 and 23. SignedExtra
contains ChargeMotra. This baseline has no new ZK pool, verifier or UTXO pallet.
`LastTouched` defaults to zero; accrual uses current holdings over elapsed time.
The fee's weight term can be zero when congestion is zero.

**E-substrate.** Swept `/home/deci/work/SUBSTRATE.md` with
`rg -n -i 'materios|sapling|groth16|midnight|zk|utxo|bridge'` and reviewed this
repo's `substrate.json`. Reuse these components:

| Existing asset | Extension proposed |
|---|---|
| orinq-receipts, tee-attestation | Typed verifier statements; preserve legacy receipt bytes |
| MOTRA and Delegatees | Paid verification and owner-independent relayer funding |
| root-timelock, ceremony-metadata-gate | Append-only upgrades and host coverage refusal |
| launch-preflight, runtime-build | Reviewed post-#66 launch artifacts and reproducible isolation |
| orynq grandpa-finality-verifier | Bounded checkpoint/authority-transition/inclusion vectors |
| checkpoint-anchoring and anchor-worker | Later commitment roots and escrow observations |

No registry primitive supplies a native Sapling pool or transparent MATRA UTXO
ledger. This pass registers only the experimental specification harness. It
does not claim unbuilt pallets are shipped. Registry duplicate cleanup is owned
by registry maintenance, outside this worktree.

**E-66.** Read [Materios issue #66](https://github.com/Flux-Point-Studios/materios/issues/66)
and AJ's handoff. #66 is a genesis launch blocker, superseding the study's M1
post-launch schedule. Read AJ's eight accrual test names from its isolated
`fix/motra-accrual-66` worktree without changing it. The adapter expects those
tests in this repository after AJ lands; it never tests another worktree's code.
The round-trip regression is necessary: `min(previous, current)` at lazy
reconciliation alone does not detect a balance leaving and returning between
touches. Every eligible balance transition must be accounted for. AJ owns the
implementation, migration and full runtime validation.

**E-ops.** Read the native-ZK memory, launch roadmap, ceremony metadata gate,
append-only error lesson and isolated Cargo-target lesson. Launch isolation must
pin the reviewed launch candidate AFTER mandatory #66 corrections, not freeze
the vulnerable starting revision. Detailed launch custody records remain local.
Metadata checks cannot establish origin correctness; source and root-gate review
remain required before a ceremony. Mainnet operations remain outside this task.

## Primary-source rechecks

Queries used: `site.github.com polkadot RFC 163 elliptic curves BLS12-381`,
`site.github.com zcash sapling-crypto no_std bellman verification`, and
`site.mithril.network mithril STM signature Ed25519 BLS12-381`.
GitHub pages and source manifests were opened directly as well.

**E-rfc.** [RFC-163](https://github.com/polkadot-fellows/RFCs/blob/main/text/0163-ec-host-functions.md)
defines curve arithmetic rather than complete protocols. Its current surface
includes BLS12-381, Bandersnatch and Pasta. This does not establish availability
at Materios's pinned SDK. Limit any future node extension to its BLS12-381 shape,
pin the exact adopted revision and test ABI/encoding equivalence. No claim that
host functions eliminate producer censorship follows from this architecture.

**E-sapling.** [sapling-crypto](https://github.com/zcash/sapling-crypto) documents
no_std support and feature caveats, with MIT/Apache licensing. The
[manifest](https://raw.githubusercontent.com/zcash/sapling-crypto/main/Cargo.toml)
was inspected, but a moving upstream branch is not a tested dependency pin.
The proposed spike must pin compatible releases, retain the unmodified Sapling
relation and setup provenance, check canonical point encodings and exercise
spend/binding signatures. Existing audit history does not audit this integration.

**E-hub.** [zkVerify](https://github.com/zkVerify/zkVerify) supplies relevant
registration and verification patterns. Its repository has both Apache and GPL
licenses; select individual compatible crates after a dependency/license review,
not a blanket repository import. The
[IOG Groth16 wrapper](https://github.com/input-output-hk/plutus-groth16-wrapper)
offers a BN254-to-BLS12-381 path and Cardano verifier tooling. Proving cost,
parameter provenance and no_std compatibility remain gates. Sharing a curve
does not make encodings, public inputs or proof systems interchangeable.

**E-mithril.** The official [mithril-stm documentation](https://mithril.network/rust-doc/mithril_stm/index.html)
documents a blst BLS12-381 backend for STM. The study's uncertainty about that
backend can be narrowed, but this is not a benchmark or proof that a certificate
verifier ports to this Wasm runtime. Certificates still require protocol,
stake/checkpoint and certified-object semantics. No automatic bridge credit
is authorized from verifying a signature alone.

## Five framings used for the challenge

1. Conservation: lane conversions are custody transfers under one issuance counter.
2. Authentication: proof validity, consensus finality and inclusion are different predicates.
3. Compatibility: runtime metadata and host imports are historical replay contracts.
4. Availability: an optional chain must be removable from both build and operation.
5. Authority: a frozen recommendation is an input to review, never permission.

## Honest RED boundary

The test scaffolds call a deliberately absent, repository-owned Rust driver.
They assert state, codecs, results and negative cases; the adapter does not
accept a file's existence, a test name or an exit-zero report as semantic proof.
Implementing that driver with actual pinned runtime Wasm, production codecs and
the existing ceremony gate is the next slice. A mock or independent ledger
model cannot satisfy the driver contract. Driver correspondence and fixture
provenance need adversarial review; the JSON protocol cannot prove them.

No test in this pass has exercised a live ZK runtime, a launch artifact, an
actual shielded transfer, a hardware benchmark or a mainnet action. GREEN adapter
tests mean the harness fails closed. RED acceptance checks mean implementation
and evidence are still absent.
