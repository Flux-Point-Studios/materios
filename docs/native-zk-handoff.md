# Native ZK specification handoff

Local specification and RED scaffolds only. No feature implementation, live verification, PR, push, vendor engagement or mainnet action.

The requested lock is blocked by a brief/runner conflict: literal `blocked` statuses are required, but the specified FluxPoint 1.42.0 validator rejects them. No digest exists. Awaiting the user's clarification; no approval inferred.

All decisions remain model recommendations. Labels `d-*` are the canonical lowercase versions of the brief's `D-*` names.

| id | status | baseline | one-line why | blocked? |
|---|---|---|---|---|
| d-arch | defaulted | wasm-semantics-rfc163-math | Forkless ledger policy, narrow optional node math. | no; mainnet separately held |
| d-order | defaulted | narrow-hub-first-parallel-sapling-spike | Other-chain verification gets the first real consumer. | no; mainnet separately held |
| d-shield-circuit | defaulted | unchanged-sapling-groth16-bls12381 | Reuse a single-asset relation only after a complete Wasm spike. | no; mainnet separately held |
| d-hub-scope | defaulted | bounded-versioned-hub-with-consensus-consumer | Proof validity, consensus and attestation remain distinct. | no; mainnet separately held |
| d-supply | defaulted | single-issuance-sovereign-escrows | Transfers under one issuance counter, with explicit soundness limits. | no; mainnet separately held |
| d-utxo | defaulted | bounded-matra-hybridtx | Exclusive value and atomic lane conversions without pretending FRAME is parallel. | no; mainnet separately held |
| d-fees | defaulted | motra-only-account-or-authorized-sponsor | MOTRA only; fresh owners need authenticated sponsorship. | no; mainnet separately held |
| d-motra-accrual | defaulted | aj-66-before-genesis | Known exploit is a genesis launch blocker owned by AJ. | no; mainnet separately held |
| d-bridge-datum | defaulted | versioned-account-utxo-reserved-shielded | Versioned recipients; reserved tags reject until separately implemented. | no; mainnet separately held |
| d-midnight-optional | defaulted | core-without-midnight-offline-adapters | Core survives removed adapters and no external network. | no; mainnet separately held |
| d-genesis-isolation | defaulted | reviewed-post-aj-launch-baseline-no-zk | Pin reviewed artifacts after AJ, then exclude ZK from launch. | no; mainnet separately held |
| d-scope | defaulted | matra-only-three-lanes-and-verification | Complete single-asset value lanes before private contracts or new assets. | no; mainnet separately held |
| d-host-acceleration | defaulted | pure-wasm-until-dark-rollout-proven | No new import until measured need and complete role coverage. | no; mainnet separately held |
| d-compliance | blocked | hold-engagement-and-activation-pending-ceo-counsel | Counsel and legal posture need explicit authority. | yes |
| d-audit | blocked | hold-booking-external-audit-before-activation | Independent integration review; no unauthorized booking. | yes |
| d-budget | blocked | no-spend-or-commitments-without-explicit-approval | No quote or approved spending/commitment exists. | yes |
| d-mainnet-rollout | blocked | hold-all-mainnet-actions-for-reviewed-gates-and-deci | Lock identity cannot authorize deployment or value activation. | yes |

Every option has an objection and cost with an evidence basis in the packet. No cost in this pass is presented as a measured performance result or vendor quote.

| Requirement | Check ids | Actual RED evidence |
|---|---|---|
| r-architecture | [c-sapling-wasm](native-zk-evidence/c-sapling-wasm.log), [c-host-coverage](native-zk-evidence/c-host-coverage.log) | exit 1: missing runtime driver |
| r-other-chains | [c-hub-other-chains](native-zk-evidence/c-hub-other-chains.log) | exit 1: missing runtime driver |
| r-hub-domains | [c-hub-other-chains](native-zk-evidence/c-hub-other-chains.log) | exit 1: missing runtime driver |
| r-sapling-spike | [c-sapling-wasm](native-zk-evidence/c-sapling-wasm.log) | exit 1: missing runtime driver |
| r-supply | [c-supply-invariant](native-zk-evidence/c-supply-invariant.log) | exit 1: missing runtime driver |
| r-midnight-independent | [c-midnight-blackhole](native-zk-evidence/c-midnight-blackhole.log) | exit 1: missing runtime driver |
| r-metadata | [c-metadata-append-only](native-zk-evidence/c-metadata-append-only.log) | exit 1: missing runtime driver |
| r-genesis-isolation | [c-mainnet-isolation](native-zk-evidence/c-mainnet-isolation.log), [c-motra-66](native-zk-evidence/c-motra-66.log) | exit 1: missing runtime driver; AJ's eight tests absent at base |
| r-bridge-datum | [c-bridge-datum](native-zk-evidence/c-bridge-datum.log) | exit 1: missing runtime driver |
| r-motra-66 | [c-motra-66](native-zk-evidence/c-motra-66.log), [c-mainnet-isolation](native-zk-evidence/c-mainnet-isolation.log) | exit 1: missing runtime driver; AJ's eight tests absent at base |
| r-fees-admission | [c-fees](native-zk-evidence/c-fees.log) | exit 1: missing runtime driver |
| r-utxo | [c-hybrid-utxo](native-zk-evidence/c-hybrid-utxo.log), [c-supply-invariant](native-zk-evidence/c-supply-invariant.log) | exit 1: missing runtime driver |
| r-shielded-runtime | [c-shielded-e2e](native-zk-evidence/c-shielded-e2e.log), [c-supply-invariant](native-zk-evidence/c-supply-invariant.log) | exit 1: missing runtime driver |
| r-host-rollout | [c-host-coverage](native-zk-evidence/c-host-coverage.log) | exit 1: missing runtime driver |
| r-authority | [c-activation-gates](native-zk-evidence/c-activation-gates.log) | exit 1: missing runtime driver |

Exact commands, full outputs and adapter RED→GREEN history are in [verification evidence](native-zk-evidence/README.md). Adapter suite: 20 tests passed, zero skips. Acceptance commands: 13 expected nonzero exits. No Cargo build or live-chain operation was attempted in this pass.

Challenges were applied in the required security, launch/operations, then feasibility/evidence order. The packet contains every claim and resolution:

- Security C01: A valid Groth16 proof proves foreign-chain finality. REJECTED. r-other-chains requires chain/checkpoint/authority transitions and inclusion; r-hub-domains binds proof claims separately. No automatic bridge credit follows.
- Security C02: A balanced public escrow proves no counterfeit hidden notes exist. REJECTED. r-supply limits its claim to custody conservation and controlled-wallet witnesses. Hidden-note soundness still depends on the relation, setup, encodings and audit; caps bound only value release, not downstream damage.
- Security C03: A last/current minimum still permits leave-and-return MOTRA farming between touches. ACCEPTED. Require every eligible balance transition accounted for and AJ's exact round-trip/delegation regressions; do not duplicate AJ's implementation.
- Security C04: Reuse of Sapling allows arbitrary circuit edits without new setup review. REJECTED. Baseline relation stays unchanged; version and hash-pin parameters/VKs, reject noncanonical encodings and test every proof-bit mutant. New asset/fee circuits require a new packet and reviewed parameters.
- Security C05: Put consumed outpoints only in requires tags. REJECTED. Consumed outpoints and sponsor vouchers must conflict through provides-style tags, then be rechecked at dispatch. Account-only intents need separate replay protection.
- Security C06: Delegatees permits taking fees from any named sponsor. REJECTED. It routes generation; it does not authorize arbitrary third-party debits. Signed relayers pay their own MOTRA and unsigned Lane U requires authenticated single-use fee authorization.
- Security C07: Permissionless VK registration should authorize every consumer. REJECTED. Registration deposits bound storage; each consumer pins backend/version/VK/domain/trust. Committee and hardware attestations cannot become consensus proofs by relabeling.
- Security C08: Mutation testing and invariant success replace independent audit. REJECTED. Tests cover bounded domains. d-audit remains blocked for booking and requires independent integration review before value-bearing activation.
- Security C22: Binding note identity to runtime spec_version could strand notes after unrelated upgrades. ACCEPTED. Use an explicit note-protocol signing domain with chain genesis and all spend effects, not automatic note identity changes on each runtime release. r-shielded-runtime adds an old-note spend witness across an unrelated pallet append; actual protocol migrations require separate review.
- Launch/operations C09: Freezing the base revision would preserve the MOTRA exploit. ACCEPTED. The reviewed launch baseline must first include AJ's fix. ZK then proves isolation against that baseline. Missing reviewed artifacts remain RED.
- Launch/operations C10: Disabled ZK genesis code is equivalent to absent code. REJECTED. Preserve launch node/runtime/genesis/metadata/import bytes; positive preprod capability is required to avoid identical empty builds passing.
- Launch/operations C11: Even default-off new host imports can halt unupgraded nodes at instantiation. ACCEPTED. Ship arithmetic dark and activate imports only after complete authenticated role coverage and differential/devnet evidence.
- Launch/operations C12: Reserved Shielded datum tag ensures a future immutable validator can process it. REJECTED. Reserved means rejected. Future semantics require a new reviewed version/contract decision; unknown data cannot fall back to accounts.
- Launch/operations C13: A generated #494 manifest is sufficient authority to upgrade. REJECTED. Test actual append-only metadata and mutants, preserve envelope, inspect migration state and require independent origin/source review and applicable timelock/multisig. No ceremony occurs here.
- Launch/operations C14: A locked recommendation authorizes counsel, audit or mainnet work. REJECTED. d-compliance, d-audit, d-budget and d-mainnet-rollout remain blocked. Their recommendations are filled but authority must be explicit.
- Feasibility/evidence C15: The native 2.41 ms arkworks result does not measure a full Sapling Wasm bundle. ACCEPTED. Recorded as unreplicated study evidence only. Require signatures, encodings, tree costs and slowest-hardware samples; thresholds are policy, not measurements.
- Feasibility/evidence C16: Other-chain priority warrants shipping all five backends together. REJECTED. d-order selects a narrow hub with a real foreign-chain consumer plus parallel Sapling spike; backend-specific gates avoid a generic registry without users.
- Feasibility/evidence C17: A hosts file or no-op optional test proves Midnight independence. REJECTED. r-midnight-independent requires isolated no-egress execution, positive denial probes, excluded dependencies and named nonempty core scenarios.
- Feasibility/evidence C18: Exit zero, names or empty JSON can make a vacuous test look successful. ACCEPTED. Reject missing drivers, timeouts, zero/ignored tests, unknown statuses and malformed/duplicate-key responses. Assert actual state transitions; list and run AJ tests exactly. Driver correspondence still needs review and real artifacts.
- Feasibility/evidence C19: An orphaned BLS library means Mithril support is ready. REJECTED. Official STM docs confirm a BLS12-381 backend, narrowing the study uncertainty. Wasm portability, certificate chains, stake/checkpoint semantics and bounded costs remain a separately gated spike.
- Feasibility/evidence C20: Trustworthy evidence must distinguish scaffold readiness from implementation readiness. ACCEPTED. Adapter unit tests may become GREEN; every feature check stays RED until its real dependencies and assertions run. No --run, live chain experiment or production assurance claim is made by this pass.
- Feasibility/evidence C21: The exact supplied runner accepts blocked decisions and uppercase D- ids at lock time. REJECTED by inspected code: FluxPoint 1.42.0 accepts only defaulted/user-confirmed statuses and lowercase kebab-case ids. IDs are normalized to d-* with the same meaning. Literal blocked statuses are preserved pending the user's answer; no lock digest is fabricated or validator patched.

To unblock the lock, the user must resolve the explicit choice: allow defaulted deny-action baselines with authority blocks retained in their records, or retain literal blocked statuses until the canonical runner/brief is corrected. This task does not patch the plugin or fake a lock.

To unblock implementation evidence, add a reviewed production runtime/codec driver and immutable fixtures, land AJ's fix/tests, establish the reviewed post-AJ launch baseline, and run the actual benchmark, codec, metadata, property and preprod/soak checks. Mainnet and procurement still require deci's explicit authorization, counsel/audit evidence and the gated rollout.

No LOW issues were filed. No PR exists; the brief requires a local commit only. The commit SHA is intentionally not embedded in its own contents; use `git rev-parse HEAD`. No shared-memory file was changed because this handoff confines writes to this worktree.
