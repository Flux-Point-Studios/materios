# Executable RED acceptance contracts

Run from the repository root. Each packet `argv` is a literal argument array,
not a shell command. The adapter forces Cargo artifacts into this checkout's
`.zk-spec-target` and uses two build jobs with `nice -n 10`. Run heavy suites
one at a time. No driver is included in this specification pass.

`test_adapter.py` tests the adapter itself. `contracts.py` contains the semantic
scaffolds. `check.py c-...` selects a nonempty suite and fails on any failure,
error, skip, expected failure or incomplete count. `c-motra-66` references AJ's
eight tests in `partnerchain/pallets/motra/src/tests.rs`: it first checks source
names, then compiled `--list`, then runs each with `--exact` and requires exactly
one passing, non-ignored result. Source names alone never produce GREEN.

## Future implementation adapter

Add `tools/zk-spec/driver/Cargo.toml` with a locked Rust binary named
`materios-zk-spec-driver`. It must depend on the actual production crates and
instantiate their built runtime through the pinned Substrate Wasm executor.
Do not copy state transition logic into the driver. Codec operations call actual
Rust and Aiken codecs; metadata operations call the existing #494 gate; wallet,
soak and coverage operations consume independently captured runtime evidence.
This source and every new fixture require review before a GREEN claim.

The adapter builds the driver using `cargo +1.85.0 build --locked --offline`.
Missing offline dependencies fail; dependency preparation is an explicit setup
step. Build errors, missing tools, timeouts and malformed responses are RED.
No environment switch replaces the driver with an arbitrary executable.

Each invocation reads one JSON request from stdin:

```json
{"version":1,"operation":"hybrid-sequence","payload":{"operations":[]}}
```

It emits one object with `version: 1` and an object `result`. The example's empty
operations are not a valid property run. The actual request data and all
asserted result fields are specified by each test in `contracts.py`. Every
result includes `executor: "wasm"` and the SHA-256 of the runtime actually loaded.
This declaration is an evidence pointer, not a self-authenticating claim.

The driver exposes snapshots/results, not pass/fail judgments. Python compares
observed lane/account/escrow totals to independent arithmetic, compares codec
bytes, and asserts expected negative results. A collected evidence file must
bind the source commit, runtime/fixture hashes, command, environment and raw
observations; empty lists and stale mismatched captures are failures. Tests that
observe counts (soaks, floods and coverage) require review of the underlying
event stream and instrumentation; a handwritten counter is not evidence.

Fixtures contain public data or deterministic disposable test identities only.
Do not read production secrets, start/signals/restart any live validator, alter
host firewall rules or broadcast on mainnet. The Midnight test isolates its
entire child process tree in a new network namespace; it changes no host network
configuration. On unavailable namespace support it fails instead of skipping.
Compile/download required public dependencies before that no-egress experiment.

Runtime microbenchmarks and slowest-hardware runs are separate observations.
The `sapling-benchmark` operation must use the complete production bundle path
(all Groth16, binding/spend signatures, serialization and tree work), not the
native microbenchmark in the study. The 150/400 ms limits are proposed policy.
Controlled test-wallet notes are decrypted only to independently check the
bounded supply property, not to claim visibility into production hidden supply.

`mainnet-isolation` uses separately rebuilt artifacts from a reviewed post-AJ
launch reference. It must refuse a missing reference and positively show that
the preprod build contains the new functionality. It does not run a mainnet node
or authorize publication. `activation-gate-simulation` is always offline and
must demonstrate zero broadcasts even when synthetic approval fixtures exist.

`mainnet-zk-enablement` enumerates mainnet chain specs and ZK pallets from the
reviewed production source and pinned fixtures, including plain/raw specs. Its
`cases` cover their full cross product exactly once; every attempted enablement
is refused and every resulting `enabled_zk_pallets` list is empty.
`activation-hold-coverage` enumerates all mainnet-capable activation paths from the same source,
including genesis, runtime upgrades and governance routes where present. Each
path retains all four authority holds and denies activation. Both operations
receive `packet_scope: "preprod-only"` and `synthetic_approvals: "all-present"`;
synthetic approvals cannot release the holds. Empty inventories, missing or
duplicate cases, missing holds, allowed activation and nonzero broadcasts fail.
Independent review must establish inventory completeness and source coverage.
These are offline mainnet refusal scenarios; they do not prohibit preprod activation.

The synthetic responses in `test_adapter.py` only exercise these assertions.
They are not runtime fixtures or evidence that the actual activation gates exist.
Future CEO approval belongs to a [separate packet](../../docs/native-zk-handoff.md#future-ceo-approval-packet).

## Assurance limits

These are RED scaffolds, not a complete verifier implementation or a formal
model. There is no formal proof obligation or escape-hatch baseline to arm.
The ten-thousand-transition property covers one reproducible generated domain
plus named boundary cases; it cannot prove arbitrary sequences or cryptographic
soundness. A future implementer must add regression cases discovered in review
and the full affected-crate, migration, lint, build and runtime suites.

Backend licenses, concrete parameters, finality checkpoint policy, cryptographic
public-input encoding and signed transaction domains must be pinned in the
implementation revision. Existing metadata/call bytes cannot be inferred safe
from JSON schemas. The verifier gets this same packet and must rerun it against
the committed implementation, rather than trusting a previous report.
