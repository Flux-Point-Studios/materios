# Phase-aware native ZK acceptance contracts

## Setup and replay

Measured results, scope boundaries and raw captures are in
[the P0 evidence report](../../docs/native-zk-p0.md).

Run `tools/zk-spec/setup.sh`, then `scripts/harness.sh --full` or `--all` from
this checkout. Setup installs only into ignored task artifacts and builds the
runtime/core with two jobs at low priority. It requires Rust 1.85.0, Node,
Python 3, Aiken 1.1.22 and the normal runtime build prerequisites. The no-egress
check requires an available `unshare --net` privilege; on Gemtek it uses
`sudo -n unshare --net runuser -u deci` and drops back to the caller before Cargo.
It never changes host routes or firewall rules. Missing privileges fail.

CI's `zk-p0` workflow builds/tests the primitive, verifies the Wasm proof corpus
without timing service hosts, and checks actual rebuilt-runtime metadata. Its
metadata step uses a runtime-only Cargo check with Rust 1.85.0 and checksum-pinned
subwasm 0.21.3. The namespace-isolated build/test and Gemtek benchmark are local
acceptance runs, repeated when `--full` selects ZK work.

The workflow runs on pushes to `main` and on pull requests to any base branch
when at least one changed path matches `tools/zk-spec/**`, `.fluxpoint-spec.json`,
`.fluxpoint-spec-lock.json`, `WORK.md`, `scripts/harness.sh`,
`.woodpecker/zk-p0.yaml`, `partnerchain/runtime/**`, `partnerchain/pallets/**`, or
`chain-spec/**`. The `c-p0-sapling-spike` and `c-p0-metadata-compat` steps run
only for `tools/zk-spec/**` or either spec file. Other matching paths run the
cheap primitive checks. The required Rust workflow has no P0 baseline gate.
Both path conditions
set `on_empty: false`. Docs-only changes outside these paths select no ZK steps.

[Woodpecker path conditions](https://woodpecker-ci.org/docs/usage/workflow-syntax#path)
use include globs for both push and pull-request events. Pull requests supply
the entire PR diff, so a docs-only commit on a PR containing ZK changes still
runs the spike and metadata comparison. `ci_paths_test.py` exercises the workflow's actual conditions
with the checksum-pinned Woodpecker 3.16.0 CLI and harmless local step markers.
CI runs this test before `ci.sh`; replay it with PyYAML installed and
`WOODPECKER_CLI=/path/to/woodpecker-cli python3 tools/zk-spec/ci_paths_test.py`.
The separate `ci-sapling.sh` consumes the shared Cargo cache populated by
`ci.sh` in the preceding step.
`fixtures/pr-68-changed-files.txt` pins the GitHub changed-file list for PR #68
at `58eb0456be7a77829b6e0344955999ef5eadeaf6`; that runtime fix selects only
the cheap ZK step.

## P0 execution

`driver` is the Rust dispatcher. It calls the standalone `materios-zk-core`
production primitive for bridge decoding and activation refusal; the Aiken CEK
evaluator for codec assertions; the existing #494 structural gate on metadata
extracted from the actual rebuilt runtime by pinned subwasm 0.21.3; and the
no_std Wasm spike in Node/V8. Core build/tests run inside a new network namespace
with a fresh target directory; Cargo must report newly compiled core artifacts.
Every command exit and required artifact is checked. Unknown operations fail.

P0 does not append or activate runtime pallets. The named mainnet target surface
is derived from `node/src/command.rs::load_spec`: this source has no built-in
mainnet builder, so all mainnet targets enter through the generic JSON-file
route (plain or raw). The core refuses that route even when a file adopts the
preprod id. The named preprod builder is a positive control. P5 must still prove
the nonempty pallet cross product and all runtime activation routes.

The P0 metadata baseline is an explicit pre-AJ source identity, with complete
metadata extracted from an unchanged-source runtime build. It is not an approved
genesis baseline. The spike measures full standalone 1-spend/2-output bundle
verification, signatures, decoding and tree work. It does not claim production
pool execution or the later 100-bundle reviewed-slowest-hardware obligation.

`scripts/harness.sh --full` always validates the specification lock and runs the
tools/zk-spec unit tests. It runs phases through CURRENT_PHASE in WORK.md only
when `tools/zk-spec/**` or either spec file changed against `FPL_DIFF_BASE`, or
against the merge-base with `origin/main` when that variable is unset or empty.
Committed, staged, unstaged, deleted and untracked paths count; ignored artifacts
do not. Invalid or unavailable bases fail closed. Runtime-only work prints the
resolved base and reports that P0 phase checks were not selected. `--spec-check`
validates only the lock. `--all` executes every check regardless of paths and
reports later-phase RED results. Original
`contracts.py` is intentionally byte-identical to the first locked packet.

The following contract describes the end-state driver operations; P0 only
implements its distinctly named `p0-*` operations.

Run from the repository root. Each packet `argv` is a literal argument array,
not a shell command. The adapter forces Cargo artifacts into this checkout's
`.zk-spec-target` and uses two build jobs with `nice -n 10`. Run heavy suites
one at a time. The P0 driver is included; later operations fail until implemented.

`test_adapter.py` tests the adapter itself. `contracts.py` contains the semantic
scaffolds. `check.py c-...` selects a nonempty suite and fails on any failure,
error, skip, expected failure or incomplete count. `c-motra-66` references AJ's
eight tests in `partnerchain/pallets/motra/src/tests.rs`: it first checks source
names, then compiled `--list`, then runs each with `--exact` and requires exactly
one passing, non-ignored result. Source names alone never produce GREEN.

## Future implementation adapter

The end-state implementation extends `tools/zk-spec/driver/Cargo.toml`, whose locked Rust binary is named
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
