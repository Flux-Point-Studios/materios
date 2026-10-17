# Native ZK P0 evidence

This P0 adds a reusable, experimental no_std Sapling verifier and canonical
Rust/Aiken bridge codec for Materios's future verification hub and shielded lane.
It does not change the node, runtime, chain specifications or running services.
The [phase revision](native-zk-revisions.md) preserves every original end-state
obligation. The materios CTO must review the pushed implementation.

## Reuse and provenance

The registry sweep and primary-source queries are recorded in
[native-zk-research.md](native-zk-research.md). P0 reuses the existing #494
metadata gate, pinned Substrate runtime builder, upstream Sapling commitments
and RedJubjub signatures, and arkworks Groth16/BLS12-381 arithmetic. There is no
new curve arithmetic, proof relation or trusted setup. The core and codec are
registered in `substrate.json` in the implementation commit.

The independently locked tools workspace uses Rust 1.85.0, arkworks 0.4,
`sapling-crypto` 0.5.0, `bls12_381` 0.8 and `redjubjub` 0.8. Sapling 0.5.0 provides
the required no_std surface at the repository's compiler version; current 0.7
requires Rust 1.85.1. The upstream Bellman verifier is not the no_std Wasm
backend: canonical checked Zcash encodings are converted into arkworks, with
the upstream public-input layout retained. The small yanked `core2` 0.3.3
dependency is vendored with its MIT/Apache licenses and original package files.

[Fixture provenance](../tools/zk-spec/fixtures/README.md) pins nine public Zebra
mainnet blocks at `2c3930dacd4ddfb4cf605a216d4bd20eda99725c`, the complete official
parameter-file hashes and extracted verification-key hashes. The parser
rederives all actions and ZIP-243 signature digests from the pinned block bytes.
There are 23 transactions, 42 distinct proofs and five complete 1-spend/2-output
bundles. No credentialed node supplies this corpus.

The native core also rejects every unchanged proof when paired with altered,
canonically encoded public inputs. This regression fails against a scratch
mutant that ignores the Groth16 verification result, establishing that proof
acceptance depends on the pairing equation. The production verifier is unchanged.

## What the measured call includes

Each timed `zk_bundle` call freshly decodes and prepares both verification keys,
decodes the framed bundle, checks all three Groth16 proofs, the spend
authorization signature and binding signature, appends both commitments to a
fresh depth-32 Sapling tree and computes its root. The input includes the
ZIP-243 transaction digest, as the upstream bundle-verification interface does.
Digest construction is checked separately against the real transaction bytes
and signatures. Timing excludes Wasm compilation/instantiation and JS dispatch
setup. It includes the synchronous JS-to-Wasm call and all bundle work above.

All five complete bundles pass. Binding-signature, signature-digest and truncated
encoding mutations fail. Each host times 20 calls, cycling through those five
bundles. These are standalone Node/V8 Wasm observations, not production pallet,
transaction-pool or ledger tests. A fresh tree is not a historical chain-state
validation. The full 100-bundle run on reviewed slowest hardware remains P3.

Both hosts use Node v24.15.0 / V8 13.6.233.17-node.48 and the same zero-import
Wasm SHA-256:
`104a771dad24c58ec7071b898e37d8e4a57aa410db8c055ac3ac2898a0b5509b`.
The MacBook's task-local official Node archive was SHA-256 checked before use.
The benchmark runs under `nice -n 10`; Gemtek also hosts live services, so these
are wall-clock observations on the shared host, not isolated CPU guarantees.

| Host / captured run | Hardware | Minimum ms | Mean ms | Maximum ms | Threshold verdict |
|---|---|---:|---:|---:|---|
| Gemtek, initial complete-call run | AMD Ryzen 7 7730U, x64, 16 logical CPUs, Linux 6.17.0-22-generic | 301.787740 | 500.543465 | 724.832242 | fallback A |
| Gemtek, initial `--full` run | Same host and Wasm | 87.560806 | 137.237940 | 254.628751 | GO with caps |
| Gemtek, initial `--all` run | Same host and Wasm | 96.572487 | 122.329436 | 181.889634 | GO with caps |
| Gemtek, final `--full` run | Same host and Wasm | 77.562076 | 80.373344 | 92.768490 | GO |
| Gemtek, final `--all` run | Same host and Wasm | 78.243863 | 81.293242 | 94.260248 | GO |
| MacBook | Apple M4 Pro, arm64, 14 logical CPUs, Darwin 25.5.0 | 44.211625 | 44.344819 | 44.542417 | GO |

Raw captures retain all 20 samples: [Gemtek](native-zk-evidence/p0-gemtek-cold.json)
and [MacBook](native-zk-evidence/p0-macbook.json). The
[`--full` capture](native-zk-evidence/p0-full.json) also records all 42 accepted
proofs, all 64,512 rejected single-bit mutations, compiler/engine identities and
source/artifact hashes. The MacBook was reachable at its
updated LAN address with its existing pinned SSH host key. Node-2 was untouched;
Node-3 was not benchmarked.

The [initial all-phase capture](native-zk-evidence/p0-all-initial.json) and
[final full capture](native-zk-evidence/p0-full-final.json) and
[final all-phase capture](native-zk-evidence/p0-all-final.json) retain the repeated
measurements. Both final runs include the hardened fresh-build no-egress check
in their accompanying harness logs.

The decision uses the slowest observed complete-call maximum: **fallback A**.
The locked thresholds are <=150 ms GO, >150 through 400 ms GO with caps, and
>400 ms fallback A. Earlier measurements that reused prepared keys are excluded
from the decision because they omitted work included in this conservative call.
Faster repetitions do not erase the recorded 724.832242 ms observation.

## P0 boundary and replay

`tools/zk-spec/setup.sh` prepares pinned tools/artifacts, then
`nice -n 10 scripts/harness.sh --full` runs the lock, 45 adapter/selector/tool
tests and the six P0 checks. `nice -n 10 scripts/harness.sh --all` also executes
the 13 original checks, preserving their honest later-phase RED results.
The driver refuses unknown operations and missing artifacts.

The no-egress check creates a new kernel network namespace, drops back to the
calling user, demonstrates failed direct-IP/SRS/Midnight probes and no routes,
then builds/tests the actual core offline in a fresh temporary target directory.
Cargo's compiler-artifact events must identify freshly compiled packages and
existing output files, including the core itself; cached artifacts cannot
satisfy this assertion. It never alters host networking.
The Midnight negative control injects an explicit local dependency named
`midnight-negative-control` and requires the dependency-exclusion gate to reject
that name. A separate regression covers a generic crate name whose source URL
identifies Midnight. This is an exclusion-gate test, not a Midnight integration.

Mainnet targets are derived from the production source's chain-spec dispatch.
There is no named mainnet builder: mainnet specifications use the generic
JSON-file route, in plain or raw form. The core refuses that route, including a
file claiming the preprod id; named preprod is a positive control. Two compiled
policy mutants must fail the refusal tests. P0 does not claim runtime activation
enforcement or the nonempty pallet/activation-path cross product required by P5.

The explicit pre-AJ metadata identity is source commit
`52829ca46323cf22b3e0feece3adc33cb4edb095`, with all 160 tracked runtime/node
workspace source files unchanged. Actual rebuilt runtime SHA-256 is
`9e5d67c22557ae11c75ec536132793f9f550525a93fe56a0b468c1aeafbbefea`;
the full extracted baseline metadata SHA-256 is
`3825a07b94e827c62b9c4bf210315b602c67012d3d75614d50ba1b1dccba0981`.
The gate compares 24 pallets and signed extensions and rejects six structural
mutants. This is compatibility with an explicitly identified unchanged build,
not an approved launch baseline. AJ's #66 fix and post-fix review remain required.

The Rust/Aiken bridge codec runs two round-trips and seven rejection cases in
both implementations, including reserved and unknown variants. The Aiken
evaluator reports real execution units for all nine passing assertions.

## Phase report

The [full log](native-zk-evidence/full-final.log) and
[all-phase log](native-zk-evidence/all-final.log) retain the assertions and
failure reasons. `--all` exits 1 because later-phase obligations are RED.
`NOT RUN` means the phase is beyond CURRENT_PHASE=P0, not a waived obligation.

| Check | P0 `--full` | `--all` |
|---|---|---|
| c-p0-core-no-egress | GREEN | GREEN |
| c-p0-midnight-negative-control | GREEN | GREEN |
| c-p0-mainnet-refusal | GREEN | GREEN |
| c-p0-metadata-compat | GREEN | GREEN |
| c-p0-bridge-codec | GREEN | GREEN |
| c-p0-sapling-spike | GREEN | GREEN |
| c-mainnet-isolation | NOT RUN (P1) | RED |
| c-sapling-wasm | NOT RUN (P3) | RED |
| c-supply-invariant | NOT RUN (P3) | RED |
| c-midnight-blackhole | NOT RUN (P3) | RED |
| c-metadata-append-only | NOT RUN (P1) | RED |
| c-bridge-datum | NOT RUN (P1) | RED |
| c-motra-66 | NOT RUN (P1) | RED |
| c-hub-other-chains | NOT RUN (P1) | RED |
| c-fees | NOT RUN (P2) | RED |
| c-hybrid-utxo | NOT RUN (P3) | RED |
| c-shielded-e2e | NOT RUN (P3) | RED |
| c-host-coverage | NOT RUN (P4) | RED |
| c-activation-gates | NOT RUN (P5) | RED |

Twelve later checks fail because their production paths and artifacts do not
exist in P0. `c-motra-66` fails because all eight required AJ regression tests
are absent; [AJ's PR #68](https://github.com/Flux-Point-Studios/materios/pull/68)
was open at capture time. A post-AJ launch baseline and the original P1-P5
runtime/evidence obligations are required to turn these checks GREEN.

## Test-first record

Captured logs include [core API RED](native-zk-evidence/core-api-red.log),
[core GREEN](native-zk-evidence/core-green.log),
[fresh-build RED](native-zk-evidence/cold-build-red.log),
[fresh-build GREEN](native-zk-evidence/cold-build-green.log),
[45-test suite](native-zk-evidence/unit-suite.log), and
[Aiken evaluator observations](native-zk-evidence/aiken-green.json).
The [pairing-result bypass RED](native-zk-evidence/pairing-mutant-red.log),
[real verifier GREEN](native-zk-evidence/pairing-green.log), and
[fresh no-egress rerun](native-zk-evidence/pairing-no-egress.log) capture the
additional public-input regression. Its mutant is an isolated copy in the
task scratch directory; construction uses the one-off scratch-script exception.

| Command / behavior | Observed RED | Observed GREEN |
|---|---|---|
| `nice -n 10 python3 tools/zk-spec/test_phases.py` | missing phase-selector implementation, five errors | five tests |
| `nice -n 10 rustc +1.85.0 --edition=2021 --test .zk-spec-scratch/red/api.rs --extern materios_zk_core=.zk-spec-scratch/red/libmaterios_zk_core.rlib` | unresolved activation, bridge and Sapling APIs against the initial empty core | real Cargo integration suite below exercises all three APIs |
| `nice -n 10 rustc +1.85.0 --test .zk-spec-scratch/red/activation.rs -o .zk-spec-scratch/red/activation` followed by `.zk-spec-scratch/red/activation` | named-preprod positive control failed | both policy controls passed |
| `nice -n 10 cargo +1.85.0 test --offline --locked --manifest-path tools/zk-spec/core/Cargo.toml` | APIs and activation behavior demonstrated RED above | three integration tests: real proofs/bundles, codec and activation |
| `nice -n 10 aiken check --deny tools/zk-spec/aiken` | unknown `encode` implementation | nine evaluator tests |
| `nice -n 10 python3 tools/zk-spec/test_vectors.py` | missing parser, then insufficient eleven-proof corpus; missing provenance verifier | four tests, 42-proof corpus |
| `nice -n 10 python3 tools/zk-spec/test_p0_tools.py` | missing helpers; Midnight source-URL mutation was initially accepted | five tests |
| `nice -n 10 python3 tools/zk-spec/test_evidence.py` | missing capture validator | three tests; stale Wasm hash rejected |
| `nice -n 10 python3 tools/zk-spec/check.py c-p0-bridge-codec` | unregistered check rejected by the adapter | real Rust/Aiken operation |
| `nice -n 10 python3 tools/zk-spec/check.py c-p0-core-no-egress` | `KeyError: compiled_packages` when fresh-compilation evidence was required | fresh namespace-isolated compilation plus the actual core tests |
| `nice -n 10 cargo +1.85.0 test --offline --manifest-path .zk-spec-scratch/pairing-mutant/core/Cargo.toml --test core public_mainnet_proofs_and_complete_bundles -- --exact` | the mutant accepts a changed public input and fails the new assertion | the unmodified verifier rejects all 42 altered statements; the complete core suite passes |

The core API RED used a scratch-only empty crate while the serialized runtime
build occupied Cargo; it was not a synthetic positive result. The later Cargo
suite tests the actual implementation and pinned public corpus. The initial
download-only scratch script used the explicitly stated one-off TDD exception.

Additional checks are Rust formatting, core/driver Clippy with `-D warnings`,
all 45 Python tests, fixture provenance reconstruction, no_std wasm32 release
build and exhaustive mutations in the Wasm engine. Hosted CI repeats primitive
tests and exhaustive proof verification without timing service hosts; the
existing Rust workflow also checks metadata from its own rebuilt runtime.

The first hosted ZK job exposed a clean-image setup failure: Rust's container
did not include `cargo-fmt`. The CI script now explicitly installs `rustfmt`
and Clippy for 1.85.0. The [hosted RED](native-zk-evidence/ci-components-red.log)
precedes the fix; the [clean-image GREEN](native-zk-evidence/ci-components-green.log)
replays the workflow commands in `rust:1.85.0-bookworm`, with an isolated clone,
fresh target and two CPUs at low priority. It passes the three core tests,
45 helper tests, policy/dependency/codec gates, native and Wasm Clippy, and
42 proofs plus all 64,512 mutations. The rebuilt Wasm hash is identical to the
measured artifact; the CI replay records zero timing samples.

The next hosted run exposed the clone's missing original spec commit.
[Woodpecker's clone plugin](https://github.com/woodpecker-ci/plugin-git/blob/main/docs.md)
supports partial/shallow history. CI now fetches the exact `5460448` baseline
commit only when absent, retaining the unchanged-obligation regression.
A depth-one clone [reproduces RED](native-zk-evidence/ci-shallow-red.log);
the complete workflow [passes in that clean shallow clone](native-zk-evidence/ci-shallow-green.log),
including all 45 tests, all proof mutations and the identical Wasm hash.

The existing partnerchain `fmt` step is advisory and has pre-existing failures
in 56 files, tracked by [LOW #67](https://github.com/Flux-Point-Studios/materios/issues/67).
P0 leaves those source files and that CI policy unchanged. Formatting and Clippy
for the new tools workspace pass. No new LOW issue was filed for the same debt.

All authority holds remain DENY. There is no merge, deployment, mainnet action,
external commitment or production activation in this P0.
