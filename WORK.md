# Native ZK P0

SPEC: .fluxpoint-spec.json
CURRENT_PHASE: P0

Repo: Flux-Point-Studios/materios. Branch: `impl/native-zk-p0`.
Original specification: `5460448`; unchanged runtime source baseline: `52829ca46323cf22b3e0feece3adc33cb4edb095`.

AK4 scopes P0 CI and harness phase selection to ZK/spec work, with signed commits
and branch pushes. PR #69 stays Ready for review. No merge, deployment, spend,
external commitment or mainnet action is authorized. The materios CTO reviews
the pushed implementation.

`scripts/harness.sh --full` always checks the lock and tools/zk-spec unit suites.
It runs checks through CURRENT_PHASE only for ZK/spec changes against
FPL_DIFF_BASE, or the merge-base with origin/main when unset or empty.
`--all` executes every phase regardless of changed paths, continues
after failures and prints every result. Missing artifacts and unimplemented
operations fail. Later-phase RED checks are obligations, not waived tests.

See [the revision record](docs/native-zk-revisions.md),
[research](docs/native-zk-research.md) and [driver contract](tools/zk-spec/README.md).
AJ owns #66; its tests and reviewed fix are required before genesis. P0's explicit
pre-AJ compatibility baseline does not establish launch readiness.

Run heavy work serially under `nice -n 10` with two Cargo jobs and
`CARGO_TARGET_DIR=/home/deci/work/wt-materios-zk-p0/.zk-spec-target`.

## Progress

- Phase selector: test-first RED (missing implementation), then GREEN.
- Real Rust driver, standalone no_std Sapling verifier and Rust/Aiken codec implemented.
- `--full`: all six P0 checks GREEN; 58 Python tests and three core integration tests GREEN.
- CI path tests: 12 RED assertions to 10 GREEN tests. Harness selection: six RED
  assertions to 13 GREEN tests. The required Rust workflow has no P0 baseline
  gate; ZK/spec changes select the independent runtime metadata step.
- [Issue #70](https://github.com/Flux-Point-Studios/materios/issues/70) tracks
  the reviewed post-AJ baseline after #68 merges.
- Wasm: 42 genuine proofs accepted, all 64,512 single-bit mutations rejected.
- Complete-bundle measurements recorded on Gemtek and the M4 Pro MacBook.
  Worst observed Gemtek call: 724.832242 ms, requiring fallback A. See
  [P0 evidence](docs/native-zk-p0.md). P3's 100-bundle obligation remains open.
- `--all`: six P0 GREEN checks; all 13 original later-phase checks RED with
  missing implementation/evidence reasons. `c-motra-66` names AJ's missing tests.
- Ready for review [PR #69](https://github.com/Flux-Point-Studios/materios/pull/69) tracks
  hosted CI. Independent materios CTO review is required before further action.

## Lock commands

```sh
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --lock
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --check
```
