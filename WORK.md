# Native ZK P0

SPEC: .fluxpoint-spec.json
CURRENT_PHASE: P0

Repo: Flux-Point-Studios/materios. Branch: `impl/native-zk-p0`.
Original specification: `5460448`; unchanged runtime source baseline: `52829ca46323cf22b3e0feece3adc33cb4edb095`.

AK2 authorizes a phase-aware revision, P0 implementation, signed commits, branch
pushes and a draft PR. No merge, deployment, spend, external commitment or mainnet
action is authorized. The materios CTO reviews the pushed implementation.

`scripts/harness.sh --full` checks the lock, adapter and phase-selector suites,
then every check through CURRENT_PHASE. `--all` executes every phase, continues
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
- `--full`: all six P0 checks GREEN; 45 Python tests and three core integration tests GREEN.
- Wasm: 42 genuine proofs accepted, all 64,512 single-bit mutations rejected.
- Complete-bundle measurements recorded on Gemtek and the M4 Pro MacBook.
  Worst observed Gemtek call: 724.832242 ms, requiring fallback A. See
  [P0 evidence](docs/native-zk-p0.md). P3's 100-bundle obligation remains open.
- `--all`: six P0 GREEN checks; all 13 original later-phase checks RED with
  missing implementation/evidence reasons. `c-motra-66` names AJ's missing tests.
- Draft [PR #69](https://github.com/Flux-Point-Studios/materios/pull/69) tracks
  hosted CI. Independent materios CTO review is required before further action.

## Lock commands

```sh
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --lock
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --check
```
