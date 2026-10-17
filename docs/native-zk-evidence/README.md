# Actual verification evidence

Captured 2026-10-17T02:28:03.623332+00:00; base `52829ca46323cf22b3e0feece3adc33cb4edb095`.

These commands ran directly from the repository root. The specification runner's `--run` was never invoked.

Every acceptance check exited 1 for its expected missing implementation dependency. No semantic runtime obligation was checked, and no live feature evidence exists. Test-method counts are attempted scaffolds, not completed runtime cases.

| Check | Exit | Actual RED cause |
|---|---:|---|
| [c-mainnet-isolation](c-mainnet-isolation.log) | 1 | `runtime driver missing` |
| [c-sapling-wasm](c-sapling-wasm.log) | 1 | `runtime driver missing` |
| [c-supply-invariant](c-supply-invariant.log) | 1 | `runtime driver missing` |
| [c-midnight-blackhole](c-midnight-blackhole.log) | 1 | `runtime driver missing` |
| [c-metadata-append-only](c-metadata-append-only.log) | 1 | `runtime driver missing` |
| [c-bridge-datum](c-bridge-datum.log) | 1 | `runtime driver missing` |
| [c-motra-66](c-motra-66.log) | 1 | `AJ tests missing` |
| [c-hub-other-chains](c-hub-other-chains.log) | 1 | `runtime driver missing` |
| [c-fees](c-fees.log) | 1 | `runtime driver missing` |
| [c-hybrid-utxo](c-hybrid-utxo.log) | 1 | `runtime driver missing` |
| [c-shielded-e2e](c-shielded-e2e.log) | 1 | `runtime driver missing` |
| [c-host-coverage](c-host-coverage.log) | 1 | `runtime driver missing` |
| [c-activation-gates](c-activation-gates.log) | 1 | `runtime driver missing` |

All check commands have this exact form (substitute each id from the table):

```sh
nice -n 10 env CARGO_TARGET_DIR=.zk-spec-target python3 tools/zk-spec/check.py c-mainnet-isolation
```

The log for each check records its actual argv, exit and full output, with trailing whitespace removed. Cargo was not invoked: absent drivers and missing AJ tests were detected first.

Adapter TDD evidence:

1. Before `check.py` existed, the adapter unit script exited 1 with `ModuleNotFoundError: No module named 'check'`.
2. After implementation, 17 tests passed.
3. Added strict response tests: boolean version, duplicate keys and unknown status all failed with `AssertionError: CheckFailure not raised` (20 tests, 3 failures).
4. After response validation, all 20 tests passed, zero skipped; see [full GREEN output](adapter-green.log).

Exact portable-plugin unit command used for the RED/GREEN development loop:

```sh
nice -n 10 env CARGO_TARGET_DIR=/home/deci/work/wt-materios-zk-spec/.zk-spec-target bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh ../../../../../../../work/wt-materios-zk-spec/tools/zk-spec/test_adapter.py -v
```

The final evidence capture invokes the same Python test script directly under the interpreter selected by `py.sh`.

Initial wrapper probes with `py.sh -m`, a repo-relative path and the brief's absolute-path form exited 66 (`no such script`). Inspection showed that `py.sh` always prepends its scripts directory; the commands above use its required relative target.

Lock evidence is recorded separately in [lock-attempt.log](lock-attempt.log). A failed lock has no digest.
