# Native ZK and hybrid MATRA specification

SPEC: .fluxpoint-spec.json

Repo: Flux-Point-Studios/materios. Branch: `spec/native-zk-hybrid`.
Base: `52829ca46323cf22b3e0feece3adc33cb4edb095`.

This task delivers the FluxPoint grill packet and intentional RED acceptance
scaffolds. It changes no production runtime code. The requested local commit is
not approval to push, open a PR, deploy, engage a vendor or operate mainnet.

Read [the research and reuse record](docs/native-zk-research.md),
[the driver contract](tools/zk-spec/README.md), the packet and its challenges.
The canonical ids are lowercase `d-*`, `r-*`, `c-*`, as the installed validator
requires; `D-arch` in the brief corresponds to `d-arch` here.

## Verification boundary

The adapter's own tests must be GREEN. The feature checks are expected RED until
the actual runtime driver, pinned fixtures, reviewed launch baseline and AJ #66
tests exist in this checkout. The packet's assertions are not a deployed feature.
Do not satisfy them with a mocked driver, a second ledger model or stored
success counters. Full implementation requires real-runtime evidence and
independent review, including the underlying driver and each fixture's origin.

Use the installed FluxPoint 1.42.0 runner. `py.sh` prepends its scripts directory,
so pass `specification.py` rather than the absolute script pathname in the brief:

```sh
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --lock
bash /home/deci/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0/scripts/py.sh specification.py --check
```

`scripts/harness.sh --full` includes the current template's specification runner
and will execute acceptance checks. It must NOT be run during this spec pass;
the brief explicitly prohibits `specification.py --run`. The lock/check commands
validate the document only and do not imply feature readiness or authorization.

## Initial blockers

- The installed validator accepts only `defaulted` and `user-confirmed` during
  lock/check; this brief requires literal `blocked` on four authority decisions.
  Keep those statuses pending the user's answer to the explicit clarification.
  Never invent a digest, patch the plugin, or pretend approval was received.
- AJ owns #66. Its eight tests are referenced but absent at this base revision.
  They and the reviewed fix must land before the approved genesis baseline.
- No runtime driver, Sapling corpus/benchmark, approved launch artifacts,
  candidate metadata, cross-language codec or live soak evidence is supplied.
- Counsel/audit bookings, budget/commitments and all mainnet actions need deci's
  explicit authorization plus the concrete evidence described in the packet.

The next engineering slice after resolving lock semantics is the narrow hub
consumer plus the Sapling spike and real driver, each developed test-first.
Launch review and execution retain priority over ZK preprod windows.
