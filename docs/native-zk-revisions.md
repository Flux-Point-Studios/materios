# Native ZK phase revision (AK2)

The CTO's AK2 handoff authorizes this revision of the locked `5460448` packet.
P0 cannot honestly demonstrate value-bearing pallets that do not yet exist.
The packet therefore distinguishes P0 evidence from the end-state acceptance
obligations. **No end-state obligation was weakened.** Original requirements,
check commands, assumptions and assertions are unchanged; the only change to an
original check is a `Phase Pn.` prefix in its scope. The regression suite compares
them and `contracts.py` byte for byte to `5460448`.

The existing strict FluxPoint schema has no phase field. The scope prefix is
the machine-readable phase tag. WORK.md declares CURRENT_PHASE. `--full` checks
the specification lock and adapter/selector suites, then phases <= CURRENT_PHASE;
`--all` executes all checks without stopping at the first RED and lists results.
Unknown phases and missing phase declarations refuse execution.

| Phase | Existing checks discharged | Obligations retained |
|---|---|---|
| P1: first hub and bridge integration | c-mainnet-isolation, c-metadata-append-only, c-bridge-datum, c-motra-66, c-hub-other-chains | Reviewed post-AJ launch artifacts; positive preprod capability; positive pallet append and migrations; production Rust+Aiken evaluation; real other-chain consumer and dual-chain confirmation |
| P2: fee/admission integration | c-fees | Pricing, sponsorship and 10,000 malformed admissions |
| P3: complete hybrid/shielded lanes | c-sapling-wasm, c-supply-invariant, c-midnight-blackhole, c-hybrid-utxo, c-shielded-e2e | Full Sapling production path and 100 bundles on reviewed slowest hardware; all four nonempty blackhole scenarios; supply, wallet and soak obligations |
| P4: optional host math rollout | c-host-coverage | Architecture differential checks and full-role coverage |
| P5: end-state activation refusal | c-activation-gates | Nonempty source-derived ZK-pallet/spec cross product; every activation path and all four DENY holds; zero broadcasts |

Six separate P0 checks cover the actual core build with no egress, an injected
Midnight dependency negative control, source-derived mainnet-target refusal and
mutants, unchanged runtime metadata against an explicit pre-AJ identity plus
gate mutants, standalone Rust/Aiken codec execution, and measured Sapling Wasm
verification with public mainnet vectors and exhaustive one-bit mutations.
The P0 bundle measurement uses Gemtek and the reachable arm64 MacBook as a proxy;
it does not claim the reviewed slowest-hardware/100-bundle obligation.

The original lock was
`bc6897c50f6f94b742ed95b9c79980d3d8c0ef6525b97282ab73899fb4e85924`.
The replacement lock is recorded by the canonical runner's lock file.
All authority holds remain DENY. No launch approval or runtime activation follows
from the lock, a P0 GREEN report, or an offline refusal test.
