# Reused sources

- `core2`: unmodified crate sources for crates.io core2 0.3.3 (MIT/Apache-2.0),
  required by sapling-crypto 0.5.0. The release is yanked, so it is vendored rather
  than silently replacing upstream I/O traits. Its licenses and crate manifest
  are included. Sapling 0.7 requires rustc 1.85.1; this repository
  pins 1.85.0. This is a P0 compatibility choice, not an ongoing maintenance plan.
- `metadata-gate/ceremony_metadata_gate.py`: exact existing #494 gate from
  `/home/deci/work/mainnet-resilience-494-ceremony-gate`, commit
  `17b8f4fbd5b2cefa33f0ca49f625ccbfd5c7b662`. It has no configured upstream remote.
  P0 uses its structural metadata reduction/diff and refusal functions for
  unchanged-runtime compatibility. Its full upgrade CLI correctly demands a
  strictly increasing spec version and therefore is not an unchanged-build test.
  Mainnet upgrade/ceremony authority remains outside this task.
