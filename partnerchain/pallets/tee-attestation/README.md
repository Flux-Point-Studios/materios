# pallet-tee-attestation

> Wave 3 / Phase 2 — ARM TrustZone evidence type via vendored Acurast verifier.

Materios's per-receipt TEE attestation primitive. Receipts can carry off-chain
evidence (TEE reports, key-attestation chains, build co-signatures, ZK proofs);
this pallet verifies the evidence on chain and exposes a composite trust score
that pricing, dispute, and customer-tier filters can act on.

## Status (2026-05-06)

- ✅ `EvidenceType::ArmTrustZone` — Android Hardware Key Attestation, via the
  vendored Acurast verifier (`vendor/acurast-attestation/`).
- ⏳ `EvidenceType::AmdSevSnp` — Phase 3.1.
- ⏳ `EvidenceType::IntelTdx` — Phase 3.2.
- ⏳ `EvidenceType::ReproducibleBuild` — Phase 3.3.
- ⏳ `EvidenceType::ZkVmExecution` — Phase 4.

The four ⏳ variants have typed dispatch wired in; their verifiers return
`VerifyFailReason::NotImplemented`. Phase ordering matters: see
`feedback_pallet_index_shift.md` — discriminants are append-only.

## What's NOT in this PR

- Wiring into `construct_runtime!` — separate PR. Intentionally decoupled so
  the verifier can land + be reviewed independently.
- Cert-daemon integration (the off-chain submitter that pulls evidence from
  the gateway manifest store and calls `submit_evidence`) — separate PR,
  Phase 2.5.
- AMD / Intel / Build / ZK verifiers — Phases 3.x and 4.

## Vendored Acurast verifier

The on-chain ARM Key Attestation verification uses Acurast's `no_std` Rust
implementation, vendored under `vendor/acurast-attestation/`. See that
directory's README for the exact upstream commit, license, and patch policy.

Adapter changes (search for `[materios-patch]` in vendored files):
1. P-384 public key parsing now uses upstream `p384 = 0.13` from crates.io
   instead of Acurast's `expose-field`-flavoured fork (which would have meant
   vendoring ~40 000 LOC of crypto code).
2. `BoundedKeyDescription`-converting `try_into()` calls were dropped — the
   Materios pallet stores the security-level integer + chip-ID hash directly
   instead of the Acurast-pallet-flavoured rich storage object.

## Determinism

Every committee member's verifier MUST produce identical bytes. Per
`feedback_mofn_hash_determinism.md` we:
- Pin trust roots via `include_bytes!` (Google RSA, Google P-384, Apple).
- Make zero network calls from the verify path.
- Skip wall-clock validity checks on certificates.
- Hash leaf SubjectPublicKeyInfo bytes (canonical DER) for the chip-ID.

## Tests

- `tests::compose::*` — composer logic, hand-rolled cases.
- `tests::reference_vectors::*` — Acurast's reference attestation chains
  (Pixel StrongBox + Samsung TEE), reused directly. These are the
  `test_validate_pixel_devices` / `test_validate_samsung_chain` chains from
  upstream.
- `tests::tampering::*` — confirms a chain with a swapped signature byte
  fails with `ChainOfTrustBroken`.
- `tests::pallet::*` — `submit_evidence` extrinsic round-trip.

Run: `cargo test -p pallet-tee-attestation`.
