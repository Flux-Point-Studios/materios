# Vendored Acurast attestation verifier

**Vendored from:** https://github.com/Acurast/acurast-substrate
**Commit SHA:** `d205a7d37d119e6c25269d5141eb16ecd36eaf22`
**Vendored on:** 2026-05-06
**Source path in upstream:** `pallets/acurast/common/src/attestation.rs` (+ `attestation/asn.rs`, `attestation/error.rs`, `__root_key__/*.key`)
**Upstream license:** Unlicense (top-level repo) / MIT (declared in `pallets/acurast/common/Cargo.toml`)
**Local license file:** `LICENSE` in this directory.

## Why is this vendored?

The Acurast org ships a `no_std`-compatible Rust verifier for Android Key Attestation
(plus Apple Secure Enclave) cert chains. We use it as the on-chain primitive for
ARM TrustZone evidence in `pallet-tee-attestation`. Vendoring (rather than git-pinning
the upstream crate) is forced by two pragmatic constraints:

1. The upstream `acurast-common` crate pulls in the entire Acurast pallet trait /
   `BoundedKeyDescription` storage type apparatus, which we don't need and which
   pins to `polkadot-v1.18.5` while Materios pins to `polkadot-stable2409-4`.
2. The upstream crate depends on Acurast's own forks of `p256`, `p384`, `ecdsa`,
   and `elliptic-curve` (collectively ~40 000 LOC under
   `pallets/acurast/p384/`), parameterised with `expose-field` so that
   `p384::AffinePoint` can be constructed from raw x/y bytes. We did not want
   to vendor 40 000 LOC of crypto code into Materios; instead the verifier here
   uses the upstream `p384 = 0.13` from crates.io (also MIT/Apache-2.0) and
   constructs P-384 public keys via SEC1 encoding — see `attestation.rs` `parse`
   helper.

## What's in this dir

| File | Source | Notes |
|---|---|---|
| `attestation.rs` | upstream `attestation.rs` | Adapted: drop `BoundedKeyDescription` import (Materios-side type lives in `pallet-tee-attestation::types`); switch P-384 public-key parsing from `AffinePoint{x,y}` direct to `p256::PublicKey::from_sec1_bytes`-style upstream API; drop the `tests` module (replaced by `tests.rs` in pallet root). |
| `asn.rs` | upstream `attestation/asn.rs` | Verbatim. Pure ASN.1 type definitions — no patches. |
| `error.rs` | upstream `attestation/error.rs` | Adapted: drop `From<p384::elliptic_curve::Error>` impl — replaced by `ParseP384PublicKey` direct construction at the call site. |
| `__root_key__/google-public.key` | upstream | Verbatim. RSA-2048, Google Hardware Key Attestation root. |
| `__root_key__/google-p384-public.key` | upstream | Verbatim. ECDSA P-384, Google Hardware Key Attestation root (newer chips). |
| `__root_key__/apple-public.key` | upstream | Verbatim. ECDSA P-256, Apple Device Attestation root. (Not used in Phase 2 — Phase 4 hook.) |
| `LICENSE` | upstream `LICENSE` | Verbatim. Unlicense (public domain). |

## Patch policy

We do NOT edit the verifier in place. Patches are applied via the `attestation.rs`
header comment block (search for `[materios-patch]`). Re-vendoring procedure:

1. Bump the commit SHA in this README.
2. `git diff` upstream's `attestation.rs` against ours; reapply the materios-patch
   blocks marked at the top of the file.
3. Run `cargo test -p pallet-tee-attestation` — must stay green.

## Divergence from upstream — P-384 SEC1 parsing

Upstream Acurast and Materios reach the same answer ("verify a P-384
ECDSA cert chain") via different APIs because Materios drops Acurast's
vendored `p384` fork (~40 000 LOC, parameterised with `expose-field` so
that `p384::AffinePoint` exposes its internal `x`/`y` field bytes
publicly) in favour of upstream `p384 = 0.13` from crates.io.

| | Upstream Acurast | Materios |
|---|---|---|
| P-384 public-key parse | `AffinePoint{x, y, infinity: false}` direct construction from raw 48-byte field elements (no curve-membership validation) | `p384::ecdsa::VerifyingKey::from_sec1_bytes(...)` — parses the SEC1-encoded uncompressed point and validates it's on the P-384 curve |
| Error code on garbage X/Y bytes | `ValidationError::InvalidSignature` (deferred — verification just produces a wrong sig comparison and fails) | `ValidationError::ParseP384PublicKey` (rejected at parse time — point isn't on the curve) |
| Where rejection happens | Late, inside the signature verification step | Early, during cert parse |
| Verifier output for malformed inputs | Reject | Reject |
| Verifier output for well-formed inputs | Accept | Accept |

Net behaviour for security is identical: malformed inputs are rejected
in both cases. The only observable difference is which `ValidationError`
variant the call site sees, and `pallet-tee-attestation` collapses both
into `VerifyFailReason::ChainOfTrustBroken` at the pallet boundary, so
the on-chain failure signal is identical too.

The Materios path is strictly safer in the abstract — a bogus
"public key" that's not on the curve cannot be constructed at all —
but the upstream Acurast path is not exploitable in practice because
the subsequent ECDSA `verify_prehash` over the same `VerifyingKey`
catches the same invalid input later. We prefer the strictly-safer
form because (a) it reduces the attack-surface argument we have to
make, and (b) it keeps the verifier reasoning local: "if `parse`
returns `Ok`, the key is on the curve" is a stronger postcondition
than the upstream's "if `parse` returns `Ok`, the bytes were 96 bytes
long".

See `attestation.rs` lines marked `[materios-patch]` for the exact
lines that switched.

## Why not relicense to MIT?

The upstream `LICENSE` is Unlicense (more permissive than MIT). The crate-level
declaration in `acurast-common/Cargo.toml` says MIT. We adopt MIT for the vendored
material per the crate-level declaration, since it's the more conservative choice
for onward distribution. This file documents the upstream divergence; the MIT text
itself is the standard MIT, included below for completeness:

> The MIT License (MIT)
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of
> this software and associated documentation files (the "Software"), to deal in
> the Software without restriction, including without limitation the rights to
> use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
> of the Software, and to permit persons to whom the Software is furnished to do
> so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
