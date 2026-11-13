# pallet-tee-attestation

> Wave 3 / Phase 2 — ARM TrustZone evidence type via vendored Acurast verifier.

Materios's per-receipt TEE attestation primitive. Receipts can carry off-chain
evidence (TEE reports, key-attestation chains, build co-signatures, ZK proofs);
this pallet verifies the evidence on chain and exposes a composite trust score
that pricing, dispute, and customer-tier filters can act on.

## Status

- ✅ `EvidenceType::ArmTrustZone` — Android Hardware Key Attestation, via the
  vendored Acurast verifier (`vendor/acurast-attestation/`), bound to one
  receipt on one chain (see below).
- ⏳ `EvidenceType::AmdSevSnp` — Phase 3.1.
- ⏳ `EvidenceType::IntelTdx` — Phase 3.2.
- ⏳ `EvidenceType::ReproducibleBuild` — Phase 3.3.
- ⏳ `EvidenceType::ZkVmExecution` — Phase 4.

The four ⏳ variants have typed dispatch wired in; their verifiers return
`VerifyFailReason::NotImplemented`. Phase ordering matters: see
`feedback_pallet_index_shift.md` — discriminants are append-only.

`Disabled` is `true` at genesis; Root releases it with `set_disabled`.

## Receipt binding (ArmTrustZone)

`submit_evidence(receipt_id, content_hash, entry)` accepts an Android
key-attestation chain only when:

1. The signer is the receipt's submitter or a member of the receipt
   committee (`OrinqReceipts::CommitteeMembers`; the cert-daemon's evidence
   submitter signs with its committee key), else `UnauthorizedSubmitter`.
   `content_hash` is the content hash `OrinqReceipts` holds for
   `receipt_id` (`UnknownReceipt`, `ContentHashMismatch`). The receipt holds
   at most one entry per evidence type: a repeat of the recorded leaf key is
   `DuplicateEvidence`, another key `EvidenceTypeFull`. These checks read
   storage and the leaf's public key only, and run before any signature is
   verified.
2. The chain starts at one of Google's two attestation root keys
   (`GOOGLE_ATTESTATION_ROOTS`: the RSA root and the P-384 root that signs
   from February 2026) and every link signature verifies.
3. No certificate but the leaf carries the key-attestation extension
   (OID 1.3.6.1.4.1.11129.2.1.17). An attested key that signs a further
   certificate can write any challenge and security level into it; Google's
   reference verifier rejects the same shape
   (`CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION`).
4. The leaf's key lives in TEE (1) or StrongBox (2).
5. The leaf's `attestationChallenge` is

   ```
   SHA-256("materios/tee-attestation/arm-trustzone-challenge/v1"
           ‖ genesis_hash ‖ receipt_id ‖ content_hash)
   ```

   with `genesis_hash` this chain's block-0 hash (`System::BlockHash(0)`)
   and each hash as its 32 raw bytes (`verifier::arm_trustzone_challenge`).

Why this derivation: receipt submitters choose both `receipt_id` and
`content_hash`, and several receipts may share a content hash. If the
challenge were the raw content hash, any published Google-rooted chain with
a 32-byte challenge would become evidence for a receipt submitted with that
content hash. The Seeker chain in `src/test_vectors.rs` is such a chain
(`public_chain_cannot_be_bound_by_choosing_content_hash_equal_to_its_challenge`).
The domain tag leaves a challenge minted for any other protocol useless here,
the receipt id keeps evidence off other receipts with the same content, and
the genesis hash keeps it off other networks.

What a device must do per receipt: mint a fresh key in KeyMint with
`setAttestationChallenge` set to that receipt's challenge, and submit the
key's certificate chain root first (the reverse of
`KeyStore.getCertificateChain`). A key minted once with a fixed challenge
verifies for no receipt.

The KeyDescription versions the vendored parser accepts are 1, 2, 3, 4, 100,
200 and 300; each carries `attestationChallenge` as a mandatory OCTET STRING.
KeyMint 4.0 and later (400, 500) leaves are refused.

Known answers for device and gateway code
(`challenge_derivation_known_answers`): the preimage is the 51-byte ASCII
tag followed by the three 32-byte hashes, 147 bytes.

| genesis_hash | receipt_id | content_hash | challenge |
|---|---|---|---|
| `00 01 … 1f` | `20 21 … 3f` | `40 41 … 5f` | `2e557791bc4dc9f1730a2f2eb512df68a10426605113e2a3ca392a8e27336299` |
| `11` × 32 | `22` × 32 | `33` × 32 | `210ef46d5f5c5da4d5f09f3ad2d2f63599680d6a019072d6f81cc780e935d344` |

## Weight

`submit_evidence` is priced at its Wasm worst case, measured with
`frame-omni-bencher` (`src/benchmarking.rs`, samples in `benchmarking/`,
method and figures in `src/weights.rs`): five P-384 signature checks, the
largest a five-certificate chain can demand, sampled up to 63.5 ms. The
weight declares 64 ms, a 4,096-byte proof, five reads and two writes. The
Seeker RKP chain costs 20 ms; Google's RSA root repeated five times, 17 ms.

## Upgrade from storage version 0

Evidence recorded before receipt binding is bound to nothing: that verifier
accepted any Google-rooted chain for any receipt. Storage version 1 holds
only bound evidence, and `migrations::ClearUnboundEvidence`, in the runtime's
migration list, clears `VerifiedEntries` and `CompositeTrustScores` once on
the upgrade from version 0. A chain built from genesis starts at version 1.

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
3. `validate_certificate_chain` takes its trust anchors from the caller. The
   pallet passes Google's attestation roots only; upstream also trusts
   Apple's App Attestation root.

## Determinism

Every committee member's verifier MUST produce identical bytes. Per
`feedback_mofn_hash_determinism.md` we:
- Pin trust roots via `include_bytes!` (Google RSA, Google P-384).
- Make zero network calls from the verify path.
- Skip wall-clock validity checks on certificates.
- Read the receipt binding from chain state only: the receipt registry and
  `System::BlockHash(0)`.
- Hash leaf SubjectPublicKeyInfo bytes (canonical DER) for the chip-ID.

## Tests

- `tests::compose::*` — composer logic, hand-rolled cases.
- `tests::reference_vectors::*` — real chains from Acurast's test suite
  (Pixel StrongBox, Samsung TEE, Seeker RKP StrongBox): every check accepts
  them except the receipt binding, and the parser reads their challenge and
  security level.
- `tests::tampering::*` — a swapped signature byte or an untrusted root fails
  with `ChainOfTrustBroken`.
- `tests::challenge_binding::*` — real chains replayed against a receipt, a
  public 32-byte challenge used as a content hash, every single-bit flip of
  the content hash, receipt id and genesis hash, empty and missing
  challenges, and every accepted KeyDescription version.
- `tests::chain_shape::*` — the root set, an Apple-anchored chain, and a
  chain extended past an attested key.
- `tests::chain_depth::*` — attested keys extended at realistic depths,
  the chain-length bound and repeated roots.
- `tests::pallet::*` — `submit_evidence` on a mock runtime: authorization,
  receipt lookup, cross-receipt and cross-network replay, the genesis hash
  past the block-hash horizon, one entry per type, duplicates, and the
  checks that run before verification.
- `tests::migration::*` — the upgrade clears the storage the pre-binding
  verifier wrote, once.
- `benchmarking::bench_submit_evidence` (`--features runtime-benchmarks`) —
  the worst-case chains reach the last signature check.

Positive cases run on synthetic chains under a test root
(`src/synthetic_chain.rs`); `submit_evidence` itself trusts Google's roots
only (`submit_evidence_trusts_only_googles_roots`).

Run: `cargo test -p pallet-tee-attestation`.
