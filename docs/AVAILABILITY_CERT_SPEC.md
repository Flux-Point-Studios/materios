# Availability Certificate Specification

**Version**: materios-availability-cert-v1
**Status**: Normative
**Last updated**: 2026-02-25

---

## 1. Overview

An **Availability Certificate** is a signed attestation that a storage provider has verified the availability and integrity of content referenced by a materios receipt. The certificate is encoded as **deterministic CBOR (dCBOR)** per RFC 8949 Section 4.2 and its SHA-256 hash is recorded on the Cardano blockchain.

This document specifies the encoding, message structure, verification levels, and on-chain hash computation for availability certificates.

---

## 2. Why dCBOR (RFC 8949 Section 4.2)

### 2.1 The Problem: Byte-Level Ambiguity

Standard CBOR permits multiple valid byte encodings for the same logical value. For example, the integer `1` can be encoded as a 1-byte, 2-byte, 3-byte, or 5-byte CBOR value — all are valid. Strings can use definite or indefinite length. Maps can have keys in any order. This flexibility is fatal for a system that derives on-chain hashes from the encoding:

- If two implementations encode the same certificate differently, they produce different SHA-256 hashes.
- If the on-chain hash does not match the locally computed hash, the certificate cannot be verified, even though the logical content is identical.
- A malicious actor could claim a valid certificate is invalid (or vice versa) by exploiting encoding ambiguity.

### 2.2 The Solution: Deterministic CBOR

RFC 8949 Section 4.2 ("Core Deterministic Encoding Requirements") eliminates this ambiguity by mandating:

| Requirement | What It Means |
|---|---|
| **Preferred integer encoding** | Use the shortest encoding that can represent the value. `0` is 1 byte, not 2 or 5. |
| **Preferred float encoding** | Use the shortest IEEE 754 encoding. If a value fits in float16 without precision loss, use float16. |
| **Definite-length only** | Arrays and maps MUST use definite-length encoding. Indefinite-length (streaming) forms are prohibited. |
| **Map key sorting** | Map keys are sorted first by encoded byte length (shorter first), then lexicographically by encoded bytes for keys of equal length. |
| **No duplicate map keys** | Each map key MUST appear exactly once. |
| **Preferred string encoding** | Strings use the shortest definite-length header. |

### 2.3 Why dCBOR Over Canonical JSON (RFC 8785)

The availability certificate is a Cardano-facing artifact. The choice of dCBOR over canonical JSON is deliberate:

- **Native to Cardano**: Cardano transactions, Plutus datums, and transaction metadata are all CBOR-encoded. Using dCBOR for certificates means a Plutus validator can decode and verify the certificate without a JSON parser — it simply decodes CBOR it already understands.
- **Binary-friendly hashing**: The certificate bytes are hashed directly. There is no parse-reserialize step that could introduce divergence.
- **Compact**: CBOR is more compact than JSON for structured data with numeric fields, reducing transaction metadata costs (which are priced per byte on Cardano).
- **Formal specification**: RFC 8949 Section 4.2 is a formal, IETF-reviewed specification with published test vectors, the same level of rigor as RFC 8785 for JSON.

Note: The receipt *content* itself uses RFC 8785 JCS canonicalization (see CANONICALIZATION.md). The availability certificate is a separate, higher-level artifact that wraps receipt references in a Cardano-native encoding.

---

## 3. Signed Message Structure

The availability certificate message is a **dCBOR-encoded array** with a fixed schema:

```
availability_cert_message = dCBOR([
  "materios-availability-cert-v1",    // [0] domain separator
  chain_id,                           // [1] partner chain genesis hash
  receipt_id,                         // [2] binds to specific receipt
  content_hash,                       // [3] binds to evidence content
  base_root_sha256,                   // [4] Merkle root of receipt chunks
  storage_locator_hash,               // [5] hash of checked storage locations
  attested_at_epoch,                  // [6] Cardano epoch at attestation time
  retention_commitment_days,          // [7] retention commitment in days
  attestation_level,                  // [8] verification level (1, 2, or 3)
])
```

The message is a CBOR **array** (major type 4), not a CBOR map. This is deliberate: arrays have no key-ordering ambiguity, and positional indexing is simpler for on-chain Plutus validators to decode. Field semantics are defined by position, not by key name.

---

## 4. Field Descriptions

### 4.0 `domain_separator` (index 0)

- **CBOR type**: text string (major type 3)
- **Value**: `"materios-availability-cert-v1"`
- **Purpose**: Prevents cross-protocol signature confusion. If the same key pair is used to sign messages in a different protocol, the domain separator ensures that a certificate signature cannot be replayed as a valid signature in that other protocol (and vice versa). The version suffix allows future schema evolution without breaking existing certificates.

### 4.1 `chain_id` (index 1)

- **CBOR type**: byte string (major type 2), 32 bytes
- **Value**: The genesis hash of the Cardano partner chain (or mainnet)
- **Purpose**: Anti-replay across chains. A certificate issued for the Cardano mainnet cannot be replayed on a testnet or a partner chain, because the genesis hash differs. This field binds the certificate to a specific chain instance.

### 4.2 `receipt_id` (index 2)

- **CBOR type**: text string (major type 3)
- **Value**: The unique identifier of the materios receipt being attested
- **Purpose**: Binds the certificate to a specific receipt. Without this field, a certificate for one receipt could be falsely presented as attesting availability of a different receipt's content.

### 4.3 `content_hash` (index 3)

- **CBOR type**: byte string (major type 2), 32 bytes
- **Value**: SHA-256 hash of the original content that the receipt covers
- **Purpose**: Binds the certificate to the specific evidence content. This is a direct link to the data — if the content changes, this hash changes, and the certificate is no longer valid.

### 4.4 `base_root_sha256` (index 4)

- **CBOR type**: byte string (major type 2), 32 bytes
- **Value**: The Merkle root hash from the receipt's chunk tree
- **Purpose**: Redundant but explicit binding to the receipt's integrity proof. While `receipt_id` indirectly references the Merkle root, including `base_root_sha256` directly allows auditors to verify the certificate against the Merkle tree without looking up the receipt. This is especially useful for offline or lightweight verification scenarios.

### 4.5 `storage_locator_hash` (index 5)

- **CBOR type**: byte string (major type 2), 32 bytes
- **Value**: SHA-256 hash of the concatenated, sorted storage locators (URIs/CIDs) that were checked during attestation
- **Purpose**: Records *which* storage locations the attester checked. If storage is replicated across multiple providers (e.g., IPFS CIDs, Arweave transaction IDs, S3 URIs), this field commits to the specific set of locations that were verified. This prevents an attester from claiming to have checked locations they did not.

### 4.6 `attested_at_epoch` (index 6)

- **CBOR type**: unsigned integer (major type 0)
- **Value**: The Cardano epoch number at the time the attestation was performed
- **Purpose**: Timestamps the attestation in Cardano-native time. Using epoch numbers (rather than Unix timestamps) makes the certificate directly verifiable against the Cardano chain state: the epoch can be cross-referenced with the on-chain transaction that records the certificate hash.

### 4.7 `retention_commitment_days` (index 7)

- **CBOR type**: unsigned integer (major type 0)
- **Value**: The number of days the attester commits to retaining the data, starting from the attestation epoch
- **Purpose**: Makes the retention promise explicit and auditable. If an attester claims a 365-day retention commitment, that commitment is permanently recorded in the certificate. Future re-attestation checks can verify whether the data is still available within the committed window.

### 4.8 `attestation_level` (index 8)

- **CBOR type**: unsigned integer (major type 0)
- **Value**: `1`, `2`, or `3` (see Section 5 for definitions)
- **Purpose**: Indicates the depth of verification performed by the attester. Higher levels provide stronger guarantees. The level is recorded in the certificate so that consumers can make risk-adjusted decisions based on the strength of the attestation.

---

## 5. Verification Levels

Availability certificates support three verification levels, each building on the previous:

### 5.1 L1 — Fetched

**Requirement**: The attester successfully downloaded all blobs (chunks) referenced by the receipt from the declared storage locations.

**What it proves**: The data exists at the declared locations and is retrievable. It does **not** prove the data is correct — only that *something* is stored there and can be fetched.

**Failure mode addressed**: Storage provider is offline, data has been deleted, or locators are broken.

### 5.2 L2 — Hash-verified

**Requirement**: L1, plus the attester computed the SHA-256 hash of each downloaded blob and verified that it matches the corresponding hash in the receipt's chunk manifest.

**What it proves**: Each individual blob is bitwise identical to the content that was originally ingested. No single blob has been corrupted or tampered with.

**Failure mode addressed**: Silent data corruption (bit rot), partial tampering, or storage provider serving incorrect data.

### 5.3 L3 — Root-verified

**Requirement**: L2, plus the attester recomputed the Merkle tree from the verified chunk hashes and confirmed that the resulting root matches `base_root_sha256`.

**What it proves**: The complete set of chunks is present (no chunks missing or added), in the correct order, and their aggregate integrity matches the on-chain Merkle root. This is the strongest possible verification: it proves the entire content is intact and complete.

**Failure mode addressed**: Missing chunks, extra chunks, reordered chunks, or a receipt that was modified after anchoring.

### 5.4 MVP Requirement

**The MVP requires L3 verification for all availability certificates.** L1 and L2 are defined for future use (e.g., lightweight periodic checks, or partial attestation when bandwidth is constrained), but MUST NOT be used in production until the protocol explicitly enables them.

---

## 6. On-Chain Hash Computation

The on-chain representation of an availability certificate is its SHA-256 hash:

```
availability_cert_hash = SHA-256(dCBOR_message_bytes)
```

### 6.1 Step-by-Step

1. **Construct the message array** with all 9 fields as specified in Section 3.
2. **Encode as dCBOR** per RFC 8949 Section 4.2. The encoding MUST satisfy all deterministic encoding requirements (preferred integer encoding, definite-length containers, sorted map keys — though this message uses an array, not a map, so map-key sorting does not apply at the top level).
3. **Compute SHA-256** over the raw dCBOR bytes. This produces a 32-byte (256-bit) hash.
4. **Record on-chain**: The `availability_cert_hash` is included in a Cardano transaction (e.g., as transaction metadata or in a datum). The full dCBOR message is stored off-chain (e.g., alongside the receipt in the storage layer).

### 6.2 Why SHA-256 of dCBOR Bytes

- **Determinism**: Because dCBOR encoding is deterministic, the same logical certificate always produces the same bytes, and therefore the same hash. There is no ambiguity.
- **Compactness**: A 32-byte hash fits efficiently in Cardano transaction metadata. The full certificate (which may be hundreds of bytes) is stored off-chain where storage is cheap.
- **Verifiability**: Anyone with the full dCBOR message can re-encode it (dCBOR is deterministic) and verify that SHA-256 matches the on-chain hash. This requires no trust in the original encoder.
- **Tamper evidence**: Any modification to any field — even a single bit — produces a completely different hash, making tampering immediately detectable.

### 6.3 Pseudocode

```typescript
import { encode as cborEncode } from 'cbor-x';  // or any RFC 8949 §4.2 compliant encoder
import { createHash } from 'crypto';

interface AvailabilityCertFields {
  chainId: Uint8Array;            // 32 bytes, genesis hash
  receiptId: string;
  contentHash: Uint8Array;        // 32 bytes
  baseRootSha256: Uint8Array;     // 32 bytes
  storageLocatorHash: Uint8Array; // 32 bytes
  attestedAtEpoch: number;        // unsigned integer
  retentionCommitmentDays: number;// unsigned integer
  attestationLevel: 1 | 2 | 3;
}

function computeAvailabilityCertHash(fields: AvailabilityCertFields): Uint8Array {
  const message = [
    "materios-availability-cert-v1",
    fields.chainId,
    fields.receiptId,
    fields.contentHash,
    fields.baseRootSha256,
    fields.storageLocatorHash,
    fields.attestedAtEpoch,
    fields.retentionCommitmentDays,
    fields.attestationLevel,
  ];

  // Encode as deterministic CBOR (RFC 8949 §4.2)
  const dCborBytes = cborEncode(message);  // Must use a dCBOR-compliant encoder

  // SHA-256 of the raw dCBOR bytes
  const hash = createHash('sha256').update(dCborBytes).digest();

  return new Uint8Array(hash);
}
```

---

## 7. Signature and Authentication

### 7.1 Domain Separation

The domain separator `"materios-availability-cert-v1"` as the first array element ensures that the dCBOR message cannot be confused with any other protocol's message format, even if the same signing key is used across protocols. This is a standard cryptographic hygiene practice.

### 7.2 Anti-Replay via `chain_id`

The `chain_id` field (genesis hash) prevents cross-chain replay. A certificate issued for Cardano mainnet (genesis hash `0x1a2b3c...`) cannot be presented as valid on a partner chain or testnet (which has a different genesis hash). This is analogous to EIP-155 chain IDs in Ethereum.

### 7.3 Signing (Future Work)

The current specification defines the **message format and hash**. The signing mechanism (which key signs, which signature scheme is used, how the signature is attached) is defined by the broader materios protocol and is outside the scope of this document. The certificate message is designed to be signing-scheme agnostic: the dCBOR bytes can be signed with Ed25519, ECDSA, or any other scheme supported by the Cardano ecosystem.

---

## 8. Encoding Requirements Summary

All implementations MUST conform to the following encoding rules when producing the `dCBOR_message_bytes`:

| Element | Encoding Rule |
|---|---|
| Top-level structure | CBOR array (major type 4), definite length, 9 elements |
| Text strings | Major type 3, definite length, UTF-8 encoded |
| Byte strings | Major type 2, definite length |
| Unsigned integers | Major type 0, preferred (shortest) encoding |
| No indefinite-length | Indefinite-length encoding MUST NOT be used |
| No tags | CBOR tags (major type 6) MUST NOT be used unless a future version of this spec explicitly requires them |
| No floating point | All numeric fields in this message are integers; float encoding MUST NOT be used |
| Canonical array ordering | Array elements are in the fixed positional order defined in Section 3; no reordering is permitted |

---

## 9. Validation Rules

A conforming implementation MUST reject a certificate as invalid if any of the following conditions are met:

1. The dCBOR bytes do not decode as a valid CBOR array of exactly 9 elements.
2. The domain separator (index 0) is not exactly `"materios-availability-cert-v1"`.
3. The `chain_id` (index 1) is not a 32-byte byte string.
4. The `receipt_id` (index 2) is not a non-empty text string.
5. The `content_hash` (index 3) is not a 32-byte byte string.
6. The `base_root_sha256` (index 4) is not a 32-byte byte string.
7. The `storage_locator_hash` (index 5) is not a 32-byte byte string.
8. The `attested_at_epoch` (index 6) is not an unsigned integer.
9. The `retention_commitment_days` (index 7) is not an unsigned integer, or is `0`.
10. The `attestation_level` (index 8) is not one of `1`, `2`, or `3`.
11. Re-encoding the decoded message as dCBOR does not produce the identical bytes (round-trip check for encoding canonicality).

---

## 10. Example

The following is a conceptual example (actual CBOR hex will vary based on field values):

```
Certificate fields:
  domain_separator:         "materios-availability-cert-v1"
  chain_id:                 0x1a2b3c4d...  (32 bytes, mainnet genesis hash)
  receipt_id:               "receipt-2026-001-abc"
  content_hash:             0xdeadbeef...  (32 bytes)
  base_root_sha256:         0xcafebabe...  (32 bytes)
  storage_locator_hash:     0x11223344...  (32 bytes)
  attested_at_epoch:        520
  retention_commitment_days: 365
  attestation_level:        3

On-chain value:
  availability_cert_hash = SHA-256(dCBOR([...fields above...])) = 0xabcdef...  (32 bytes)
```

The full dCBOR message is stored off-chain (e.g., in the materios storage layer, alongside the receipt data). The 32-byte `availability_cert_hash` is the only value that must appear on-chain.

---

## 11. Normative References

- **RFC 8949** — Concise Binary Object Representation (CBOR). Bormann, C., Hoffman, P. December 2020. Section 4.2: Core Deterministic Encoding Requirements.
  https://www.rfc-editor.org/rfc/rfc8949#section-4.2
- **RFC 8785** — JSON Canonicalization Scheme (JCS). Rundgren, A., Jordan, B., Erdtman, S. June 2020.
  https://www.rfc-editor.org/rfc/rfc8785
- **FIPS 180-4** — Secure Hash Standard (SHA-256).
  https://csrc.nist.gov/publications/detail/fips/180/4/final

---

## 12. Informative References

- **CDDL (RFC 8610)** — Concise Data Definition Language. For future formal schema definition of the certificate structure.
  https://www.rfc-editor.org/rfc/rfc8610
- **Cardano Ledger Specification** — For transaction metadata encoding and datum structure.
- **EIP-155** — Ethereum chain ID concept, analogous to the `chain_id` anti-replay mechanism used here.
