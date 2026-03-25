# Canonicalization Specification

**Version**: materios-receipt-v1
**Status**: Normative
**Last updated**: 2026-02-25

---

## 1. Overview

This document specifies how materios canonicalizes JSON content before hashing. The goal is **deterministic, reproducible byte output** so that any compliant implementation — on any platform, in any language — produces the identical SHA-256 hash for the same logical content.

materios adopts **RFC 8785 JSON Canonicalization Scheme (JCS)** as the sole canonicalization algorithm. All prior homebrew approaches (e.g., recursive `deepSortKeys` helpers) are superseded by this specification.

---

## 2. Why RFC 8785 Over Homebrew Canonicalization

Homebrew key-sorting functions are a recurring source of subtle, hard-to-diagnose bugs:

| Problem | Homebrew `deepSortKeys` | RFC 8785 JCS |
|---|---|---|
| **Unicode sort order** | Typically delegates to language-default `Array.sort`, which may vary across engines and locales | Mandates UTF-16 code-unit lexicographic ordering (ECMA-262 §11.8.5), fully specified |
| **Numeric encoding** | `JSON.stringify` output varies (`1.0` vs `1`, `-0` vs `0`, exponential notation thresholds differ) | Strict I-JSON (RFC 7493) numeric serialization: no leading zeros, no trailing fractional zeros, no positive-sign exponent, `-0` serialized as `0` |
| **String escaping** | Implementations disagree on whether to escape `/`, which Unicode escapes to use, and surrogate-pair handling | Minimal escaping: only the mandatory control characters and `"` and `\` are escaped; all other code points appear as literal UTF-8 |
| **Whitespace** | Must remember to strip; easy to miss in nested structures | Specification prohibits insignificant whitespace by construction |
| **Interoperability** | Every consumer must reimplement the same ad-hoc rules | Multiple audited, cross-language reference implementations exist (Node.js, Java, Python, Go, Rust, C) |
| **Auditability** | "Trust our sort function" | "Trust the IETF RFC and its test vectors" |

By adopting RFC 8785, materios inherits a formally specified, widely reviewed standard with published test vectors. This is essential for a system whose hashes will be anchored on an immutable blockchain: there is zero room for "works on my machine" divergence.

---

## 3. Input Format

### 3.1 JSONL (JSON Lines)

Content arrives as **JSONL**: one complete, self-contained JSON object per newline-delimited line.

```
{"type":"receipt","id":"abc-001","ts":1700000000}\n
{"type":"receipt","id":"abc-002","ts":1700000001}\n
```

Each line MUST parse as a valid JSON value (typically an object, but arrays and primitives are permitted). Lines that do not parse as valid JSON MUST cause the pipeline to reject the entire input.

### 3.2 Newline Normalization

Before any further processing:

1. **Strip carriage returns**: Replace every `\r\n` (CRLF) and bare `\r` (CR) with `\n` (LF). This eliminates platform-specific line endings.
2. **Strip empty lines**: Remove any line that, after trimming, is zero-length. Empty lines carry no semantic content and MUST NOT contribute to the hash.
3. **Ignore trailing newline**: If the input ends with `\n`, that trailing newline does not produce an additional empty line. (This is consistent with POSIX text-file conventions.)

After normalization, the input is an ordered sequence of non-empty lines, each containing exactly one JSON value.

---

## 4. Per-Line Canonicalization

Each line is independently canonicalized using **RFC 8785 JCS**. The algorithm, in summary:

1. **Parse** the JSON text into the implementation's native data model.
2. **Serialize** back to JSON using the following rules:
   - **Property ordering**: Object properties are sorted by key using UTF-16 code-unit lexicographic comparison (the same ordering as ECMAScript `Array.prototype.sort` applied to strings).
   - **Numeric encoding**: Numbers are serialized following the I-JSON (RFC 7493) profile:
     - No leading zeros (except the single digit `0`).
     - No trailing zeros after the decimal point.
     - No positive sign on exponents.
     - Negative zero (`-0`) is serialized as `0`.
     - The shortest representation that round-trips to the same IEEE 754 double is used.
   - **String escaping**: Only the following characters are escaped: `\b`, `\f`, `\n`, `\r`, `\t`, `\"`, `\\`, and Unicode code points U+0000 through U+001F (using `\uXXXX` lowercase hex). All other characters — including `/` — appear as literal UTF-8.
   - **No whitespace**: No spaces or newlines appear between tokens.
3. **Encode** the resulting string as UTF-8 bytes.

### 4.1 Reference Implementation

The **`canonicalize`** npm package is the designated implementation for Node.js/TypeScript environments:

```bash
npm install canonicalize
```

```typescript
import canonicalize from 'canonicalize';

function canonicalizeLine(jsonText: string): string {
  const parsed = JSON.parse(jsonText);
  const canonical = canonicalize(parsed);
  if (canonical === undefined) {
    throw new Error('canonicalize returned undefined — input was not a valid JSON value');
  }
  return canonical;
}
```

This package is the **RFC 8785 reference implementation** maintained by Anders Rundgren (one of the RFC authors). It passes the full RFC 8785 test-vector suite.

**Do not** use `JSON.stringify` with a custom replacer or `deepSortKeys`. These approaches cannot correctly handle all edge cases specified by RFC 8785 (especially numeric serialization and Unicode sort order).

---

## 5. Chunk Boundaries

### 5.1 Lines Are Atomic

A single JSONL line is the **minimum unit of chunking**. A line MUST NOT be split across chunks. This guarantee simplifies verification: a verifier can parse each chunk as a sequence of complete JSONL lines without buffering partial JSON across chunk boundaries.

### 5.2 Chunk Formation

When multiple lines are grouped into a chunk (e.g., for batching or size targets), the canonical lines are concatenated as follows:

- Lines are joined with a single `\n` (U+000A, LF) character.
- There is **no trailing newline** after the last line in the chunk.

```
canonical_line_1 + "\n" + canonical_line_2 + "\n" + canonical_line_3
```

For a chunk containing a single line, the chunk content is simply that line's canonical bytes with no trailing newline.

### 5.3 Rationale for No Trailing Newline

A trailing newline would create ambiguity: does it signal "there is one more empty line" or "end of chunk"? By omitting it, the chunk byte-length is fully determined by the canonical lines it contains, and `chunk.split('\n')` recovers exactly the original lines with no empty-string artifacts.

---

## 6. Hash Input

The SHA-256 hash of a chunk is computed over the **canonical chunk bytes** (UTF-8 encoded canonical JSONL), **not** over any compressed representation.

```
chunk_hash = SHA-256(canonical_chunk_bytes)
```

This is a critical design decision:

- **Compression is not deterministic across implementations.** Gzip, Brotli, and zstd all permit implementation-defined choices (compression level, window size, dictionary). Two compliant compressors can produce different byte streams for the same input.
- **Hashing canonical plaintext is reproducible.** Any verifier can decompress, re-canonicalize, and recompute the hash — regardless of which compressor was used at ingest time.
- **Separation of concerns.** Canonicalization defines semantic identity; compression is a transport/storage optimization. Mixing them couples the hash to a specific compressor version, which is fragile.

---

## 7. Full Pipeline Summary

```
Raw input (may have CRLF, empty lines, unsorted keys)
  |
  v
[1] Newline normalization: strip \r, drop empty lines, ignore trailing \n
  |
  v
[2] Split into lines
  |
  v
[3] Per-line RFC 8785 JCS canonicalization (via `canonicalize` npm package)
  |
  v
[4] Group lines into chunks (lines are atomic, never split)
  |
  v
[5] Join chunk lines with \n (no trailing newline)
  |
  v
[6] UTF-8 encode chunk -> canonical chunk bytes
  |
  v
[7] SHA-256(canonical chunk bytes) -> chunk hash
  |
  v
[8] Chunk hashes feed into Merkle tree for receipt anchoring
```

---

## 8. Versioning

The version header **`materios-receipt-v1`** identifies this canonicalization scheme. The version string appears:

- In receipt metadata, binding the receipt to a specific canonicalization algorithm.
- In the domain separator of signed messages (see AVAILABILITY_CERT_SPEC.md).

If the canonicalization algorithm changes (e.g., a move to CBOR), the version string MUST change (e.g., `materios-receipt-v2`).

---

## 9. Future: CBOR Canonicalization (V2)

Cardano's on-chain data formats are natively CBOR (Concise Binary Object Representation). A natural evolution for materios is to adopt **CBOR deterministic encoding per RFC 8949 Section 4.2** as the canonical format in a future version.

### 9.1 Why CBOR Is a Natural V2 Step

- **Ecosystem alignment**: Cardano transactions, datums, and metadata are all CBOR-encoded. Using CBOR for receipt content eliminates a JSON-to-CBOR transcoding step at the chain boundary.
- **Deterministic encoding is specified**: RFC 8949 Section 4.2 defines "Core Deterministic Encoding Requirements" — map keys sorted by encoded byte length then lexicographically, preferred integer encodings, preferred float encodings. This is the CBOR analogue of RFC 8785 for JSON.
- **Compact representation**: CBOR is more compact than JSON for the same data, reducing storage and bandwidth costs.
- **Binary-native hashing**: CBOR bytes can be hashed directly without a parse-reserialize round-trip, simplifying on-chain verification logic in Plutus validators.

### 9.2 Migration Path

A V2 specification would:

1. Define the CBOR schema for receipt lines (CDDL notation).
2. Mandate RFC 8949 Section 4.2 deterministic encoding.
3. Introduce a new version header (`materios-receipt-v2`).
4. Maintain backward compatibility by allowing V1 receipts to remain valid under their original canonicalization rules.

This is documented here for planning purposes. The current specification (V1) uses RFC 8785 JCS exclusively.

---

## 10. Normative References

- **RFC 8785** — JSON Canonicalization Scheme (JCS). Rundgren, A., Jordan, B., Erdtman, S. June 2020.
  https://www.rfc-editor.org/rfc/rfc8785
- **RFC 7493** — The I-JSON Message Format. Bray, T. March 2015.
  https://www.rfc-editor.org/rfc/rfc7493
- **RFC 8949** — Concise Binary Object Representation (CBOR). Bormann, C., Hoffman, P. December 2020.
  https://www.rfc-editor.org/rfc/rfc8949
- **ECMA-262** — ECMAScript Language Specification, Section 11.8.5 (Abstract Relational Comparison).
  https://tc39.es/ecma262/
- **`canonicalize` npm package** — RFC 8785 reference implementation for JavaScript.
  https://www.npmjs.com/package/canonicalize
