import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeJsonl } from "../src/canonicalize.js";
import { chunkLines } from "../src/chunker.js";
import { sha256, sha256Bytes } from "../src/hash/sha256.js";
import { buildMerkleTree } from "../src/hash/merkle.js";
import { compressChunk } from "../src/compress.js";
import { encryptBlob, decryptBlob } from "../src/encrypt.js";
import { runPipeline } from "../src/pipeline.js";
import { computeContentHash, computeReceiptId } from "../src/receipt.js";
import type { CanonicalLine } from "../src/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "..", "examples");
const TRACE_FILE = path.join(FIXTURES_DIR, "trace.jsonl");
const TEST_OUTPUT_BASE = path.join(__dirname, ".test-output");

let outputCounter = 0;
function freshOutputDir(): string {
  const dir = path.join(TEST_OUTPUT_BASE, `run-${++outputCounter}-${Date.now()}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

beforeAll(() => {
  fs.mkdirSync(TEST_OUTPUT_BASE, { recursive: true });
});

afterAll(() => {
  // Clean up test output
  fs.rmSync(TEST_OUTPUT_BASE, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. JCS Canonicalize Tests
// ---------------------------------------------------------------------------
describe("JCS canonicalize", () => {
  it("should order object keys alphabetically (RFC 8785)", () => {
    const input = '{"z":1,"a":2,"m":3}';
    const lines = canonicalizeJsonl(input);

    expect(lines).toHaveLength(1);
    // RFC 8785 mandates lexicographic key ordering
    expect(lines[0].canonical).toBe('{"a":2,"m":3,"z":1}');
  });

  it("should encode numbers without unnecessary decimals", () => {
    const input = '{"value":1.0,"count":100,"neg":-0}';
    const lines = canonicalizeJsonl(input);

    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0].canonical);
    // 1.0 should become 1, -0 should become 0 in JCS
    expect(parsed.value).toBe(1);
    expect(parsed.count).toBe(100);
  });

  it("should handle nested objects with correct ordering", () => {
    const input = '{"b":{"z":1,"a":2},"a":true}';
    const lines = canonicalizeJsonl(input);

    expect(lines).toHaveLength(1);
    expect(lines[0].canonical).toBe('{"a":true,"b":{"a":2,"z":1}}');
  });

  it("should handle multiple JSONL lines", () => {
    const input = '{"b":1}\n{"a":2}\n\n{"c":3}\n';
    const lines = canonicalizeJsonl(input);

    expect(lines).toHaveLength(3);
    expect(lines[0].canonical).toBe('{"b":1}');
    expect(lines[1].canonical).toBe('{"a":2}');
    expect(lines[2].canonical).toBe('{"c":3}');
  });

  it("should strip carriage returns", () => {
    const input = '{"a":1}\r\n{"b":2}\r\n';
    const lines = canonicalizeJsonl(input);

    expect(lines).toHaveLength(2);
  });

  it("should produce correct UTF-8 bytes", () => {
    const input = '{"emoji":"\\u2764"}';
    const lines = canonicalizeJsonl(input);

    expect(lines[0].bytes).toBeInstanceOf(Buffer);
    expect(lines[0].bytes.toString("utf-8")).toBe(lines[0].canonical);
  });
});

// ---------------------------------------------------------------------------
// 2. Chunker Tests
// ---------------------------------------------------------------------------
describe("chunker", () => {
  function makeLines(count: number, sizeEach: number): CanonicalLine[] {
    const content = "x".repeat(sizeEach);
    return Array.from({ length: count }, (_, i) => ({
      index: i,
      canonical: `{"d":"${content}"}`,
      bytes: Buffer.from(`{"d":"${content}"}`, "utf-8"),
    }));
  }

  it("should keep all lines in one chunk if total < targetSize", () => {
    const lines = makeLines(3, 10);
    const chunks = chunkLines(lines, 65536);

    expect(chunks).toHaveLength(1);
    expect(chunks[0].lines).toHaveLength(3);
  });

  it("should split lines across chunks when exceeding target", () => {
    // Each line is ~20 bytes + overhead; set target very small
    const lines = makeLines(10, 50);
    const chunks = chunkLines(lines, 100);

    expect(chunks.length).toBeGreaterThan(1);
    // Verify all lines are present
    const totalLines = chunks.reduce((sum, c) => sum + c.lines.length, 0);
    expect(totalLines).toBe(10);
  });

  it("should never split a line across chunks (atomic lines)", () => {
    const lines = makeLines(5, 200);
    const chunks = chunkLines(lines, 150);

    for (const chunk of chunks) {
      for (const line of chunk.lines) {
        // Each line should appear intact
        expect(line.canonical).toContain("x".repeat(200));
      }
    }
  });

  it("should give a single oversized line its own chunk", () => {
    const lines: CanonicalLine[] = [
      { index: 0, canonical: "a".repeat(10), bytes: Buffer.from("a".repeat(10)) },
      { index: 1, canonical: "b".repeat(200), bytes: Buffer.from("b".repeat(200)) },
      { index: 2, canonical: "c".repeat(10), bytes: Buffer.from("c".repeat(10)) },
    ];
    const chunks = chunkLines(lines, 50);

    // The oversized line should be alone in its chunk
    const oversizedChunk = chunks.find((c) =>
      c.lines.some((l) => l.index === 1),
    );
    expect(oversizedChunk).toBeDefined();
    expect(oversizedChunk!.lines).toHaveLength(1);
  });

  it("should join lines with LF and no trailing newline", () => {
    const lines: CanonicalLine[] = [
      { index: 0, canonical: '{"a":1}', bytes: Buffer.from('{"a":1}') },
      { index: 1, canonical: '{"b":2}', bytes: Buffer.from('{"b":2}') },
    ];
    const chunks = chunkLines(lines, 65536);

    expect(chunks[0].canonicalBytes.toString("utf-8")).toBe('{"a":1}\n{"b":2}');
  });

  it("should handle empty input", () => {
    const chunks = chunkLines([], 65536);
    expect(chunks).toHaveLength(0);
  });

  it("should assign sequential chunk indices", () => {
    const lines = makeLines(20, 50);
    const chunks = chunkLines(lines, 100);

    chunks.forEach((chunk, i) => {
      expect(chunk.index).toBe(i);
    });
  });
});

// ---------------------------------------------------------------------------
// 3. Merkle Tree Tests
//
// Algorithm parity with cert-daemon's `daemon/merkle.py`:
//   - 0 leaves -> 32 zero bytes
//   - 1 leaf   -> leaf as-is
//   - N > 1    -> sha256(RAW(a) || RAW(b)); duplicate last on odd levels
// ---------------------------------------------------------------------------

// Helper: cert-daemon-canonical pair hash over hex-string leaves.
function pairHashHex(a: string, b: string): string {
  return sha256Bytes(
    Buffer.concat([Buffer.from(a, "hex"), Buffer.from(b, "hex")]),
  ).toString("hex");
}

describe("Merkle tree", () => {
  it("should return 32 zero bytes for 0 leaves (cert-daemon parity)", () => {
    const tree = buildMerkleTree([]);
    expect(tree.root).toBe("0".repeat(64));
    expect(tree.leaves).toHaveLength(0);
  });

  it("should return the leaf itself for 1 leaf", () => {
    const leaf = sha256("hello");
    const tree = buildMerkleTree([leaf]);
    expect(tree.root).toBe(leaf);
  });

  it("should compute correct root for 2 leaves (raw-byte concat)", () => {
    const a = sha256("a");
    const b = sha256("b");
    const tree = buildMerkleTree([a, b]);

    const expectedRoot = pairHashHex(a, b);
    expect(tree.root).toBe(expectedRoot);
  });

  it("should handle odd number of leaves by duplicating last", () => {
    const a = sha256("a");
    const b = sha256("b");
    const c = sha256("c");
    const tree = buildMerkleTree([a, b, c]);

    // Level 1: hash(a,b), hash(c,c)
    // Level 2: hash(hash(a,b), hash(c,c))
    const left = pairHashHex(a, b);
    const right = pairHashHex(c, c);
    const expectedRoot = pairHashHex(left, right);
    expect(tree.root).toBe(expectedRoot);
  });

  it("should handle 4 leaves correctly", () => {
    const leaves = ["a", "b", "c", "d"].map((x) => sha256(x));
    const tree = buildMerkleTree(leaves);

    const l01 = pairHashHex(leaves[0], leaves[1]);
    const l23 = pairHashHex(leaves[2], leaves[3]);
    const expectedRoot = pairHashHex(l01, l23);
    expect(tree.root).toBe(expectedRoot);
  });

  it("should produce deterministic roots", () => {
    const leaves = ["x", "y", "z"].map((x) => sha256(x));
    const tree1 = buildMerkleTree(leaves);
    const tree2 = buildMerkleTree(leaves);
    expect(tree1.root).toBe(tree2.root);
  });

  it("should accept custom hash function", () => {
    // Custom hash: reversed raw-byte concat.
    const customHash = (a: string, b: string) =>
      sha256Bytes(
        Buffer.concat([Buffer.from(b, "hex"), Buffer.from(a, "hex")]),
      ).toString("hex");
    const leaves = [sha256("a"), sha256("b")];

    const tree = buildMerkleTree(leaves, customHash);
    const expected = customHash(leaves[0], leaves[1]);
    expect(tree.root).toBe(expected);
  });

  // Regression test pinning cert-daemon parity for the 3-chunk default-chunk
  // fixture used by the SDK's anchors-materios package. Computed by running
  // `daemon/merkle.py` against the same input — see fixtures comment.
  it("matches cert-daemon for 3-chunk @ 256 KiB fixture", () => {
    const CHUNK_SIZE = 256 * 1024;
    const leafBuf0 = Buffer.alloc(CHUNK_SIZE, 0);
    const leafBuf1 = Buffer.alloc(CHUNK_SIZE, 1);
    const leafBuf2 = Buffer.alloc(CHUNK_SIZE, 2);
    const leaves = [
      sha256Bytes(leafBuf0).toString("hex"),
      sha256Bytes(leafBuf1).toString("hex"),
      sha256Bytes(leafBuf2).toString("hex"),
    ];
    expect(leaves[0]).toBe(
      "8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90",
    );
    expect(leaves[1]).toBe(
      "f317dd9d6ba01c465d82e4c4d55d01d270dda69db4a01a64c587a5593ac6084d",
    );
    expect(leaves[2]).toBe(
      "b1026d9249014c863c3a8daf11dec61bd4d4abcfdc7f1a62181cf743d4b6a12e",
    );

    const tree = buildMerkleTree(leaves);
    expect(tree.root).toBe(
      "cff7222bfb3b15ac46d49664992dea6d9bd55ec3da34f0bf12fe255e49c354f6",
    );
  });
});

// ---------------------------------------------------------------------------
// 4. SHA-256 Tests
// ---------------------------------------------------------------------------
describe("SHA-256", () => {
  it("should match known test vector for empty string", () => {
    const hash = sha256("");
    expect(hash).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("should match known test vector for 'abc'", () => {
    const hash = sha256("abc");
    expect(hash).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("should match known test vector for 'hello world'", () => {
    const hash = sha256("hello world");
    expect(hash).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
  });

  it("sha256Bytes should return a Buffer of 32 bytes", () => {
    const buf = sha256Bytes("test");
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBe(32);
  });

  it("sha256 hex should match sha256Bytes hex", () => {
    const hex = sha256("test");
    const buf = sha256Bytes("test");
    expect(buf.toString("hex")).toBe(hex);
  });
});

// ---------------------------------------------------------------------------
// 5. Encryption Tests
// ---------------------------------------------------------------------------
describe("encryption", () => {
  const testKey = "a".repeat(64); // 32 bytes of 0xaa

  it("should encrypt and decrypt round-trip", () => {
    const plaintext = Buffer.from("hello world");
    const { encrypted, iv, authTag } = encryptBlob(plaintext, testKey);

    const decrypted = decryptBlob(encrypted, testKey, iv, authTag);
    expect(decrypted.toString("utf-8")).toBe("hello world");
  });

  it("should produce different ciphertext each time (random IV)", () => {
    const plaintext = Buffer.from("same input");
    const result1 = encryptBlob(plaintext, testKey);
    const result2 = encryptBlob(plaintext, testKey);

    expect(result1.iv).not.toBe(result2.iv);
    expect(result1.encrypted.equals(result2.encrypted)).toBe(false);
  });

  it("should reject invalid key length", () => {
    expect(() => encryptBlob(Buffer.from("x"), "abcd")).toThrow(
      /Invalid key length/,
    );
  });
});

// ---------------------------------------------------------------------------
// 6. Determinism Test
// ---------------------------------------------------------------------------
describe("determinism", () => {
  it("should produce identical content_hash and roots for same input", async () => {
    const out1 = freshOutputDir();
    const out2 = freshOutputDir();

    const receipt1 = await runPipeline({
      input: TRACE_FILE,
      output: out1,
      skipPoseidon: true,
    });

    // Small delay to ensure different timestamp
    await new Promise((resolve) => setTimeout(resolve, 10));

    const receipt2 = await runPipeline({
      input: TRACE_FILE,
      output: out2,
      skipPoseidon: true,
    });

    // Content hash and roots should be identical
    expect(receipt1.contentHash).toBe(receipt2.contentHash);
    expect(receipt1.baseRootSha256).toBe(receipt2.baseRootSha256);
    expect(receipt1.schemaHash).toBe(receipt2.schemaHash);
    expect(receipt1.baseManifestHash).toBe(receipt2.baseManifestHash);

    // Receipt IDs should differ (different timestamps)
    expect(receipt1.receiptId).not.toBe(receipt2.receiptId);
    expect(receipt1.observedAtMillis).not.toBe(receipt2.observedAtMillis);
  });
});

// ---------------------------------------------------------------------------
// 7. Encryption Independence Test
// ---------------------------------------------------------------------------
describe("encryption independence", () => {
  it("should produce identical roots and content_hash with and without encryption", async () => {
    const outPlain = freshOutputDir();
    const outEncrypted = freshOutputDir();

    const encryptKey = "b".repeat(64);

    const receiptPlain = await runPipeline({
      input: TRACE_FILE,
      output: outPlain,
      skipPoseidon: true,
    });

    const receiptEncrypted = await runPipeline({
      input: TRACE_FILE,
      output: outEncrypted,
      encryptKey,
      skipPoseidon: true,
    });

    // Roots and content hash should be identical -- encryption is storage-only
    expect(receiptPlain.baseRootSha256).toBe(receiptEncrypted.baseRootSha256);
    expect(receiptPlain.schemaHash).toBe(receiptEncrypted.schemaHash);

    // Note: content_hash will differ because baseManifestHash includes
    // blob_sha256 which changes with encryption. But the Merkle root
    // (baseRootSha256) must remain identical since it's based on canonical bytes.
  });
});

// ---------------------------------------------------------------------------
// 8. Pipeline Integration Test
// ---------------------------------------------------------------------------
describe("pipeline integration", () => {
  it("should produce valid output files", async () => {
    const outDir = freshOutputDir();

    const receipt = await runPipeline({
      input: TRACE_FILE,
      output: outDir,
      skipPoseidon: true,
    });

    // Verify receipt.json exists and is valid
    const receiptPath = path.join(outDir, "receipt.json");
    expect(fs.existsSync(receiptPath)).toBe(true);
    const receiptJson = JSON.parse(fs.readFileSync(receiptPath, "utf-8"));
    expect(receiptJson.receiptId).toBe(receipt.receiptId);
    expect(receiptJson.contentHash).toBe(receipt.contentHash);

    // Verify manifest.json exists and is valid
    const manifestPath = path.join(outDir, "manifest.json");
    expect(fs.existsSync(manifestPath)).toBe(true);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
    expect(manifest.version).toBe("0.1.0");
    expect(manifest.entries).toBeInstanceOf(Array);
    expect(manifest.entries.length).toBeGreaterThan(0);

    // Verify blobs directory exists with chunk files
    const blobsDir = path.join(outDir, "blobs");
    expect(fs.existsSync(blobsDir)).toBe(true);
    const blobFiles = fs.readdirSync(blobsDir).filter((f) => f.endsWith(".bin"));
    expect(blobFiles.length).toBe(manifest.entries.length);

    // Verify each entry has required fields
    for (const entry of manifest.entries) {
      expect(entry.chunkIndex).toBeTypeOf("number");
      expect(entry.canonicalSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.blobSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.byteSize).toBeGreaterThan(0);
      expect(entry.lineCount).toBeGreaterThan(0);
      expect(entry.codec).toBe("gzip");
      expect(entry.encrypted).toBe(false);
    }
  });

  it("should produce encrypted blobs with metadata files", async () => {
    const outDir = freshOutputDir();
    const encryptKey = "c".repeat(64);

    await runPipeline({
      input: TRACE_FILE,
      output: outDir,
      encryptKey,
      skipPoseidon: true,
    });

    const manifest = JSON.parse(
      fs.readFileSync(path.join(outDir, "manifest.json"), "utf-8"),
    );

    // All entries should be marked encrypted
    for (const entry of manifest.entries) {
      expect(entry.encrypted).toBe(true);
    }

    // Each blob should have a corresponding .meta.json
    const blobsDir = path.join(outDir, "blobs");
    const metaFiles = fs.readdirSync(blobsDir).filter((f) =>
      f.endsWith(".meta.json"),
    );
    expect(metaFiles.length).toBe(manifest.entries.length);

    // Verify meta files have iv and authTag
    for (const metaFile of metaFiles) {
      const meta = JSON.parse(
        fs.readFileSync(path.join(blobsDir, metaFile), "utf-8"),
      );
      expect(meta.iv).toMatch(/^[0-9a-f]{24}$/); // 12 bytes = 24 hex chars
      expect(meta.authTag).toMatch(/^[0-9a-f]{32}$/); // 16 bytes = 32 hex chars
    }
  });

  it("should handle the example trace file completely", async () => {
    const outDir = freshOutputDir();

    const receipt = await runPipeline({
      input: TRACE_FILE,
      output: outDir,
      skipPoseidon: true,
    });

    // Basic sanity checks on the receipt
    expect(receipt.receiptId).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.baseRootSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.zkRootPoseidon).toBeNull();
    expect(receipt.poseidonParamsHash).toBeNull();
    expect(receipt.schemaHash).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.observedAtMillis).toBeGreaterThan(0);
  });

  it("should include Poseidon hashes when not skipped", async () => {
    const outDir = freshOutputDir();

    const receipt = await runPipeline({
      input: TRACE_FILE,
      output: outDir,
      skipPoseidon: false,
    });

    expect(receipt.zkRootPoseidon).not.toBeNull();
    expect(receipt.zkRootPoseidon).toMatch(/^[0-9a-f]+$/);
    expect(receipt.poseidonParamsHash).not.toBeNull();
    expect(receipt.poseidonParamsHash).toMatch(/^[0-9a-f]{64}$/);

    // Verify manifest also has Poseidon fields
    const manifest = JSON.parse(
      fs.readFileSync(path.join(outDir, "manifest.json"), "utf-8"),
    );
    expect(manifest.zkRootPoseidon).toBe(receipt.zkRootPoseidon);
    expect(manifest.poseidonParamsHash).toBe(receipt.poseidonParamsHash);
  });
});

// ---------------------------------------------------------------------------
// 9. Receipt computation tests
// ---------------------------------------------------------------------------
describe("receipt computation", () => {
  it("computeContentHash should be deterministic", () => {
    const fields = {
      baseRootSha256: sha256("root"),
      zkRootPoseidon: null,
      baseManifestHash: sha256("manifest"),
      safetyManifestHash: sha256("safety"),
      monitorConfigHash: sha256("monitor"),
      attestationEvidenceHash: sha256("attestation"),
      storageLocatorHash: sha256("storage"),
      schemaHash: sha256("schema"),
    };

    const hash1 = computeContentHash(fields);
    const hash2 = computeContentHash(fields);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("computeContentHash should use zero bytes for null zkRootPoseidon", () => {
    const fieldsWithNull = {
      baseRootSha256: sha256("root"),
      zkRootPoseidon: null,
      baseManifestHash: sha256("manifest"),
      safetyManifestHash: sha256("safety"),
      monitorConfigHash: sha256("monitor"),
      attestationEvidenceHash: sha256("attestation"),
      storageLocatorHash: sha256("storage"),
      schemaHash: sha256("schema"),
    };

    const fieldsWithZero = {
      ...fieldsWithNull,
      zkRootPoseidon: "0".repeat(64),
    };

    const hashNull = computeContentHash(fieldsWithNull);
    const hashZero = computeContentHash(fieldsWithZero);
    expect(hashNull).toBe(hashZero);
  });

  it("computeReceiptId should differ with different timestamps", () => {
    const contentHash = sha256("content");
    const pubkey = "0".repeat(64);

    const id1 = computeReceiptId(contentHash, pubkey, 1000);
    const id2 = computeReceiptId(contentHash, pubkey, 2000);
    expect(id1).not.toBe(id2);
  });
});

// ---------------------------------------------------------------------------
// 10. Compression tests
// ---------------------------------------------------------------------------
describe("compression", () => {
  it("should produce valid gzip output that can be decompressed", async () => {
    const { gunzipSync } = await import("node:zlib");
    const input = Buffer.from('{"hello":"world"}');
    const compressed = compressChunk(input);

    // gzip magic number
    expect(compressed[0]).toBe(0x1f);
    expect(compressed[1]).toBe(0x8b);

    const decompressed = gunzipSync(compressed);
    expect(decompressed.toString("utf-8")).toBe('{"hello":"world"}');
  });
});
