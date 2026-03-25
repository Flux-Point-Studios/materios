import fs from "node:fs";
import path from "node:path";
import { canonicalizeJsonl } from "./canonicalize.js";
import { chunkLines } from "./chunker.js";
import { sha256 } from "./hash/sha256.js";
import { poseidonHashBuffer, poseidonParamsHash } from "./hash/poseidon.js";
import { buildMerkleTree } from "./hash/merkle.js";
import { compressChunk } from "./compress.js";
import { encryptBlob } from "./encrypt.js";
import { buildManifest } from "./manifest.js";
import { buildReceipt } from "./receipt.js";
import type { ChunkHashes, PipelineOptions, Receipt } from "./types.js";

// Schema definition for receipt version 1
const SCHEMA_VERSION = "materios-receipt-v1";
const SCHEMA_FIELDS =
  "receiptId,contentHash,baseRootSha256,zkRootPoseidon,poseidonParamsHash," +
  "baseManifestHash,safetyManifestHash,monitorConfigHash," +
  "attestationEvidenceHash,storageLocatorHash,availabilityCertHash," +
  "schemaHash,observedAtMillis";

/**
 * Run the full receipt-builder pipeline.
 *
 * Steps:
 *  1. Read input JSONL file
 *  2. Canonicalize each line (RFC 8785 JCS)
 *  3. Chunk canonical lines (64KB target)
 *  4. Hash CANONICAL chunk bytes (SHA-256 always, Poseidon if not skipped)
 *  5. Build Merkle trees from chunk hashes
 *  6. Compute content_hash (deterministic)
 *  7. Compress chunks (gzip -- storage only)
 *  8. Encrypt compressed blobs if encryptKey provided (storage only)
 *  9. Compute blob_sha256 for each stored blob
 * 10. Build manifest with both canonical_sha256 and blob_sha256
 * 11. Compute schema_hash
 * 12. Compute receipt_id (unique per run -- uses Date.now())
 * 13. Write output: blobs/, manifest.json, receipt.json
 * 14. Return receipt
 */
export async function runPipeline(options: PipelineOptions): Promise<Receipt> {
  const {
    input,
    output,
    chunkSize = 65536,
    encryptKey,
    skipPoseidon = false,
  } = options;

  // 1. Read input JSONL
  const rawInput = fs.readFileSync(input, "utf-8");

  // 2. Canonicalize each line
  const canonicalLines = canonicalizeJsonl(rawInput);

  // 3. Chunk canonical lines
  const chunks = chunkLines(canonicalLines, chunkSize);

  // 4. Hash canonical chunk bytes
  const chunkHashes: ChunkHashes[] = chunks.map((chunk) => ({
    chunkIndex: chunk.index,
    canonicalSha256: sha256(chunk.canonicalBytes),
    blobSha256: "", // filled after compression
  }));

  // 5. Build Merkle trees
  const sha256Leaves = chunkHashes.map((h) => h.canonicalSha256);
  const sha256Tree = buildMerkleTree(sha256Leaves);

  let zkRootPoseidon: string | null = null;
  let poseidonParams: string | null = null;

  if (!skipPoseidon) {
    const poseidonLeaves = chunks.map((chunk) =>
      poseidonHashBuffer(chunk.canonicalBytes),
    );
    // Build Poseidon Merkle tree using SHA-256 as the tree hash
    // (Poseidon is used at the leaf level, SHA-256 for the tree structure)
    const poseidonTree = buildMerkleTree(poseidonLeaves);
    zkRootPoseidon = poseidonTree.root;
    poseidonParams = poseidonParamsHash();
  }

  // 6. Schema hash
  const schemaHash = sha256(SCHEMA_VERSION + SCHEMA_FIELDS);

  // 7. Compress chunks
  const compressedBlobs = chunks.map((chunk) =>
    compressChunk(chunk.canonicalBytes),
  );

  // 8. Encrypt if key provided
  const encrypted = encryptKey !== undefined;
  const storedBlobs: Buffer[] = [];
  const encryptionMeta: Array<{ iv: string; authTag: string } | null> = [];

  for (const blob of compressedBlobs) {
    if (encryptKey) {
      const result = encryptBlob(blob, encryptKey);
      storedBlobs.push(result.encrypted);
      encryptionMeta.push({ iv: result.iv, authTag: result.authTag });
    } else {
      storedBlobs.push(blob);
      encryptionMeta.push(null);
    }
  }

  // 9. Compute blob_sha256 for stored blobs
  for (let i = 0; i < storedBlobs.length; i++) {
    chunkHashes[i].blobSha256 = sha256(storedBlobs[i]);
  }

  // 10. Build manifest
  const manifest = buildManifest(chunks, chunkHashes, {
    baseRootSha256: sha256Tree.root,
    zkRootPoseidon,
    poseidonParamsHash: poseidonParams,
    schemaHash,
    encrypted,
  });

  // Serialize manifest for hashing
  const manifestJson = JSON.stringify(manifest, null, 2);
  const baseManifestHash = sha256(manifestJson);

  // Placeholder hashes for fields not yet implemented
  const safetyManifestHash = sha256("safety-manifest-placeholder");
  const monitorConfigHash = sha256("monitor-config-placeholder");
  const attestationEvidenceHash = sha256("attestation-evidence-placeholder");
  const storageLocatorHash = sha256("storage-locator-placeholder");
  const availabilityCertHash = sha256("availability-cert-placeholder");

  // 11-12. Build receipt
  const observedAtMillis = Date.now();

  const receipt = buildReceipt({
    baseRootSha256: sha256Tree.root,
    zkRootPoseidon,
    poseidonParamsHash: poseidonParams,
    baseManifestHash,
    safetyManifestHash,
    monitorConfigHash,
    attestationEvidenceHash,
    storageLocatorHash,
    availabilityCertHash,
    schemaHash,
    observedAtMillis,
  });

  // 13. Write output
  const blobsDir = path.join(output, "blobs");
  fs.mkdirSync(blobsDir, { recursive: true });

  // Write blobs
  for (let i = 0; i < storedBlobs.length; i++) {
    const filename = `chunk-${String(i).padStart(4, "0")}.bin`;
    fs.writeFileSync(path.join(blobsDir, filename), storedBlobs[i]);

    // Write encryption metadata alongside blob if encrypted
    if (encryptionMeta[i]) {
      const metaFilename = `chunk-${String(i).padStart(4, "0")}.meta.json`;
      fs.writeFileSync(
        path.join(blobsDir, metaFilename),
        JSON.stringify(encryptionMeta[i], null, 2),
      );
    }
  }

  // Write manifest
  fs.writeFileSync(path.join(output, "manifest.json"), manifestJson);

  // Write receipt
  fs.writeFileSync(
    path.join(output, "receipt.json"),
    JSON.stringify(receipt, null, 2),
  );

  // 14. Return receipt
  return receipt;
}
