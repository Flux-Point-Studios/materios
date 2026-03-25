/**
 * A single JSONL line after RFC 8785 JCS canonicalization.
 */
export interface CanonicalLine {
  index: number;
  canonical: string;
  bytes: Buffer;
}

/**
 * A chunk of canonical lines grouped for storage.
 */
export interface Chunk {
  index: number;
  lines: CanonicalLine[];
  canonicalBytes: Buffer;
}

/**
 * Hash digests for a single chunk.
 * canonicalSha256 is computed from the canonical bytes (pre-compression).
 * blobSha256 is computed from the stored blob (post-compression, possibly encrypted).
 */
export interface ChunkHashes {
  chunkIndex: number;
  canonicalSha256: string;
  blobSha256: string;
}

/**
 * Merkle tree structure with leaves, root, and optional proofs.
 */
export interface MerkleTree {
  leaves: string[];
  root: string;
  proof?: string[][];
}

/**
 * A single entry in the manifest corresponding to one chunk.
 */
export interface ManifestEntry {
  chunkIndex: number;
  canonicalSha256: string;
  blobSha256: string;
  byteSize: number;
  lineCount: number;
  codec: string;
  encrypted: boolean;
}

/**
 * The full manifest describing all chunks and their integrity hashes.
 */
export interface Manifest {
  version: string;
  schemaHash: string;
  entries: ManifestEntry[];
  baseRootSha256: string;
  zkRootPoseidon: string | null;
  poseidonParamsHash: string | null;
}

/**
 * The final receipt object — the top-level integrity anchor.
 */
export interface Receipt {
  receiptId: string;
  contentHash: string;
  baseRootSha256: string;
  zkRootPoseidon: string | null;
  poseidonParamsHash: string | null;
  baseManifestHash: string;
  safetyManifestHash: string;
  monitorConfigHash: string;
  attestationEvidenceHash: string;
  storageLocatorHash: string;
  availabilityCertHash: string;
  schemaHash: string;
  observedAtMillis: number;
}

/**
 * Options for the receipt-builder pipeline.
 */
export interface PipelineOptions {
  input: string;
  output: string;
  chunkSize?: number;
  encryptKey?: string;
  skipPoseidon?: boolean;
}

/**
 * Interface for Poseidon hash operations.
 */
export interface PoseidonHasher {
  hash(inputs: bigint[]): bigint;
  paramsHash(): string;
}
