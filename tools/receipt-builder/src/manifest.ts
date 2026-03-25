import type { Chunk, ChunkHashes, Manifest, ManifestEntry } from "./types.js";

/**
 * Build a manifest from chunks and their hashes.
 *
 * Each entry includes:
 * - canonicalSha256: hash of canonical bytes (Merkle leaf, pre-compression)
 * - blobSha256: hash of stored blob (post-compression, possibly encrypted)
 */
export function buildManifest(
  chunks: Chunk[],
  chunkHashes: ChunkHashes[],
  options: {
    baseRootSha256: string;
    zkRootPoseidon: string | null;
    poseidonParamsHash: string | null;
    schemaHash: string;
    encrypted?: boolean;
  },
): Manifest {
  const entries: ManifestEntry[] = chunks.map((chunk) => {
    const hashes = chunkHashes.find((h) => h.chunkIndex === chunk.index);
    if (!hashes) {
      throw new Error(
        `Missing hashes for chunk index ${chunk.index}`,
      );
    }

    return {
      chunkIndex: chunk.index,
      canonicalSha256: hashes.canonicalSha256,
      blobSha256: hashes.blobSha256,
      byteSize: chunk.canonicalBytes.length,
      lineCount: chunk.lines.length,
      codec: "gzip",
      encrypted: options.encrypted ?? false,
    };
  });

  return {
    version: "0.1.0",
    schemaHash: options.schemaHash,
    entries,
    baseRootSha256: options.baseRootSha256,
    zkRootPoseidon: options.zkRootPoseidon,
    poseidonParamsHash: options.poseidonParamsHash,
  };
}
