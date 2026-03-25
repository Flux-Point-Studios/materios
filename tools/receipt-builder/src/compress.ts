import { gzipSync } from "node:zlib";

/**
 * Compress canonical bytes using gzip.
 * Compression happens AFTER hashing canonical bytes.
 */
export function compressChunk(canonicalBytes: Buffer): Buffer {
  return gzipSync(canonicalBytes);
}
