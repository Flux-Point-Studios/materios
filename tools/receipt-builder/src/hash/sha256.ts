import { createHash } from "node:crypto";

/**
 * Compute SHA-256 hash of the given data, returning a hex string.
 */
export function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Compute SHA-256 hash of the given data, returning a raw Buffer.
 */
export function sha256Bytes(data: Buffer | string): Buffer {
  return createHash("sha256").update(data).digest();
}
