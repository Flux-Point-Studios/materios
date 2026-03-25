import { poseidon2 } from "poseidon-lite";
import { sha256 } from "./sha256.js";
import type { PoseidonHasher } from "../types.js";

/**
 * Poseidon hasher implementation using poseidon-lite (BN254, t=3).
 */
export const poseidonHasher: PoseidonHasher = {
  hash(inputs: bigint[]): bigint {
    return poseidonHash(inputs);
  },
  paramsHash(): string {
    return poseidonParamsHash();
  },
};

/**
 * Compute Poseidon hash over an array of bigint inputs.
 * Uses poseidon2 (t=3, BN254) — processes pairs of inputs iteratively.
 */
export function poseidonHash(inputs: bigint[]): bigint {
  if (inputs.length === 0) {
    return poseidon2([BigInt(0), BigInt(0)]);
  }

  if (inputs.length === 1) {
    return poseidon2([inputs[0], BigInt(0)]);
  }

  // Hash pairs iteratively: fold left
  let acc = poseidon2([inputs[0], inputs[1]]);
  for (let i = 2; i < inputs.length; i++) {
    acc = poseidon2([acc, inputs[i]]);
  }

  return acc;
}

/**
 * SHA-256 of the canonical Poseidon parameter string.
 */
export function poseidonParamsHash(): string {
  return sha256("poseidon-lite:bn254:t3:v0.3.0");
}

/**
 * Split a buffer into 31-byte chunks and convert each to a bigint.
 * 31 bytes ensures the value fits within the BN254 scalar field.
 */
export function bufferToPoseidonInputs(buf: Buffer): bigint[] {
  const inputs: bigint[] = [];
  const chunkSize = 31;

  for (let offset = 0; offset < buf.length; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, buf.length);
    const slice = buf.subarray(offset, end);
    // Convert bytes to bigint (big-endian)
    let value = BigInt(0);
    for (const byte of slice) {
      value = (value << BigInt(8)) | BigInt(byte);
    }
    inputs.push(value);
  }

  return inputs;
}

/**
 * Hash a buffer's contents using Poseidon, returning a hex string.
 */
export function poseidonHashBuffer(buf: Buffer): string {
  const inputs = bufferToPoseidonInputs(buf);
  const result = poseidonHash(inputs);
  return result.toString(16).padStart(64, "0");
}
