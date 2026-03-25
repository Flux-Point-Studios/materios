import { sha256, sha256Bytes } from "./hash/sha256.js";
import type { Receipt } from "./types.js";

const ZERO_HASH_BYTES = Buffer.alloc(32, 0);

/**
 * Compute the content hash from all receipt fields.
 *
 * SHA-256 of concatenation of all field hex strings converted to buffers.
 * For optional fields (zkRootPoseidon), use 32 zero bytes if null.
 */
export function computeContentHash(fields: {
  baseRootSha256: string;
  zkRootPoseidon: string | null;
  baseManifestHash: string;
  safetyManifestHash: string;
  monitorConfigHash: string;
  attestationEvidenceHash: string;
  storageLocatorHash: string;
  schemaHash: string;
}): string {
  const buffers = [
    Buffer.from(fields.baseRootSha256, "hex"),
    fields.zkRootPoseidon
      ? Buffer.from(fields.zkRootPoseidon, "hex")
      : ZERO_HASH_BYTES,
    Buffer.from(fields.baseManifestHash, "hex"),
    Buffer.from(fields.safetyManifestHash, "hex"),
    Buffer.from(fields.monitorConfigHash, "hex"),
    Buffer.from(fields.attestationEvidenceHash, "hex"),
    Buffer.from(fields.storageLocatorHash, "hex"),
    Buffer.from(fields.schemaHash, "hex"),
  ];

  return sha256(Buffer.concat(buffers));
}

/**
 * Compute a unique receipt ID.
 *
 * SHA-256(contentHash bytes || submitterPubkey bytes || createdAtMillis as 8-byte big-endian)
 */
export function computeReceiptId(
  contentHash: string,
  submitterPubkey: string,
  createdAtMillis: number,
): string {
  const contentBuf = Buffer.from(contentHash, "hex");
  const pubkeyBuf = Buffer.from(submitterPubkey, "hex");

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(BigInt(createdAtMillis));

  return sha256(Buffer.concat([contentBuf, pubkeyBuf, timeBuf]));
}

/**
 * Assemble a full Receipt object.
 */
export function buildReceipt(params: {
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
  submitterPubkey?: string;
}): Receipt {
  const contentHash = computeContentHash({
    baseRootSha256: params.baseRootSha256,
    zkRootPoseidon: params.zkRootPoseidon,
    baseManifestHash: params.baseManifestHash,
    safetyManifestHash: params.safetyManifestHash,
    monitorConfigHash: params.monitorConfigHash,
    attestationEvidenceHash: params.attestationEvidenceHash,
    storageLocatorHash: params.storageLocatorHash,
    schemaHash: params.schemaHash,
  });

  // Default submitter pubkey (placeholder — 32 zero bytes hex)
  const submitterPubkey =
    params.submitterPubkey ?? "0".repeat(64);

  const receiptId = computeReceiptId(
    contentHash,
    submitterPubkey,
    params.observedAtMillis,
  );

  return {
    receiptId,
    contentHash,
    baseRootSha256: params.baseRootSha256,
    zkRootPoseidon: params.zkRootPoseidon,
    poseidonParamsHash: params.poseidonParamsHash,
    baseManifestHash: params.baseManifestHash,
    safetyManifestHash: params.safetyManifestHash,
    monitorConfigHash: params.monitorConfigHash,
    attestationEvidenceHash: params.attestationEvidenceHash,
    storageLocatorHash: params.storageLocatorHash,
    availabilityCertHash: params.availabilityCertHash,
    schemaHash: params.schemaHash,
    observedAtMillis: params.observedAtMillis,
  };
}
