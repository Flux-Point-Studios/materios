import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96-bit IV for GCM

/**
 * Encrypt data using AES-256-GCM.
 *
 * @param data - The plaintext data to encrypt
 * @param keyHex - The AES-256 key as a hex string (64 hex chars = 32 bytes)
 * @returns The encrypted buffer, IV (hex), and auth tag (hex)
 */
export function encryptBlob(
  data: Buffer,
  keyHex: string,
): { encrypted: Buffer; iv: string; authTag: string } {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    throw new Error(
      `Invalid key length: expected 32 bytes, got ${key.length}`,
    );
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
  };
}

/**
 * Decrypt data using AES-256-GCM.
 *
 * @param encrypted - The ciphertext buffer
 * @param keyHex - The AES-256 key as a hex string
 * @param ivHex - The IV as a hex string
 * @param authTagHex - The auth tag as a hex string
 * @returns The decrypted plaintext buffer
 */
export function decryptBlob(
  encrypted: Buffer,
  keyHex: string,
  ivHex: string,
  authTagHex: string,
): Buffer {
  const key = Buffer.from(keyHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
