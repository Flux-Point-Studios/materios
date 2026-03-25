/**
 * Utility functions for the Midnight client.
 *
 * Provides hex/byte conversions and environment variable helpers
 * used across all client scripts.
 */

/**
 * Convert a hex string to a Uint8Array.
 *
 * @param hex - Hex-encoded string (with or without 0x prefix)
 * @returns Uint8Array of decoded bytes
 * @throws Error if the input contains invalid hex characters or has odd length
 */
export function hexToBytes(hex: string): Uint8Array {
  // Strip optional 0x prefix
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;

  if (cleaned.length % 2 !== 0) {
    throw new Error(`Hex string must have even length, got ${cleaned.length}`);
  }

  if (!/^[0-9a-fA-F]*$/.test(cleaned)) {
    throw new Error('Hex string contains invalid characters');
  }

  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a hex string.
 *
 * @param bytes - Byte array to encode
 * @returns Lowercase hex-encoded string (no 0x prefix)
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Get a required environment variable or throw an error.
 *
 * @param name - Name of the environment variable
 * @returns The environment variable value
 * @throws Error if the variable is not set or is empty
 */
export function assertEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Required environment variable ${name} is not set. ` +
        `Please set it before running this script.`
    );
  }
  return value;
}
