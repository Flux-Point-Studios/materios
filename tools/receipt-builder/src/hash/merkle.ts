import { sha256, sha256Bytes } from "./sha256.js";
import type { MerkleTree } from "../types.js";

/**
 * Build a Merkle tree from an array of leaf hex strings.
 *
 * Algorithm — byte-for-byte identical to cert-daemon's `daemon/merkle.py`,
 * which is the consensus source of truth for the on-chain
 * `base_root_sha256` field:
 *
 *   - 0 leaves:                root = 32 zero bytes (Python: `b'\\x00' * 32`)
 *   - 1 leaf:                  root = that leaf, returned as-is (no hashing)
 *   - N > 1:                   pair `sha256(left || right)` as RAW bytes
 *                              (NOT hex-string concat); duplicate last on
 *                              odd levels; recurse upward.
 *
 * The previous implementation used `sha256(a + b)` over hex-string concat,
 * which produces a different value than cert-daemon for any tree with more
 * than one leaf. The 1-leaf case coincidentally worked because of the
 * `return leaves[0]` shortcut.
 *
 * Note on `hashFn`: kept for API compat (e.g. the test suite passing a
 * reversed-order hash). Default still uses cert-daemon-canonical raw-byte
 * concat. Pass a custom `hashFn` only if you need a non-canonical tree.
 */
export function buildMerkleTree(
  leaves: string[],
  hashFn?: (a: string, b: string) => string,
): MerkleTree {
  // Default: cert-daemon-canonical raw-byte concat then sha256.
  const hash =
    hashFn ??
    ((a: string, b: string) =>
      sha256Bytes(Buffer.concat([Buffer.from(a, "hex"), Buffer.from(b, "hex")]))
        .toString("hex"));

  if (leaves.length === 0) {
    // cert-daemon returns 32 zero bytes for empty input. Keeping the legacy
    // `sha256("")` here would silently disagree with the chain-side check.
    return {
      leaves: [],
      root: "0".repeat(64),
    };
  }

  if (leaves.length === 1) {
    return {
      leaves: [...leaves],
      root: leaves[0],
    };
  }

  // Build tree bottom-up
  let currentLevel = [...leaves];

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];

    // If odd number, duplicate last element
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }

    for (let i = 0; i < currentLevel.length; i += 2) {
      nextLevel.push(hash(currentLevel[i], currentLevel[i + 1]));
    }

    currentLevel = nextLevel;
  }

  return {
    leaves: [...leaves],
    root: currentLevel[0],
  };
}

// `sha256` is re-imported here only for backward compatibility for callers
// that imported it from this module. Nothing in this file uses it anymore.
void sha256;
