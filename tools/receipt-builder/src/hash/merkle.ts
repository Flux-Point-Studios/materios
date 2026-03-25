import { sha256 } from "./sha256.js";
import type { MerkleTree } from "../types.js";

/**
 * Build a Merkle tree from an array of leaf hex strings.
 *
 * Default hash function: sha256(a + b) where a and b are hex strings concatenated.
 *
 * Edge cases:
 * - 0 leaves: root = sha256 of empty string
 * - 1 leaf: root = that leaf
 * - Odd number of leaves at any level: duplicate the last leaf
 */
export function buildMerkleTree(
  leaves: string[],
  hashFn?: (a: string, b: string) => string,
): MerkleTree {
  const hash = hashFn ?? ((a: string, b: string) => sha256(a + b));

  if (leaves.length === 0) {
    return {
      leaves: [],
      root: sha256(""),
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
