import hashlib
from typing import List


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """Compute SHA-256 Merkle root from a list of leaf hashes.

    Uses standard binary Merkle tree construction:
    - If odd number of leaves, duplicate the last leaf
    - Concatenate pairs and hash: H(left || right)
    - Repeat until single root remains
    """
    if not leaf_hashes:
        return b'\x00' * 32

    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    nodes = list(leaf_hashes)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # duplicate last
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            next_level.append(sha256(combined))
        nodes = next_level

    return nodes[0]
