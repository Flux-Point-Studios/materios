"""
Verification Index — writes the full chain-of-custody record when a
checkpoint is anchored, so the explorer can verify instantly without
scanning blocks.

Records are stored as JSON files keyed by receipt_id on the blob
gateway's PVC. The explorer reads them via a new API endpoint.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

VERIFICATION_DIR = "/data/verification-index"


def ensure_dir():
    Path(VERIFICATION_DIR).mkdir(parents=True, exist_ok=True)


def write_verification_record(
    receipt_id: str,
    cert_hash: str,
    leaf_hash: str,
    anchor_id: str,
    merkle_root: str,
    cardano_tx_hash: str,
    anchor_block: int,
    checkpoint_batch_size: int,
):
    """Write a complete verification record for a receipt."""
    ensure_dir()
    clean_id = receipt_id.replace("0x", "")
    record = {
        "receipt_id": receipt_id,
        "cert_hash": cert_hash,
        "leaf_hash": leaf_hash,
        "anchor_id": anchor_id,
        "merkle_root": merkle_root,
        "cardano_tx_hash": cardano_tx_hash,
        "anchor_block": anchor_block,
        "checkpoint_batch_size": checkpoint_batch_size,
        "verified_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    path = os.path.join(VERIFICATION_DIR, f"{clean_id}.json")
    with open(path, "w") as f:
        json.dump(record, f)
    logger.info(f"Verification record written for {receipt_id[:16]}...")


def read_verification_record(receipt_id: str) -> Optional[dict]:
    """Read a verification record for a receipt, or None if not indexed."""
    clean_id = receipt_id.replace("0x", "")
    path = os.path.join(VERIFICATION_DIR, f"{clean_id}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def write_batch_records(
    receipt_ids: list[str],
    leaf_hashes: list[str],
    cert_hashes: list[str],
    anchor_id: str,
    merkle_root: str,
    cardano_tx_hash: str,
    anchor_block: int,
):
    """Write verification records for all receipts in a checkpoint batch."""
    for i, rid in enumerate(receipt_ids):
        write_verification_record(
            receipt_id=rid,
            cert_hash=cert_hashes[i] if i < len(cert_hashes) else "",
            leaf_hash=leaf_hashes[i] if i < len(leaf_hashes) else "",
            anchor_id=anchor_id,
            merkle_root=merkle_root,
            cardano_tx_hash=cardano_tx_hash,
            anchor_block=anchor_block,
            checkpoint_batch_size=len(receipt_ids),
        )
    logger.info(
        f"Wrote {len(receipt_ids)} verification records for anchor {anchor_id[:16]}..."
    )
