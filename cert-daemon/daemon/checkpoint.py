"""Cardano L1 checkpointing for Materios availability certificates.

Collects certified receipts into batches, computes a Merkle root with
context-bound leaves, and submits the root to Cardano via the anchor worker.

Leaf binding prevents replay/mixing:
    leaf_i = SHA256(b"materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)

Crash-proof: pending leaves and last checkpoint block are persisted to a
JSON state file on PVC so nothing is lost across daemon restarts.
"""

import hashlib
import json
import logging
import math
import os
import time
from datetime import datetime
from typing import Optional

import requests

from daemon.config import DaemonConfig

logger = logging.getLogger(__name__)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Compute SHA-256 Merkle root from a list of leaf hashes."""
    if not leaves:
        return b"\x00" * 32
    if len(leaves) == 1:
        return leaves[0]

    # Pad to even length by duplicating last leaf
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_sha256(layer[i] + layer[i + 1]))
        layer = next_layer
    return layer[0]


class CardanoCheckpointer:
    """Batches certified receipts and periodically checkpoints to Cardano."""

    def __init__(self, config: DaemonConfig, state_file: str):
        self.config = config
        self.batch_size = config.checkpoint_batch_size
        self.interval_minutes = config.checkpoint_interval
        self.state_file = state_file
        self.pending_leaves: list[dict] = []
        self.last_checkpointed_block: int = 0
        self.last_flush_time: float = 0.0
        self._load_state()

    def _load_state(self):
        """Restore pending list + last checkpoint block from PVC."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    state = json.load(f)
                self.pending_leaves = state.get("pending_leaves", [])
                self.last_checkpointed_block = state.get("last_checkpointed_block", 0)
                self.last_flush_time = state.get("last_flush_time", 0.0)
                logger.info(
                    f"Checkpoint state loaded: {len(self.pending_leaves)} pending, "
                    f"last_block={self.last_checkpointed_block}"
                )
            except Exception as e:
                logger.warning(f"Failed to load checkpoint state: {e}")

    def _save_state(self):
        """Persist to PVC — survives daemon restart."""
        try:
            tmp = self.state_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(
                    {
                        "pending_leaves": self.pending_leaves,
                        "last_checkpointed_block": self.last_checkpointed_block,
                        "last_flush_time": self.last_flush_time,
                    },
                    f,
                )
            os.replace(tmp, self.state_file)
        except Exception as e:
            logger.error(f"Failed to save checkpoint state: {e}")

    def add_cert(self, receipt_id: str, cert_hash: bytes, block_num: int):
        """Add a certified receipt to the pending batch."""
        self.pending_leaves.append(
            {
                "receipt_id": receipt_id,
                "cert_hash": cert_hash.hex(),
                "block_num": block_num,
                "timestamp": time.time(),
            }
        )
        self._save_state()
        logger.debug(
            f"Checkpoint: added cert for {receipt_id[:16]}... "
            f"({len(self.pending_leaves)}/{self.batch_size})"
        )

    def should_flush(self) -> bool:
        """Check if a flush is due (time, batch-size, or leaf-age trigger)."""
        if not self.pending_leaves:
            return False
        # Batch size trigger
        if len(self.pending_leaves) >= self.batch_size:
            return True
        # Oldest leaf age trigger
        oldest_ts = min(
            leaf.get("timestamp", time.time()) for leaf in self.pending_leaves
        )
        if time.time() - oldest_ts > self.config.max_leaf_wait_seconds:
            return True
        # Time-based trigger
        if self.interval_minutes <= 0:
            return False
        elapsed = (time.time() - self.last_flush_time) / 60.0
        return elapsed >= self.interval_minutes

    def flush(self, current_best_block: int = 0) -> bool:
        """Build Merkle root and submit checkpoint to Cardano anchor worker.

        Only includes leaves confirmed by at least `finality_confirmations` blocks.
        Returns True if checkpoint was submitted successfully.
        """
        if not self.pending_leaves:
            return True

        if not self.config.cardano_anchor_url:
            logger.warning("Checkpoint flush skipped: CARDANO_ANCHOR_URL not configured")
            return False

        # Filter by confirmation depth
        confirmed_cutoff = current_best_block - self.config.finality_confirmations
        eligible = [l for l in self.pending_leaves if l["block_num"] <= confirmed_cutoff]
        if not eligible:
            logger.debug(
                f"Checkpoint: no leaves confirmed yet "
                f"(cutoff={confirmed_cutoff}, best={current_best_block})"
            )
            return True  # nothing confirmed enough yet

        chain_id_bytes = bytes.fromhex(self.config.chain_id)

        leaves = []
        for leaf in eligible:
            receipt_id_bytes = bytes.fromhex(leaf["receipt_id"].removeprefix("0x"))
            cert_hash_bytes = bytes.fromhex(leaf["cert_hash"])
            bound_leaf = _sha256(
                b"materios-checkpoint-v1" + chain_id_bytes + receipt_id_bytes + cert_hash_bytes
            )
            leaves.append(bound_leaf)

        root = merkle_root(leaves)
        from_block = min(l["block_num"] for l in eligible)
        to_block = max(l["block_num"] for l in eligible)
        count = len(leaves)

        logger.info(
            f"Checkpoint: flushing {count} leaves, blocks {from_block}-{to_block}, "
            f"root={root.hex()[:16]}..."
        )

        manifest = {
            "materios_chain_id": self.config.chain_id,
            "cardano_network_id": self.config.cardano_network_id,
            "from_block": from_block,
            "to_block": to_block,
            "count": count,
            "root": root.hex(),
        }
        manifest_hash = hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode()
        ).hexdigest()

        # Build batch metadata for anchor worker to post as backup
        batch_metadata = {
            "rootHash": root.hex(),
            "leafCount": len(leaves),
            "leafHashes": [lh.hex() for lh in leaves],
            "blockRangeStart": from_block,
            "blockRangeEnd": to_block,
            "submitter": self.config.signer_uri,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "daemon",
        }

        anchor_response = self._submit_to_cardano(root, manifest, manifest_hash, batch_metadata)

        if anchor_response is not None:
            leaf_hashes = [lh.hex() for lh in leaves]
            self._save_batch_history(eligible, leaves, root, manifest, manifest_hash)

            # Post batch metadata to blob gateway for SDK verification
            anchor_id = anchor_response.get("anchorId", "")
            if anchor_id:
                self._post_batch_metadata(anchor_id, root.hex(), eligible, leaf_hashes)

            self.last_checkpointed_block = to_block
            self.last_flush_time = time.time()
            # Remove only the eligible leaves; keep unconfirmed ones
            self.pending_leaves = [l for l in self.pending_leaves if l["block_num"] > confirmed_cutoff]
            self._save_state()
            logger.info(f"Checkpoint submitted: root={root.hex()[:16]}... ({count} certs)")
        else:
            logger.error("Checkpoint submission failed — will retry on next flush")

        return anchor_response is not None

    def _save_batch_history(
        self,
        eligible: list[dict],
        leaf_hashes: list[bytes],
        root: bytes,
        manifest: dict,
        manifest_hash: str,
    ):
        """Append completed batch to checkpoint-history.json for verification."""
        history_file = self.state_file.replace("checkpoint-state.json", "checkpoint-history.json")
        try:
            if os.path.exists(history_file):
                with open(history_file) as f:
                    history = json.load(f)
            else:
                history = []

            batch = {
                "timestamp": time.time(),
                "root_hash": root.hex(),
                "manifest_hash": manifest_hash,
                "manifest": manifest,
                "leaves": [
                    {
                        "receipt_id": e["receipt_id"],
                        "cert_hash": e["cert_hash"],
                        "block_num": e["block_num"],
                        "leaf_hash": lh.hex(),
                    }
                    for e, lh in zip(eligible, leaf_hashes)
                ],
            }
            history.append(batch)

            tmp = history_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(history, f, indent=2)
            os.replace(tmp, history_file)
            logger.debug(f"Batch history saved: {len(history)} batches total")
        except Exception as e:
            logger.warning(f"Failed to save batch history: {e}")

    def _post_batch_metadata(
        self,
        anchor_id: str,
        root_hash: str,
        eligible_leaves: list[dict],
        leaf_hashes: list[str],
    ):
        """Post batch metadata to blob gateway for SDK verification."""
        blob_gateway_url = self.config.blob_gateway_url or os.environ.get("BLOB_GATEWAY_URL", "")
        blob_gateway_api_key = self.config.blob_gateway_api_key or os.environ.get("BLOB_GATEWAY_API_KEY", "")

        if not blob_gateway_url:
            logger.debug("BLOB_GATEWAY_URL not set, skipping batch metadata post")
            return

        try:
            batch_metadata = {
                "anchorId": anchor_id,
                "rootHash": root_hash,
                "leafCount": len(leaf_hashes),
                "leafHashes": leaf_hashes,
                "blockRangeStart": min(leaf.get("block_num", 0) for leaf in eligible_leaves),
                "blockRangeEnd": max(leaf.get("block_num", 0) for leaf in eligible_leaves),
                "submitter": self.config.signer_uri,
                "timestamp": datetime.utcnow().isoformat(),
            }

            headers = {"Content-Type": "application/json"}
            if blob_gateway_api_key:
                headers["x-api-key"] = blob_gateway_api_key

            # Strip 0x prefix from anchor_id for URL path
            anchor_id_clean = anchor_id
            if anchor_id_clean.startswith("0x"):
                anchor_id_clean = anchor_id_clean[2:]

            resp = requests.post(
                f"{blob_gateway_url}/batches/{anchor_id_clean}",
                json=batch_metadata,
                headers=headers,
                timeout=10,
            )
            if resp.status_code in (200, 201):
                logger.info(f"Posted batch metadata for anchor {anchor_id[:16]}... to gateway")
            else:
                logger.warning(f"Failed to post batch metadata: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Error posting batch metadata to gateway: {e}")

    def _submit_to_cardano(
        self, root: bytes, manifest: dict, manifest_hash: str, batch_metadata: dict | None = None
    ) -> Optional[dict]:
        """POST checkpoint to the Cardano anchor worker.

        Returns the anchor response dict on success (containing anchorId, blockHash, etc.),
        or None on failure.
        """
        payload = {
            "contentHash": root.hex(),
            "rootHash": root.hex(),
            "manifestHash": manifest_hash,
        }
        if batch_metadata:
            payload["batchMetadata"] = batch_metadata

        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{self.config.cardano_anchor_url}/anchor",
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-internal-token": self.config.anchor_worker_token,
                    },
                    timeout=60,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    logger.info(f"Cardano checkpoint tx: {data}")
                    return data
                else:
                    logger.error(
                        f"Cardano anchor worker returned {resp.status_code}: {resp.text}"
                    )
            except Exception as e:
                logger.error(f"Checkpoint submit attempt {attempt + 1} failed: {e}")
                if attempt < 2:
                    time.sleep(2**attempt)

        return None
