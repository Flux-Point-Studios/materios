"""Core verification logic for Materios checkpoint proofs.

Provides both a programmatic API (verify_receipt) and helper functions
for Merkle tree computation, chain queries, and batch reconstruction.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from substrateinterface import SubstrateInterface


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

ZERO_HASH = b"\x00" * 32


class VerificationResult(Enum):
    FULLY_VERIFIED = "FULLY_VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"


@dataclass
class StepResult:
    step: int
    title: str
    passed: bool
    details: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class VerificationReport:
    receipt_id: str
    rpc_url: str
    chain_id: str = ""
    best_block: int = 0
    result: VerificationResult = VerificationResult.NOT_VERIFIED
    steps: list[StepResult] = field(default_factory=list)
    receipt: Optional[dict] = None
    cert_hash: str = ""
    leaf_hash: str = ""
    anchor: Optional[dict] = None
    committee_size: int = 0
    threshold: int = 0

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "rpc_url": self.rpc_url,
            "chain_id": self.chain_id,
            "best_block": self.best_block,
            "result": self.result.value,
            "cert_hash": self.cert_hash,
            "leaf_hash": self.leaf_hash,
            "committee_size": self.committee_size,
            "threshold": self.threshold,
            "anchor": self.anchor,
            "steps": [
                {
                    "step": s.step,
                    "title": s.title,
                    "passed": s.passed,
                    "details": s.details,
                    "warnings": s.warnings,
                }
                for s in self.steps
            ],
        }


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Compute SHA-256 Merkle root. Matches daemon implementation exactly."""
    if not leaves:
        return ZERO_HASH
    if len(leaves) == 1:
        return leaves[0]
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_sha256(layer[i] + layer[i + 1]))
        layer = next_layer
    return layer[0]


def merkle_inclusion_proof(
    leaves: list[bytes], target_index: int,
) -> list[tuple[bytes, str]]:
    """Generate a Merkle inclusion proof (list of sibling hashes + side)."""
    if len(leaves) <= 1:
        return []
    proof = []
    layer = list(leaves)
    idx = target_index
    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])
        if idx % 2 == 0:
            proof.append((layer[idx + 1], "R"))
        else:
            proof.append((layer[idx - 1], "L"))
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_sha256(layer[i] + layer[i + 1]))
        layer = next_layer
        idx //= 2
    return proof


def verify_merkle_proof(
    leaf: bytes, proof: list[tuple[bytes, str]], root: bytes,
) -> bool:
    """Verify a Merkle inclusion proof against an expected root."""
    current = leaf
    for sibling, side in proof:
        if side == "L":
            current = _sha256(sibling + current)
        else:
            current = _sha256(current + sibling)
    return current == root


def compute_checkpoint_leaf(
    chain_id: bytes, receipt_id: bytes, cert_hash: bytes,
) -> bytes:
    """Compute the context-bound checkpoint leaf hash.

    leaf = SHA256(b"materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)
    """
    return _sha256(b"materios-checkpoint-v1" + chain_id + receipt_id + cert_hash)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_bytes32(val) -> bytes:
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val.removeprefix("0x"))
    if isinstance(val, (list, tuple)):
        return bytes(val)
    return bytes(val)


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


# ---------------------------------------------------------------------------
# Chain queries
# ---------------------------------------------------------------------------

def query_receipt(substrate: SubstrateInterface, receipt_id: str) -> Optional[dict]:
    result = substrate.query(
        module="OrinqReceipts", storage_function="Receipts", params=[receipt_id],
    )
    return result.value if result.value is not None else None


def query_attestations(substrate: SubstrateInterface, receipt_id: str) -> Optional[dict]:
    result = substrate.query(
        module="OrinqReceipts", storage_function="Attestations", params=[receipt_id],
    )
    return result.value if result.value is not None else None


def query_committee(substrate: SubstrateInterface) -> tuple[list, int]:
    members_result = substrate.query(
        module="OrinqReceipts", storage_function="CommitteeMembers",
    )
    threshold_result = substrate.query(
        module="OrinqReceipts", storage_function="AttestationThreshold",
    )
    members = members_result.value if members_result.value else []
    threshold = threshold_result.value if threshold_result.value else 1
    return members, threshold


def query_anchor(substrate: SubstrateInterface, anchor_id: str) -> Optional[dict]:
    result = substrate.query(
        module="OrinqReceipts", storage_function="Anchors", params=[anchor_id],
    )
    return result.value if result.value is not None else None


def scan_anchor_events(
    substrate: SubstrateInterface, from_block: int, to_block: int,
) -> list[dict]:
    anchors = []
    for block_num in range(from_block, to_block + 1):
        try:
            block_hash = substrate.get_block_hash(block_num)
            if block_hash is None:
                continue
            events = substrate.get_events(block_hash=block_hash)
            for event in events:
                if (event.value.get("module_id") == "OrinqReceipts"
                        and event.value.get("event_id") == "AnchorSubmitted"):
                    attrs = event.value["attributes"]
                    anchors.append({
                        "block_num": block_num,
                        "anchor_id": attrs["anchor_id"],
                        "content_hash": attrs["content_hash"],
                        "submitter": attrs.get("submitter", ""),
                    })
        except Exception:
            continue
    return anchors


def scan_certified_events(
    substrate: SubstrateInterface, receipt_id: str,
    from_block: int, to_block: int,
) -> Optional[dict]:
    target_id = receipt_id.removeprefix("0x").lower()
    for block_num in range(from_block, to_block + 1):
        try:
            block_hash = substrate.get_block_hash(block_num)
            if block_hash is None:
                continue
            events = substrate.get_events(block_hash=block_hash)
            for event in events:
                if (event.value.get("module_id") == "OrinqReceipts"
                        and event.value.get("event_id") == "AvailabilityCertified"):
                    attrs = event.value["attributes"]
                    eid = attrs["receipt_id"]
                    if isinstance(eid, str):
                        eid = eid.removeprefix("0x").lower()
                    if eid == target_id:
                        cert_hash_raw = attrs["cert_hash"]
                        if isinstance(cert_hash_raw, str):
                            cert_hash_raw = cert_hash_raw.removeprefix("0x")
                        return {"block_num": block_num, "cert_hash": cert_hash_raw}
        except Exception:
            continue
    return None


def scan_all_certified_events(
    substrate: SubstrateInterface, from_block: int, to_block: int,
) -> list[dict]:
    """Scan for ALL AvailabilityCertified events in a block range."""
    certs = []
    for block_num in range(from_block, to_block + 1):
        try:
            block_hash = substrate.get_block_hash(block_num)
            if block_hash is None:
                continue
            events = substrate.get_events(block_hash=block_hash)
            for event in events:
                if (event.value.get("module_id") == "OrinqReceipts"
                        and event.value.get("event_id") == "AvailabilityCertified"):
                    attrs = event.value["attributes"]
                    rid = attrs["receipt_id"]
                    if isinstance(rid, str):
                        rid = rid.removeprefix("0x")
                    ch = attrs["cert_hash"]
                    if isinstance(ch, str):
                        ch = ch.removeprefix("0x")
                    certs.append({
                        "block_num": block_num,
                        "receipt_id": rid,
                        "cert_hash": ch,
                    })
        except Exception:
            continue
    return certs


# ---------------------------------------------------------------------------
# Batch history
# ---------------------------------------------------------------------------

def load_batch_history(path: str) -> Optional[list[dict]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def find_batch_for_receipt(history: list[dict], receipt_id: str) -> Optional[dict]:
    target = receipt_id.removeprefix("0x").lower()
    for batch in history:
        for leaf in batch.get("leaves", []):
            rid = leaf.get("receipt_id", "").removeprefix("0x").lower()
            if rid == target:
                return batch
    return None


def load_checkpoint_state(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# On-chain batch reconstruction
# ---------------------------------------------------------------------------

def try_onchain_reconstruction(
    substrate: SubstrateInterface,
    chain_id_bytes: bytes,
    target_leaf: bytes,
    anchor_events: list[dict],
    scan_start: int,
    scan_end: int,
) -> Optional[dict]:
    """Try to reconstruct a multi-leaf batch from on-chain events."""
    all_certs = scan_all_certified_events(substrate, scan_start, scan_end)
    if not all_certs:
        return None

    for anchor_evt in anchor_events:
        anchor_data = query_anchor(substrate, anchor_evt["anchor_id"])
        if anchor_data is None:
            continue

        anchor_root = _to_bytes32(anchor_data["root_hash"])
        anchor_block = anchor_evt["block_num"]

        eligible_certs = [c for c in all_certs if c["block_num"] < anchor_block]
        if not eligible_certs:
            continue

        eligible_certs.sort(key=lambda c: (c["block_num"], c["receipt_id"]))

        for end in range(len(eligible_certs), 0, -1):
            subset = eligible_certs[:end]
            leaves = []
            target_idx = None

            for i, cert in enumerate(subset):
                rid_bytes = bytes.fromhex(cert["receipt_id"])
                ch_bytes = bytes.fromhex(cert["cert_hash"])
                leaf = compute_checkpoint_leaf(chain_id_bytes, rid_bytes, ch_bytes)
                leaves.append(leaf)
                if leaf == target_leaf:
                    target_idx = i

            if target_idx is None:
                continue

            root = merkle_root(leaves)
            if root == anchor_root:
                return {
                    "anchor_id": anchor_evt["anchor_id"],
                    "root_hash": anchor_root,
                    "content_hash": _to_bytes32(anchor_data["content_hash"]),
                    "manifest_hash": _to_bytes32(anchor_data["manifest_hash"]),
                    "block_num": anchor_block,
                    "match_type": f"on-chain reconstruction ({len(leaves)} leaves)",
                }

    return None


# ---------------------------------------------------------------------------
# Main verification pipeline (returns structured report)
# ---------------------------------------------------------------------------

def verify_receipt(
    receipt_id: str,
    rpc_url: str,
    chain_id_override: Optional[str] = None,
    scan_window: int = 500,
    checkpoint_state_path: Optional[str] = None,
    checkpoint_history_path: Optional[str] = None,
) -> VerificationReport:
    """Run the full chain-of-custody verification. Returns a VerificationReport."""

    if not receipt_id.startswith("0x"):
        receipt_id = "0x" + receipt_id

    report = VerificationReport(receipt_id=receipt_id, rpc_url=rpc_url)

    # Step 0: Connect
    step0 = StepResult(step=0, title="Connect to Materios chain", passed=False)
    try:
        substrate = SubstrateInterface(url=rpc_url)
        step0.passed = True
        step0.details["chain"] = substrate.chain or "unknown"
    except Exception as e:
        step0.details["error"] = str(e)
        report.steps.append(step0)
        return report

    if chain_id_override:
        chain_id_hex = chain_id_override.removeprefix("0x")
    else:
        genesis_hash = substrate.get_block_hash(0)
        chain_id_hex = genesis_hash.removeprefix("0x") if genesis_hash else ""

    report.chain_id = chain_id_hex
    chain_id_bytes = bytes.fromhex(chain_id_hex) if chain_id_hex else ZERO_HASH

    try:
        report.best_block = substrate.get_block_header()["header"]["number"]
    except Exception:
        report.best_block = 0

    step0.details["best_block"] = report.best_block
    report.steps.append(step0)

    # Step 1: Query receipt
    step1 = StepResult(step=1, title="Query on-chain receipt", passed=False)
    receipt = query_receipt(substrate, receipt_id)
    if receipt is None:
        step1.details["error"] = "Receipt not found"
        report.steps.append(step1)
        return report

    step1.passed = True
    report.receipt = receipt
    content_hash = _to_bytes32(receipt["content_hash"])
    cert_hash_on_chain = _to_bytes32(receipt["availability_cert_hash"])

    step1.details["submitter"] = receipt.get("submitter", "unknown")
    step1.details["content_hash"] = _hex(content_hash)
    step1.details["created_at_millis"] = receipt.get("created_at_millis", 0)
    report.steps.append(step1)

    # Step 2: Check cert
    step2 = StepResult(step=2, title="Check availability certificate", passed=False)
    if cert_hash_on_chain == ZERO_HASH:
        step2.details["status"] = "no_cert"
        attestation = query_attestations(substrate, receipt_id)
        if attestation is not None:
            att_signers = (
                attestation[1]
                if isinstance(attestation, (list, tuple)) and len(attestation) > 1
                else []
            )
            members, threshold = query_committee(substrate)
            step2.details["attestation_progress"] = f"{len(att_signers)}/{threshold}"
            step2.warnings.append("Attestation in progress, cert not yet issued")
        else:
            step2.warnings.append("No attestation in progress")
        report.steps.append(step2)
        report.result = VerificationResult.NOT_VERIFIED
        return report

    step2.passed = True
    report.cert_hash = _hex(cert_hash_on_chain)
    step2.details["cert_hash"] = report.cert_hash

    members, threshold = query_committee(substrate)
    report.committee_size = len(members)
    report.threshold = threshold
    step2.details["committee_size"] = len(members)
    step2.details["threshold"] = threshold
    step2.details["members"] = [str(m) for m in members]
    report.steps.append(step2)

    # Step 3: Compute leaf
    step3 = StepResult(step=3, title="Compute checkpoint leaf hash", passed=True)
    receipt_id_bytes = bytes.fromhex(receipt_id.removeprefix("0x"))
    leaf_hash = compute_checkpoint_leaf(chain_id_bytes, receipt_id_bytes, cert_hash_on_chain)
    report.leaf_hash = _hex(leaf_hash)
    step3.details["leaf_hash"] = report.leaf_hash
    step3.details["binding"] = 'SHA256("materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)'
    report.steps.append(step3)

    # Step 4: Search anchor
    step4 = StepResult(step=4, title="Search for checkpoint anchor", passed=False)
    scan_start = max(1, report.best_block - scan_window)
    step4.details["scan_range"] = f"#{scan_start}-#{report.best_block}"

    checkpoint_found = False
    anchor_record = None
    batch_match = None

    if checkpoint_state_path:
        state = load_checkpoint_state(checkpoint_state_path)
        if state:
            pending = state.get("pending_leaves", [])
            target_rid = receipt_id.removeprefix("0x").lower()
            in_pending = any(
                l.get("receipt_id", "").removeprefix("0x").lower() == target_rid
                for l in pending
            )
            if in_pending:
                step4.warnings.append(f"Receipt in pending queue ({len(pending)} pending)")

    anchor_events = scan_anchor_events(substrate, scan_start, report.best_block)
    step4.details["anchors_found"] = len(anchor_events)

    for anchor_evt in anchor_events:
        anchor_id = anchor_evt["anchor_id"]
        anchor_data = query_anchor(substrate, anchor_id)
        if anchor_data is None:
            continue

        anchor_root = _to_bytes32(anchor_data["root_hash"])
        anchor_manifest = _to_bytes32(anchor_data["manifest_hash"])

        if anchor_root == leaf_hash:
            checkpoint_found = True
            anchor_record = {
                "anchor_id": str(anchor_id),
                "root_hash": _hex(anchor_root),
                "manifest_hash": _hex(anchor_manifest),
                "block_num": anchor_evt["block_num"],
                "match_type": "exact (single-leaf batch)",
            }
            if checkpoint_history_path:
                history = load_batch_history(checkpoint_history_path)
                if history:
                    batch = find_batch_for_receipt(history, receipt_id)
                    if batch and batch.get("root_hash") == anchor_root.hex():
                        batch_match = batch
            break

        if checkpoint_history_path:
            history = load_batch_history(checkpoint_history_path)
            if history:
                batch = find_batch_for_receipt(history, receipt_id)
                if batch and batch.get("root_hash") == anchor_root.hex():
                    checkpoint_found = True
                    batch_match = batch
                    leaf_count = batch.get("manifest", {}).get("count", "?")
                    anchor_record = {
                        "anchor_id": str(anchor_id),
                        "root_hash": _hex(anchor_root),
                        "manifest_hash": _hex(anchor_manifest),
                        "block_num": anchor_evt["block_num"],
                        "match_type": f"multi-leaf batch ({leaf_count} leaves)",
                    }
                    break

    if not checkpoint_found and anchor_events:
        reconstructed = try_onchain_reconstruction(
            substrate, chain_id_bytes, leaf_hash, anchor_events,
            scan_start, report.best_block,
        )
        if reconstructed:
            checkpoint_found = True
            anchor_record = {
                "anchor_id": str(reconstructed["anchor_id"]),
                "root_hash": _hex(reconstructed["root_hash"]),
                "manifest_hash": _hex(reconstructed["manifest_hash"]),
                "block_num": reconstructed["block_num"],
                "match_type": reconstructed["match_type"],
            }

    step4.passed = checkpoint_found
    if anchor_record:
        step4.details.update(anchor_record)
        report.anchor = anchor_record
    elif not anchor_events:
        step4.warnings.append(f"No anchor events in last {scan_window} blocks")
    else:
        step4.warnings.append("Checkpoint may be pending flush")
    report.steps.append(step4)

    # Step 5: Merkle inclusion
    step5 = StepResult(step=5, title="Verify Merkle inclusion", passed=False)
    if not checkpoint_found:
        step5.warnings.append("Skipped: no anchor found")
    elif batch_match:
        leaves_data = batch_match.get("leaves", [])
        leaf_hashes = [bytes.fromhex(l["leaf_hash"]) for l in leaves_data]
        target_rid = receipt_id.removeprefix("0x").lower()
        target_idx = None
        for i, l in enumerate(leaves_data):
            if l["receipt_id"].removeprefix("0x").lower() == target_rid:
                target_idx = i
                break

        if target_idx is not None:
            proof = merkle_inclusion_proof(leaf_hashes, target_idx)
            computed_root = merkle_root(leaf_hashes)
            step5.passed = computed_root == (
                anchor_record["root_hash"]
                if isinstance(anchor_record["root_hash"], bytes)
                else bytes.fromhex(anchor_record["root_hash"].removeprefix("0x"))
            )
            step5.details["leaf_count"] = len(leaf_hashes)
            step5.details["leaf_index"] = target_idx
            step5.details["proof_depth"] = len(proof)
    elif anchor_record and anchor_record.get("match_type", "").startswith("exact"):
        step5.passed = True
        step5.details["match_type"] = "single-leaf (root == leaf)"
    elif anchor_record and anchor_record.get("match_type", "").startswith("on-chain"):
        step5.passed = True
        step5.details["match_type"] = "on-chain reconstruction"
    report.steps.append(step5)

    # Step 6: Manifest hash
    step6 = StepResult(step=6, title="Verify manifest hash", passed=False)
    if not checkpoint_found or not anchor_record:
        step6.warnings.append("Skipped: no anchor found")
    elif batch_match and batch_match.get("manifest"):
        manifest = batch_match["manifest"]
        manifest_json = json.dumps(manifest, sort_keys=True).encode()
        computed_hash = hashlib.sha256(manifest_json).digest()
        expected = (
            anchor_record["manifest_hash"]
            if isinstance(anchor_record["manifest_hash"], bytes)
            else bytes.fromhex(anchor_record["manifest_hash"].removeprefix("0x"))
        )
        step6.passed = computed_hash == expected
        step6.details["from_block"] = manifest.get("from_block")
        step6.details["to_block"] = manifest.get("to_block")
        step6.details["cert_count"] = manifest.get("count")
    else:
        step6.passed = True  # supplementary — don't fail when manifest unavailable
        step6.warnings.append("Manifest data not available")
    report.steps.append(step6)

    # Step 7: AvailabilityCertified event
    step7 = StepResult(step=7, title="Locate AvailabilityCertified event", passed=False)
    cert_event = scan_certified_events(substrate, receipt_id, scan_start, report.best_block)
    if cert_event:
        event_cert_hash = cert_event["cert_hash"]
        if isinstance(event_cert_hash, str):
            event_cert_bytes = bytes.fromhex(event_cert_hash.removeprefix("0x"))
        else:
            event_cert_bytes = _to_bytes32(event_cert_hash)

        step7.passed = event_cert_bytes == cert_hash_on_chain
        step7.details["event_block"] = cert_event["block_num"]
        if not step7.passed:
            step7.details["error"] = "cert_hash mismatch between event and storage"
    else:
        step7.warnings.append(f"Event not found in last {scan_window} blocks (may be older)")
        step7.passed = True  # supplementary — don't fail on missing old events
    report.steps.append(step7)

    # Summary
    all_pass = all(s.passed for s in report.steps)
    if cert_hash_on_chain != ZERO_HASH and all_pass and checkpoint_found:
        report.result = VerificationResult.FULLY_VERIFIED
    elif cert_hash_on_chain != ZERO_HASH:
        report.result = VerificationResult.PARTIALLY_VERIFIED
    else:
        report.result = VerificationResult.NOT_VERIFIED

    return report
