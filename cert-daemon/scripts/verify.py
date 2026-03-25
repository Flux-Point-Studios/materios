#!/usr/bin/env python3
"""Materios end-to-end checkpoint verifier.

Given a receipt_id, produce a full chain-of-custody proof:
  0. Connect to Materios chain
  1. Query the receipt and availability cert hash
  2. Check committee attestation
  3. Compute the checkpoint leaf hash (context-bound binding)
  4. Locate the checkpoint anchor on Materios chain
  5. Verify Merkle inclusion (single-leaf exact match or multi-leaf proof)
  6. Verify manifest hash integrity
  7. Locate AvailabilityCertified event (supplementary)

Usage:
    python3 scripts/verify.py <receipt_id> [--rpc-url ws://...]
    python3 scripts/verify.py 0xabc123... --rpc-url wss://materios.fluxpointstudios.com/rpc
    python3 scripts/verify.py 0xabc123... --verbose --scan-window 1000
    python3 scripts/verify.py 0xabc123... --checkpoint-history /data/checkpoint-history.json

Environment fallbacks:
    MATERIOS_RPC_URL  (default: ws://127.0.0.1:9944)
    CHAIN_ID          (auto-detected from chain genesis if not set)
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Optional

from substrateinterface import SubstrateInterface


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ZERO_HASH = b"\x00" * 32

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _short(h: str, n: int = 18) -> str:
    if len(h) > n + 4:
        return h[:n] + "..."
    return h


def _to_bytes32(val) -> bytes:
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val.removeprefix("0x"))
    if isinstance(val, (list, tuple)):
        return bytes(val)
    return bytes(val)


def _pass(msg: str):
    print(f"  {GREEN}PASS{RESET}  {msg}")


def _fail(msg: str):
    print(f"  {RED}FAIL{RESET}  {msg}")


def _warn(msg: str):
    print(f"  {YELLOW}WARN{RESET}  {msg}")


def _info(msg: str):
    print(f"  {CYAN}INFO{RESET}  {msg}")


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

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


def merkle_inclusion_proof(leaves: list[bytes], target_index: int) -> list[tuple[bytes, str]]:
    """Generate a Merkle inclusion proof (list of sibling hashes + side).

    Returns list of (sibling_hash, "L"|"R") pairs from leaf to root.
    """
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


def verify_merkle_proof(leaf: bytes, proof: list[tuple[bytes, str]], root: bytes) -> bool:
    """Verify a Merkle inclusion proof against an expected root."""
    current = leaf
    for sibling, side in proof:
        if side == "L":
            current = _sha256(sibling + current)
        else:
            current = _sha256(current + sibling)
    return current == root


def compute_checkpoint_leaf(chain_id: bytes, receipt_id: bytes, cert_hash: bytes) -> bytes:
    """Compute the context-bound checkpoint leaf hash.

    leaf = SHA256(b"materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)
    """
    return _sha256(b"materios-checkpoint-v1" + chain_id + receipt_id + cert_hash)


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
    members_result = substrate.query(module="OrinqReceipts", storage_function="CommitteeMembers")
    threshold_result = substrate.query(module="OrinqReceipts", storage_function="AttestationThreshold")
    members = members_result.value if members_result.value else []
    threshold = threshold_result.value if threshold_result.value else 1
    return members, threshold


def query_anchor(substrate: SubstrateInterface, anchor_id: str) -> Optional[dict]:
    result = substrate.query(
        module="OrinqReceipts", storage_function="Anchors", params=[anchor_id],
    )
    return result.value if result.value is not None else None


def scan_anchor_events(substrate: SubstrateInterface, from_block: int, to_block: int) -> list[dict]:
    anchors = []
    for block_num in range(from_block, to_block + 1):
        try:
            block_hash = substrate.get_block_hash(block_num)
            if block_hash is None:
                continue
            events = substrate.get_events(block_hash=block_hash)
            for event in events:
                if (event.value.get("module_id") == "OrinqReceipts" and
                        event.value.get("event_id") == "AnchorSubmitted"):
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
    substrate: SubstrateInterface, receipt_id: str, from_block: int, to_block: int,
) -> Optional[dict]:
    target_id = receipt_id.removeprefix("0x").lower()
    for block_num in range(from_block, to_block + 1):
        try:
            block_hash = substrate.get_block_hash(block_num)
            if block_hash is None:
                continue
            events = substrate.get_events(block_hash=block_hash)
            for event in events:
                if (event.value.get("module_id") == "OrinqReceipts" and
                        event.value.get("event_id") == "AvailabilityCertified"):
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
                if (event.value.get("module_id") == "OrinqReceipts" and
                        event.value.get("event_id") == "AvailabilityCertified"):
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
    """Load the daemon's checkpoint-history.json."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def find_batch_for_receipt(history: list[dict], receipt_id: str) -> Optional[dict]:
    """Find the batch containing a specific receipt_id."""
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
# Verification pipeline
# ---------------------------------------------------------------------------

TOTAL_STEPS = 7


def verify(
    receipt_id: str,
    rpc_url: str,
    chain_id_override: Optional[str] = None,
    verbose: bool = False,
    scan_window: int = 500,
    checkpoint_state_path: Optional[str] = None,
    checkpoint_history_path: Optional[str] = None,
) -> bool:
    """Run the full chain-of-custody verification for a receipt."""
    all_pass = True

    if not receipt_id.startswith("0x"):
        receipt_id = "0x" + receipt_id

    print(f"\n{BOLD}=== Materios Checkpoint Verifier ==={RESET}")
    print(f"  Receipt ID : {receipt_id}")
    print(f"  RPC URL    : {rpc_url}")
    print()

    # ── Step 0: Connect ──────────────────────────────────────────────────
    print(f"{BOLD}[0/{TOTAL_STEPS}] Connecting to Materios chain{RESET}")
    try:
        substrate = SubstrateInterface(url=rpc_url)
    except Exception as e:
        _fail(f"Cannot connect to {rpc_url}: {e}")
        return False

    _pass(f"Connected to '{substrate.chain}', runtime v{substrate.runtime_version}")

    if chain_id_override:
        chain_id_hex = chain_id_override.removeprefix("0x")
    else:
        genesis_hash = substrate.get_block_hash(0)
        if genesis_hash:
            chain_id_hex = genesis_hash.removeprefix("0x")
        else:
            _fail("Cannot determine genesis hash for chain_id")
            return False

    chain_id_bytes = bytes.fromhex(chain_id_hex)
    _info(f"Chain ID (genesis): 0x{chain_id_hex[:16]}...")

    try:
        best_block = substrate.get_block_header()["header"]["number"]
    except Exception:
        best_block = 0
    _info(f"Best block: #{best_block}")
    print()

    # ── Step 1: Query receipt ────────────────────────────────────────────
    print(f"{BOLD}[1/{TOTAL_STEPS}] Querying on-chain receipt{RESET}")
    receipt = query_receipt(substrate, receipt_id)
    if receipt is None:
        _fail(f"Receipt {_short(receipt_id)} not found on chain")
        return False

    _pass("Receipt exists on chain")

    content_hash = _to_bytes32(receipt["content_hash"])
    base_root = _to_bytes32(receipt["base_root_sha256"])
    cert_hash_on_chain = _to_bytes32(receipt["availability_cert_hash"])
    submitter = receipt.get("submitter", "unknown")

    if verbose:
        _info(f"Content hash      : {_hex(content_hash)}")
        _info(f"Base root SHA256  : {_hex(base_root)}")
        _info(f"Submitter         : {submitter}")
        for field in ["schema_hash", "storage_locator_hash", "base_manifest_hash",
                       "safety_manifest_hash", "monitor_config_hash", "attestation_evidence_hash"]:
            _info(f"{field:22s}: {_hex(_to_bytes32(receipt[field]))}")

    print()

    # ── Step 2: Check availability cert ──────────────────────────────────
    print(f"{BOLD}[2/{TOTAL_STEPS}] Checking availability certificate{RESET}")

    if cert_hash_on_chain == ZERO_HASH:
        _fail("No availability certificate (cert_hash is zero)")
        attestation = query_attestations(substrate, receipt_id)
        if attestation is not None:
            att_signers = attestation[1] if isinstance(attestation, (list, tuple)) and len(attestation) > 1 else []
            members, threshold = query_committee(substrate)
            _warn(f"Attestation in progress: {len(att_signers)}/{threshold} signatures")
        else:
            _warn("No attestation in progress. Cert daemon may not have processed this receipt.")
        print(f"\n{YELLOW}Verification stopped: certificate not yet issued.{RESET}")
        return False

    _pass(f"Availability cert hash: {_hex(cert_hash_on_chain)}")

    members, threshold = query_committee(substrate)
    _info(f"Committee: {len(members)} members, threshold={threshold}")
    if verbose:
        for m in members:
            _info(f"  Member: {m}")
    print()

    # ── Step 3: Compute checkpoint leaf hash ─────────────────────────────
    print(f"{BOLD}[3/{TOTAL_STEPS}] Computing checkpoint leaf hash{RESET}")

    receipt_id_bytes = bytes.fromhex(receipt_id.removeprefix("0x"))
    leaf_hash = compute_checkpoint_leaf(chain_id_bytes, receipt_id_bytes, cert_hash_on_chain)

    _pass('Leaf = SHA256("materios-checkpoint-v1" || chain_id || receipt_id || cert_hash)')
    _info(f"Leaf hash     : {_hex(leaf_hash)}")

    if verbose:
        preimage = b"materios-checkpoint-v1" + chain_id_bytes + receipt_id_bytes + cert_hash_on_chain
        _info(f"Preimage ({len(preimage)} bytes): {preimage.hex()}")
    print()

    # ── Step 4: Search for checkpoint anchor ─────────────────────────────
    print(f"{BOLD}[4/{TOTAL_STEPS}] Searching for checkpoint anchor{RESET}")

    checkpoint_found = False
    anchor_record = None
    batch_match = None

    # Check pending queue first
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
                _warn("Receipt is in the checkpoint pending queue (not yet flushed)")
                _info(f"Pending leaves: {len(pending)}")

    # Scan for AnchorSubmitted events
    scan_start = max(1, best_block - scan_window)
    _info(f"Scanning blocks #{scan_start}-#{best_block} for AnchorSubmitted events...")

    anchor_events = scan_anchor_events(substrate, scan_start, best_block)

    if not anchor_events:
        _warn(f"No anchor events in last {scan_window} blocks")
        _info("Use --scan-window N to search wider")
    else:
        _info(f"Found {len(anchor_events)} anchor(s)")

        for anchor_evt in anchor_events:
            anchor_id = anchor_evt["anchor_id"]
            anchor_data = query_anchor(substrate, anchor_id)
            if anchor_data is None:
                continue

            anchor_root = _to_bytes32(anchor_data["root_hash"])
            anchor_content = _to_bytes32(anchor_data["content_hash"])
            anchor_manifest = _to_bytes32(anchor_data["manifest_hash"])

            # Single-leaf exact match
            if anchor_root == leaf_hash:
                checkpoint_found = True
                anchor_record = {
                    "anchor_id": anchor_id,
                    "root_hash": anchor_root,
                    "content_hash": anchor_content,
                    "manifest_hash": anchor_manifest,
                    "block_num": anchor_evt["block_num"],
                    "match_type": "exact (single-leaf batch)",
                }
                # Look up batch history for manifest verification
                if checkpoint_history_path:
                    history = load_batch_history(checkpoint_history_path)
                    if history:
                        batch = find_batch_for_receipt(history, receipt_id)
                        if batch and batch.get("root_hash") == anchor_root.hex():
                            batch_match = batch
                break

            # Multi-leaf: try batch history lookup
            if checkpoint_history_path:
                history = load_batch_history(checkpoint_history_path)
                if history:
                    batch = find_batch_for_receipt(history, receipt_id)
                    if batch and batch.get("root_hash") == anchor_root.hex():
                        checkpoint_found = True
                        batch_match = batch
                        anchor_record = {
                            "anchor_id": anchor_id,
                            "root_hash": anchor_root,
                            "content_hash": anchor_content,
                            "manifest_hash": anchor_manifest,
                            "block_num": anchor_evt["block_num"],
                            "match_type": f"multi-leaf batch ({batch['manifest']['count']} leaves)",
                        }
                        break

            if verbose:
                _info(f"  Anchor {_short(str(anchor_id))}: root={_short(_hex(anchor_root))} block=#{anchor_evt['block_num']}")

    if checkpoint_found and anchor_record:
        _pass("Checkpoint anchor found!")
        _info(f"Anchor ID     : {anchor_record['anchor_id']}")
        _info(f"Root hash     : {_hex(anchor_record['root_hash'])}")
        _info(f"Manifest hash : {_hex(anchor_record['manifest_hash'])}")
        _info(f"Block         : #{anchor_record['block_num']}")
        _info(f"Match type    : {anchor_record['match_type']}")
    elif anchor_events:
        # Try on-chain reconstruction as last resort
        _warn("No direct root match. Attempting on-chain batch reconstruction...")
        reconstructed = _try_onchain_reconstruction(
            substrate, chain_id_bytes, leaf_hash, anchor_events, scan_start, best_block, verbose,
        )
        if reconstructed:
            checkpoint_found = True
            anchor_record = reconstructed
            _pass("Checkpoint anchor verified via on-chain reconstruction!")
            _info(f"Anchor ID     : {anchor_record['anchor_id']}")
            _info(f"Root hash     : {_hex(anchor_record['root_hash'])}")
            _info(f"Block         : #{anchor_record['block_num']}")
            _info(f"Match type    : {anchor_record['match_type']}")
        else:
            _warn("Could not verify inclusion. Receipt may be pending flush.")
            all_pass = False
    else:
        _warn("No checkpoint anchor found for this receipt yet.")
        all_pass = False

    print()

    # ── Step 5: Merkle inclusion proof ───────────────────────────────────
    print(f"{BOLD}[5/{TOTAL_STEPS}] Verifying Merkle inclusion{RESET}")

    if not checkpoint_found:
        _warn("Skipped: no anchor found")
    elif batch_match:
        # Multi-leaf: generate and verify inclusion proof from batch history
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

            if computed_root == anchor_record["root_hash"]:
                _pass(f"Merkle tree root matches anchor ({len(leaf_hashes)} leaves)")
            else:
                _fail("Merkle tree root MISMATCH with anchor")
                all_pass = False

            if verify_merkle_proof(leaf_hash, proof, anchor_record["root_hash"]):
                _pass(f"Merkle inclusion proof valid (leaf #{target_idx}, {len(proof)} siblings)")
                if verbose:
                    for i, (sibling, side) in enumerate(proof):
                        _info(f"  Level {i}: {side} sibling {_short(_hex(sibling))}")
            else:
                _fail("Merkle inclusion proof FAILED")
                all_pass = False
        else:
            _fail("Receipt not found in batch leaf list")
            all_pass = False
    elif anchor_record and anchor_record.get("match_type", "").startswith("exact"):
        _pass("Single-leaf batch: root == leaf (no proof needed)")
    elif anchor_record and anchor_record.get("match_type", "").startswith("on-chain"):
        _pass(f"Inclusion verified via on-chain reconstruction")
    else:
        _warn("Merkle inclusion could not be verified")

    print()

    # ── Step 6: Manifest hash verification ───────────────────────────────
    print(f"{BOLD}[6/{TOTAL_STEPS}] Verifying manifest hash{RESET}")

    if not checkpoint_found or not anchor_record:
        _warn("Skipped: no anchor found")
    elif batch_match and batch_match.get("manifest"):
        manifest = batch_match["manifest"]
        manifest_json = json.dumps(manifest, sort_keys=True).encode()
        computed_hash = hashlib.sha256(manifest_json).digest()

        if computed_hash == anchor_record["manifest_hash"]:
            _pass("Manifest hash matches on-chain anchor")
            _info(f"Chain ID      : {manifest.get('materios_chain_id', '?')[:16]}...")
            _info(f"Block range   : #{manifest.get('from_block')}-#{manifest.get('to_block')}")
            _info(f"Cert count    : {manifest.get('count')}")
            _info(f"Root          : {manifest.get('root', '?')[:16]}...")
        else:
            _fail("Manifest hash MISMATCH")
            _info(f"Computed : {_hex(computed_hash)}")
            _info(f"On-chain : {_hex(anchor_record['manifest_hash'])}")
            all_pass = False
    elif anchor_record and anchor_record.get("match_type", "").startswith("exact"):
        _info("Single-leaf batch: use --checkpoint-history to enable manifest verification")
    else:
        _warn("Manifest data not available for verification")

    print()

    # ── Step 7: AvailabilityCertified event ──────────────────────────────
    print(f"{BOLD}[7/{TOTAL_STEPS}] Locating AvailabilityCertified event{RESET}")

    cert_event = scan_certified_events(substrate, receipt_id, scan_start, best_block)
    if cert_event:
        event_cert_hash = cert_event["cert_hash"]
        if isinstance(event_cert_hash, str):
            event_cert_bytes = bytes.fromhex(event_cert_hash.removeprefix("0x"))
        else:
            event_cert_bytes = _to_bytes32(event_cert_hash)

        if event_cert_bytes == cert_hash_on_chain:
            _pass(f"AvailabilityCertified at block #{cert_event['block_num']} matches on-chain cert hash")
        else:
            _fail(f"Event cert_hash MISMATCH: event={_hex(event_cert_bytes)} vs on-chain={_hex(cert_hash_on_chain)}")
            all_pass = False
    else:
        _warn(f"Event not found in last {scan_window} blocks (may be older)")
        _info("On-chain cert_hash is authoritative; event scan is supplementary.")

    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"{BOLD}=== Verification Summary ==={RESET}")
    print(f"  Receipt ID          : {receipt_id}")
    print(f"  On-chain cert hash  : {_hex(cert_hash_on_chain)}")
    print(f"  Checkpoint leaf     : {_hex(leaf_hash)}")

    if checkpoint_found and anchor_record:
        print(f"  Anchor root         : {_hex(anchor_record['root_hash'])}")
        print(f"  Anchor block        : #{anchor_record['block_num']}")
        print(f"  Match type          : {anchor_record['match_type']}")

    print()

    if cert_hash_on_chain != ZERO_HASH and all_pass and checkpoint_found:
        print(f"  {GREEN}{BOLD}RESULT: FULLY VERIFIED{RESET}")
        print(f"  {DIM}Full chain of custody:{RESET}")
        print(f"  {DIM}  Receipt -> Cert -> Leaf -> Merkle Root -> Anchor{RESET}")
        return True
    elif cert_hash_on_chain != ZERO_HASH and all_pass:
        print(f"  {YELLOW}{BOLD}RESULT: PARTIALLY VERIFIED{RESET}")
        print(f"  {DIM}Receipt and cert valid. Checkpoint anchor not yet found.{RESET}")
        print(f"  {DIM}The checkpoint may be pending flush (interval={os.environ.get('CHECKPOINT_INTERVAL', '60')}min).{RESET}")
        return False
    elif cert_hash_on_chain != ZERO_HASH:
        print(f"  {YELLOW}{BOLD}RESULT: PARTIALLY VERIFIED (with warnings){RESET}")
        return False
    else:
        print(f"  {RED}{BOLD}RESULT: NOT VERIFIED{RESET}")
        return False


# ---------------------------------------------------------------------------
# On-chain batch reconstruction
# ---------------------------------------------------------------------------

def _try_onchain_reconstruction(
    substrate: SubstrateInterface,
    chain_id_bytes: bytes,
    target_leaf: bytes,
    anchor_events: list[dict],
    scan_start: int,
    scan_end: int,
    verbose: bool,
) -> Optional[dict]:
    """Try to reconstruct a multi-leaf batch from on-chain events.

    For each anchor, scan the block range for AvailabilityCertified events,
    rebuild the Merkle tree, and check if the target leaf is included.
    """
    # Collect all certified events in the scan range
    all_certs = scan_all_certified_events(substrate, scan_start, scan_end)
    if not all_certs:
        return None

    if verbose:
        _info(f"Found {len(all_certs)} AvailabilityCertified events for reconstruction")

    # For each anchor, try to find a subset of certs whose Merkle root matches
    for anchor_evt in anchor_events:
        anchor_data = query_anchor(substrate, anchor_evt["anchor_id"])
        if anchor_data is None:
            continue

        anchor_root = _to_bytes32(anchor_data["root_hash"])
        anchor_block = anchor_evt["block_num"]

        # Certs eligible for this anchor: certified before the anchor was submitted
        eligible_certs = [c for c in all_certs if c["block_num"] < anchor_block]
        if not eligible_certs:
            continue

        # Sort by block_num (deterministic ordering matches daemon's batch ordering)
        eligible_certs.sort(key=lambda c: (c["block_num"], c["receipt_id"]))

        # Try the full set first, then decreasing subsets from the end
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
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Materios end-to-end checkpoint verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 verify.py 0xabc123...def456
  python3 verify.py 0xabc123... --rpc-url wss://materios.fluxpointstudios.com/rpc
  python3 verify.py 0xabc123... --verbose --scan-window 1000
  python3 verify.py 0xabc123... --checkpoint-history /data/checkpoint-history.json
        """,
    )
    parser.add_argument("receipt_id", help="Receipt ID to verify (hex, with or without 0x prefix)")
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("MATERIOS_RPC_URL", "ws://127.0.0.1:9944"),
        help="Materios chain RPC URL (default: $MATERIOS_RPC_URL or ws://127.0.0.1:9944)",
    )
    parser.add_argument("--chain-id", default=os.environ.get("CHAIN_ID", ""), help="Chain ID (genesis hash hex)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed values")
    parser.add_argument("--scan-window", type=int, default=500, help="Blocks to scan for events (default: 500)")
    parser.add_argument("--checkpoint-state", default=None, help="Path to checkpoint-state.json")
    parser.add_argument("--checkpoint-history", default=None, help="Path to checkpoint-history.json for multi-leaf proofs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        global GREEN, RED, YELLOW, CYAN, BOLD, DIM, RESET
        GREEN = RED = YELLOW = CYAN = BOLD = DIM = RESET = ""

    ok = verify(
        receipt_id=args.receipt_id,
        rpc_url=args.rpc_url,
        chain_id_override=args.chain_id if args.chain_id else None,
        verbose=args.verbose,
        scan_window=args.scan_window,
        checkpoint_state_path=args.checkpoint_state,
        checkpoint_history_path=args.checkpoint_history,
    )

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
