"""Substrate chain connection wrapper and event index for the explorer."""

import hashlib
import json as _json
import logging
import os
import threading
import time
import urllib.request
from typing import Optional

from substrateinterface import SubstrateInterface

logger = logging.getLogger(__name__)

RPC_URL = os.environ.get("MATERIOS_RPC_URL", "ws://127.0.0.1:9944")

ZERO_HASH = "0x" + "00" * 32

STATUS_SUBMITTED_SECS = int(os.environ.get("STATUS_SUBMITTED_SECS", "60"))
STATUS_STALE_SECS = int(os.environ.get("STATUS_STALE_SECS", "600"))
BLOB_GATEWAY_URL = os.environ.get("BLOB_GATEWAY_URL", "http://materios-blob-gateway.materios.svc.cluster.local:3000")
BLOB_GATEWAY_API_KEY = os.environ.get("BLOB_GATEWAY_API_KEY", "")

# ---------------------------------------------------------------------------
# Connection singleton
# ---------------------------------------------------------------------------

_conn: Optional[SubstrateInterface] = None
_conn_lock = threading.Lock()


def get_substrate() -> SubstrateInterface:
    """Return a shared SubstrateInterface, reconnecting if needed."""
    global _conn
    with _conn_lock:
        if _conn is None:
            _conn = SubstrateInterface(url=RPC_URL)
        try:
            _conn.get_block_hash(0)  # lightweight ping
        except Exception:
            try:
                _conn = SubstrateInterface(url=RPC_URL)
            except Exception as e:
                logger.error("Failed to reconnect to %s: %s", RPC_URL, e)
                raise
        return _conn


def _hex_hash(val) -> str:
    """Convert a storage hash value to 0x-prefixed hex string."""
    if isinstance(val, str):
        return val if val.startswith("0x") else "0x" + val
    if isinstance(val, (bytes, bytearray)):
        return "0x" + val.hex()
    return str(val)


def _compute_checkpoint_leaf(genesis_hash: str, receipt_id: str, cert_hash: str) -> str:
    """Compute the checkpoint leaf hash: SHA256("materios-checkpoint-v1" || genesis_hash || receipt_id || cert_hash)."""
    prefix = b"materios-checkpoint-v1"
    g = bytes.fromhex(genesis_hash.replace("0x", ""))
    r = bytes.fromhex(receipt_id.replace("0x", ""))
    c = bytes.fromhex(cert_hash.replace("0x", ""))
    return hashlib.sha256(prefix + g + r + c).hexdigest()


def _fetch_batch_leaf_hashes(anchor_ids: list[str]) -> set[str]:
    """Fetch leaf hashes from blob gateway batch metadata for all anchors.
    Returns a set of leaf hashes (hex, no 0x prefix).
    Falls back to empty set if gateway is unreachable."""
    if not BLOB_GATEWAY_URL or not BLOB_GATEWAY_API_KEY:
        return set()

    all_leaves = set()
    for aid in anchor_ids:
        try:
            aid_clean = aid.replace("0x", "")
            url = f"{BLOB_GATEWAY_URL}/batches/{aid_clean}"
            req = urllib.request.Request(url, headers={
                "x-api-key": BLOB_GATEWAY_API_KEY,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read())
                for leaf in data.get("leafHashes", []):
                    # Normalize: strip 0x prefix, lowercase
                    all_leaves.add(leaf.replace("0x", "").lower())
        except Exception:
            continue
    return all_leaves


# ---------------------------------------------------------------------------
# Event Index — loads data from on-chain storage + event scanning
# ---------------------------------------------------------------------------

MAX_FAILED_SUBMISSIONS = 50


def _parse_dispatch_error(attrs) -> dict:
    """Parse DispatchError from ExtrinsicFailed event attributes into a readable dict.

    The attrs can take many forms depending on substrate-interface version:
    - dict with 'dispatch_error' key containing Module/Token/Other/etc
    - list with positional args
    - nested dicts/tuples
    We extract what we can and return {error, module, name}.
    """
    result = {"error": "ExtrinsicFailed", "module": "", "name": ""}

    if not attrs:
        return result

    try:
        # attrs might be a dict or a list
        dispatch_error = None
        if isinstance(attrs, dict):
            dispatch_error = attrs.get("dispatch_error", attrs.get("error", attrs))
        elif isinstance(attrs, (list, tuple)):
            # First element is typically the DispatchError
            dispatch_error = attrs[0] if attrs else None

        if dispatch_error is None:
            return result

        # Handle DispatchError variants
        if isinstance(dispatch_error, dict):
            # Module error: {Module: {index: N, error: N}} or {Module: {index, error, message}}
            module_err = dispatch_error.get("Module", dispatch_error.get("module", None))
            if module_err and isinstance(module_err, dict):
                idx = module_err.get("index", "?")
                err = module_err.get("error", "?")
                msg = module_err.get("message", "")
                result["module"] = f"Module(index={idx})"
                result["name"] = msg if msg else f"error={err}"
                result["error"] = msg if msg else f"Module(index={idx}, error={err})"
                return result

            # Other error types: Token, Arithmetic, etc
            for variant in ("Token", "Arithmetic", "Transactional", "Exhausted",
                            "Corruption", "Unavailable", "Other", "BadOrigin",
                            "CannotLookup", "ConsumerRemaining", "NoProviders"):
                if variant in dispatch_error:
                    inner = dispatch_error[variant]
                    if inner and isinstance(inner, str):
                        result["error"] = f"{variant}: {inner}"
                    elif inner and isinstance(inner, dict):
                        result["error"] = f"{variant}: {inner}"
                    else:
                        result["error"] = variant
                    result["name"] = variant
                    return result

            # Fallback: stringify it
            result["error"] = str(dispatch_error)[:120]

        elif isinstance(dispatch_error, str):
            result["error"] = dispatch_error[:120]

    except Exception:
        pass

    return result


class EventIndex:
    """In-memory index of receipts, anchors, and certs."""

    def __init__(self):
        self.receipts: list[dict] = []       # newest first (by created_at_millis)
        self.anchors: list[dict] = []        # newest first (by created_at_millis)
        self.certs: dict[str, dict] = {}     # receipt_id -> {block_num, cert_hash}
        self.failed_submissions: list[dict] = []  # newest first, capped at MAX_FAILED_SUBMISSIONS
        self.last_scanned_block: int = 0
        self._lock = threading.Lock()
        self._initialized = False
        self._scanning = False
        self._genesis_hash = ""
        self._anchored_leaves: set[str] = set()

    def ensure_initialized(self):
        """Start background initial load on first call. Non-blocking."""
        if self._initialized or self._scanning:
            return
        self._scanning = True
        t = threading.Thread(target=self._background_init, daemon=True)
        t.start()

    def _background_init(self):
        """Load all receipts/anchors from storage, then compute statuses."""
        try:
            logger.info("EventIndex: connecting to %s...", RPC_URL)
            s = SubstrateInterface(url=RPC_URL)
            logger.info("EventIndex: connected, loading receipts and anchors from storage...")

            # Load genesis hash for checkpoint leaf computation
            genesis_hash = s.get_block_hash(0) or ""

            # Load all receipts from storage via query_map
            receipts = []
            cert_hashes = {}  # receipt_id -> cert_hash (for anchored detection)
            try:
                result = s.query_map("OrinqReceipts", "Receipts", page_size=100)
                for key, value in result:
                    rid = key.value if hasattr(key, "value") else str(key)
                    rid = _hex_hash(rid)
                    val = value.value if hasattr(value, "value") else value
                    if isinstance(val, dict):
                        cert_hash = _hex_hash(val.get("availability_cert_hash", ""))
                        is_certified = cert_hash != ZERO_HASH
                        if is_certified:
                            cert_hashes[rid] = cert_hash
                        receipts.append({
                            "receipt_id": rid,
                            "submitter": str(val.get("submitter", "")),
                            "content_hash": _hex_hash(val.get("content_hash", "")),
                            "status": "certified" if is_certified else "pending",  # temporary, refined below
                            "_cert_hash": cert_hash,
                            "timestamp": val.get("created_at_millis", 0),
                            "block_num": 0,
                        })
            except Exception as e:
                logger.error("EventIndex: failed to load receipts: %s", e)

            # Sort by timestamp descending (newest first)
            receipts.sort(key=lambda r: r.get("timestamp", 0), reverse=True)

            # Load all anchors from storage via query_map
            anchors = []
            try:
                result = s.query_map("OrinqReceipts", "Anchors", page_size=100)
                for key, value in result:
                    aid = key.value if hasattr(key, "value") else str(key)
                    aid = _hex_hash(aid)
                    val = value.value if hasattr(value, "value") else value
                    if isinstance(val, dict):
                        anchors.append({
                            "anchor_id": aid,
                            "submitter": str(val.get("submitter", "")),
                            "content_hash": _hex_hash(val.get("content_hash", "")),
                            "root_hash": _hex_hash(val.get("root_hash", "")),
                            "manifest_hash": _hex_hash(val.get("manifest_hash", "")),
                            "timestamp": val.get("created_at_millis", 0),
                            "block_num": 0,
                        })
            except Exception as e:
                logger.error("EventIndex: failed to load anchors: %s", e)

            anchors.sort(key=lambda a: a.get("timestamp", 0), reverse=True)

            # Build anchored set from blob gateway batch metadata
            anchor_ids = [a["anchor_id"] for a in anchors]
            anchored_leaves = _fetch_batch_leaf_hashes(anchor_ids)
            if anchored_leaves:
                logger.info("EventIndex: fetched %d leaf hashes from blob gateway batches", len(anchored_leaves))
            else:
                logger.info("EventIndex: no batch metadata available (gateway unreachable or no batches)")

            # Assign 5-state statuses
            now_ms = int(time.time() * 1000)
            for r in receipts:
                cert_hash = r.pop("_cert_hash", ZERO_HASH)
                if cert_hash != ZERO_HASH:
                    # Certified — check if anchored
                    leaf = _compute_checkpoint_leaf(genesis_hash, r["receipt_id"], cert_hash)
                    if leaf in anchored_leaves:
                        r["status"] = "anchored"
                    else:
                        r["status"] = "certified"
                else:
                    # Uncertified — age-based status
                    age_secs = (now_ms - r.get("timestamp", 0)) / 1000 if r.get("timestamp") else float("inf")
                    if age_secs < STATUS_SUBMITTED_SECS:
                        r["status"] = "submitted"
                    elif age_secs < STATUS_STALE_SECS:
                        r["status"] = "awaiting_cert"
                    else:
                        r["status"] = "stale"

            best = s.get_block_header()["header"]["number"]

            with self._lock:
                self.receipts = receipts
                self.anchors = anchors
                self._genesis_hash = genesis_hash
                self._anchored_leaves = anchored_leaves
                self.last_scanned_block = best
                self._initialized = True

            logger.info(
                "EventIndex: loaded %d receipts, %d anchors from storage",
                len(self.receipts), len(self.anchors),
            )
        except Exception as e:
            import traceback
            logger.error("EventIndex initial load failed: %s\n%s", e, traceback.format_exc())
        finally:
            self._scanning = False

    def scan_new_blocks(self):
        """Scan new blocks for new receipts/anchors/certs. Non-blocking if not initialized."""
        if not self._initialized:
            self.ensure_initialized()
            return

        try:
            s = SubstrateInterface(url=RPC_URL)
            best = s.get_block_header()["header"]["number"]
        except Exception:
            return

        if best <= self.last_scanned_block:
            return

        with self._lock:
            start = self.last_scanned_block + 1
            if best - start > 50:
                start = best - 50
            try:
                self._scan_range(s, start, best)
            except Exception as e:
                logger.error("EventIndex incremental scan failed: %s", e)
            self.last_scanned_block = best

    def _scan_range(self, substrate: SubstrateInterface, start: int, end: int):
        """Scan a block range for new events. Must hold _lock."""
        for block_num in range(start, end + 1):
            try:
                block_hash = substrate.get_block_hash(block_num)
                if block_hash is None:
                    continue
                events = substrate.get_events(block_hash=block_hash)
                timestamp = self._extract_timestamp(substrate, block_hash)

                # Collect failed extrinsic indices and their dispatch errors
                failed_ext_indices: dict[int, dict] = {}  # ext_index -> error info
                for event in events:
                    ev = event.value
                    module = ev.get("module_id", "")
                    event_id = ev.get("event_id", "")

                    if module == "System" and event_id == "ExtrinsicFailed":
                        # Extract extrinsic index from event phase
                        phase = ev.get("phase", {})
                        ext_idx = None
                        if isinstance(phase, dict):
                            ext_idx = phase.get("ApplyExtrinsic")
                        elif isinstance(phase, (list, tuple)) and len(phase) >= 2:
                            ext_idx = phase[1] if phase[0] == "ApplyExtrinsic" else None
                        elif isinstance(phase, int):
                            ext_idx = phase

                        # Extract dispatch error info
                        attrs = ev.get("attributes", {})
                        error_info = _parse_dispatch_error(attrs)

                        if ext_idx is not None:
                            failed_ext_indices[int(ext_idx)] = error_info

                # Process OrinqReceipts events (existing logic)
                for event in events:
                    ev = event.value
                    module = ev.get("module_id", "")
                    event_id = ev.get("event_id", "")
                    attrs = ev.get("attributes", {})

                    if module != "OrinqReceipts":
                        continue

                    if event_id == "ReceiptSubmitted":
                        rid = attrs.get("receipt_id", "")
                        if not any(r["receipt_id"] == rid for r in self.receipts):
                            # New receipt discovered via events — also query storage
                            try:
                                receipt = substrate.query("OrinqReceipts", "Receipts", [rid])
                                if receipt and receipt.value:
                                    val = receipt.value
                                    cert_hash = _hex_hash(val.get("availability_cert_hash", ""))
                                    ts = val.get("created_at_millis", 0)
                                    if cert_hash != ZERO_HASH:
                                        leaf = _compute_checkpoint_leaf(self._genesis_hash, rid, cert_hash)
                                        status = "anchored" if leaf in self._anchored_leaves else "certified"
                                    else:
                                        age_secs = (int(time.time() * 1000) - ts) / 1000 if ts else float("inf")
                                        if age_secs < STATUS_SUBMITTED_SECS:
                                            status = "submitted"
                                        elif age_secs < STATUS_STALE_SECS:
                                            status = "awaiting_cert"
                                        else:
                                            status = "stale"
                                    self.receipts.insert(0, {
                                        "receipt_id": rid,
                                        "submitter": str(val.get("submitter", "")),
                                        "content_hash": _hex_hash(val.get("content_hash", "")),
                                        "status": status,
                                        "timestamp": ts,
                                        "block_num": block_num,
                                    })
                            except Exception:
                                age_secs = (int(time.time() * 1000) - timestamp) / 1000 if timestamp else float("inf")
                                if age_secs < STATUS_SUBMITTED_SECS:
                                    status = "submitted"
                                elif age_secs < STATUS_STALE_SECS:
                                    status = "awaiting_cert"
                                else:
                                    status = "stale"
                                self.receipts.insert(0, {
                                    "receipt_id": rid,
                                    "submitter": str(attrs.get("submitter", "")),
                                    "content_hash": attrs.get("content_hash", ""),
                                    "status": status,
                                    "timestamp": timestamp,
                                    "block_num": block_num,
                                })

                    elif event_id == "AvailabilityCertified":
                        rid = attrs.get("receipt_id", "")
                        cert_hash = _hex_hash(attrs.get("cert_hash", attrs.get("availability_cert_hash", "")))
                        for r in self.receipts:
                            if r["receipt_id"] == rid:
                                if cert_hash and cert_hash != ZERO_HASH:
                                    leaf = _compute_checkpoint_leaf(self._genesis_hash, rid, cert_hash)
                                    r["status"] = "anchored" if leaf in self._anchored_leaves else "certified"
                                else:
                                    r["status"] = "certified"
                                break

                    elif event_id == "AnchorSubmitted":
                        aid = attrs.get("anchor_id", "")
                        if not any(a["anchor_id"] == aid for a in self.anchors):
                            try:
                                anchor = substrate.query("OrinqReceipts", "Anchors", [aid])
                                if anchor and anchor.value:
                                    val = anchor.value
                                    self.anchors.insert(0, {
                                        "anchor_id": aid,
                                        "submitter": str(val.get("submitter", "")),
                                        "content_hash": _hex_hash(val.get("content_hash", "")),
                                        "root_hash": _hex_hash(val.get("root_hash", "")),
                                        "manifest_hash": _hex_hash(val.get("manifest_hash", "")),
                                        "timestamp": val.get("created_at_millis", 0),
                                        "block_num": block_num,
                                    })
                            except Exception:
                                self.anchors.insert(0, {
                                    "anchor_id": aid,
                                    "submitter": str(attrs.get("submitter", "")),
                                    "content_hash": attrs.get("content_hash", ""),
                                    "timestamp": timestamp,
                                    "block_num": block_num,
                                })

                # Process failed extrinsics — match to actual extrinsic data
                if failed_ext_indices:
                    self._process_failed_extrinsics(
                        substrate, block_num, block_hash, timestamp, failed_ext_indices,
                    )

            except Exception as e:
                logger.debug("EventIndex scan block %d failed: %s", block_num, e)
                continue

    def _extract_timestamp(self, substrate: SubstrateInterface, block_hash: str) -> int:
        """Extract millisecond timestamp from Timestamp.set inherent."""
        try:
            block = substrate.get_block(block_hash=block_hash)
            for ext in block.get("extrinsics", []):
                call = ext.value.get("call", {})
                if call.get("call_module") == "Timestamp" and call.get("call_function") == "set":
                    args = call.get("call_args", [])
                    if args:
                        return args[0].get("value", 0)
        except Exception:
            pass
        return 0

    def _process_failed_extrinsics(
        self,
        substrate: SubstrateInterface,
        block_num: int,
        block_hash: str,
        timestamp: int,
        failed_ext_indices: dict[int, dict],
    ):
        """Decode failed extrinsics and store them in self.failed_submissions."""
        try:
            block = substrate.get_block(block_hash=block_hash)
            extrinsics = block.get("extrinsics", [])
        except Exception:
            # If we cannot get the block, still record what we know
            for ext_idx, error_info in failed_ext_indices.items():
                self._add_failed_submission({
                    "block_number": block_num,
                    "block_hash": block_hash,
                    "extrinsic_index": ext_idx,
                    "extrinsic_method": "unknown",
                    "account": None,
                    "error": error_info.get("error", "ExtrinsicFailed"),
                    "error_module": error_info.get("module", ""),
                    "error_name": error_info.get("name", ""),
                    "receipt_id": None,
                    "timestamp": timestamp,
                })
            return

        for ext_idx, error_info in failed_ext_indices.items():
            if ext_idx >= len(extrinsics):
                continue

            ext = extrinsics[ext_idx]
            try:
                val = ext.value if hasattr(ext, "value") else ext
                call = val.get("call", {}) if isinstance(val, dict) else {}
                call_module = call.get("call_module", "")
                call_function = call.get("call_function", "")
                signer = val.get("address", None) if isinstance(val, dict) else None
                method = f"{call_module}.{call_function}" if call_module else "unknown"

                # Try to extract receipt_id if this is a receipt submission call
                receipt_id = None
                if call_module == "OrinqReceipts" and call_function == "submit_receipt":
                    call_args = call.get("call_args", [])
                    for arg in call_args:
                        if isinstance(arg, dict) and arg.get("name") == "receipt_id":
                            receipt_id = _hex_hash(arg.get("value", ""))
                            break
                    # Fallback: first arg might be the receipt data struct
                    if receipt_id is None and call_args:
                        first_val = call_args[0].get("value", {}) if isinstance(call_args[0], dict) else {}
                        if isinstance(first_val, dict) and "receipt_id" in first_val:
                            receipt_id = _hex_hash(first_val["receipt_id"])

                self._add_failed_submission({
                    "block_number": block_num,
                    "block_hash": block_hash,
                    "extrinsic_index": ext_idx,
                    "extrinsic_method": method,
                    "account": str(signer) if signer else None,
                    "error": error_info.get("error", "ExtrinsicFailed"),
                    "error_module": error_info.get("module", ""),
                    "error_name": error_info.get("name", ""),
                    "receipt_id": receipt_id,
                    "timestamp": timestamp,
                })
            except Exception:
                self._add_failed_submission({
                    "block_number": block_num,
                    "block_hash": block_hash,
                    "extrinsic_index": ext_idx,
                    "extrinsic_method": "unknown",
                    "account": None,
                    "error": error_info.get("error", "ExtrinsicFailed"),
                    "error_module": error_info.get("module", ""),
                    "error_name": error_info.get("name", ""),
                    "receipt_id": None,
                    "timestamp": timestamp,
                })

    def _add_failed_submission(self, entry: dict):
        """Insert a failed submission at the front of the list, keeping the cap."""
        self.failed_submissions.insert(0, entry)
        if len(self.failed_submissions) > MAX_FAILED_SUBMISSIONS:
            self.failed_submissions = self.failed_submissions[:MAX_FAILED_SUBMISSIONS]

    def get_receipts_page(self, page: int, limit: int) -> tuple[list[dict], int]:
        """Return a page of receipts (newest first) and total count."""
        with self._lock:
            total = len(self.receipts)
            start = (page - 1) * limit
            end = start + limit
            return self.receipts[start:end], total

    def get_anchors_page(self, page: int, limit: int) -> tuple[list[dict], int]:
        """Return a page of anchors (newest first) and total count."""
        with self._lock:
            total = len(self.anchors)
            start = (page - 1) * limit
            end = start + limit
            return self.anchors[start:end], total

    def is_certified(self, receipt_id: str) -> bool:
        """Check if a receipt has been certified (from stored status)."""
        with self._lock:
            for r in self.receipts:
                if r["receipt_id"] == receipt_id:
                    return r.get("status") == "certified"
        return False

    def get_receipts_by_submitter(self, address: str) -> list[dict]:
        """Return all receipts submitted by an address."""
        with self._lock:
            return [r for r in self.receipts if r["submitter"] == address]

    def get_receipt_stats(self) -> dict:
        """Return count breakdown by status."""
        with self._lock:
            stats = {"total": len(self.receipts), "anchored": 0, "certified": 0,
                     "awaiting_cert": 0, "submitted": 0, "stale": 0,
                     "failed": len(self.failed_submissions)}
            for r in self.receipts:
                s = r.get("status", "stale")
                if s in stats:
                    stats[s] += 1
            return stats

    def get_recent_certified(self, limit: int = 10) -> list[dict]:
        """Return most recent certified or anchored receipts."""
        with self._lock:
            result = []
            for r in self.receipts:
                if r.get("status") in ("certified", "anchored"):
                    result.append(r)
                    if len(result) >= limit:
                        break
            return result

    def get_recent_failed(self, limit: int = 10) -> list[dict]:
        """Return most recent failed submissions."""
        with self._lock:
            return self.failed_submissions[:limit]

    def get_failed_for_receipt(self, receipt_id: str) -> Optional[dict]:
        """Look up a specific receipt_id in failed submissions."""
        with self._lock:
            for f in self.failed_submissions:
                if f.get("receipt_id") == receipt_id:
                    return f
        return None

    def get_filtered_receipts_page(self, page: int, limit: int, status_filter: str) -> tuple[list[dict], int]:
        """Return a filtered page of receipts and total matching count.
        Filters: anchored, certified (includes anchored), pending (submitted+awaiting_cert+stale), stale."""
        with self._lock:
            if status_filter == "anchored":
                filtered = [r for r in self.receipts if r.get("status") == "anchored"]
            elif status_filter == "certified":
                filtered = [r for r in self.receipts if r.get("status") in ("certified", "anchored")]
            elif status_filter == "pending":
                filtered = [r for r in self.receipts if r.get("status") in ("submitted", "awaiting_cert", "stale")]
            elif status_filter == "stale":
                filtered = [r for r in self.receipts if r.get("status") == "stale"]
            else:
                filtered = self.receipts

            total = len(filtered)
            start = (page - 1) * limit
            end = start + limit
            return filtered[start:end], total


# Global event index instance
event_index = EventIndex()
