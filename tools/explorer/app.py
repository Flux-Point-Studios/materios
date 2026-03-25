"""Materios Explorer — blockchain explorer for the Materios Partner Chain.

Run:
    pip install fastapi uvicorn substrate-interface
    MATERIOS_RPC_URL=ws://127.0.0.1:9944 python app.py
"""

import argparse
import json
import logging
import os
import re
import sys

import requests as req
from substrateinterface.utils.ss58 import ss58_decode

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "materios-verify"))

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from materios_verify.core import (
    verify_receipt,
    query_receipt,
    query_committee,
    query_anchor,
    _hex,
    _to_bytes32,
    ZERO_HASH,
)

from .cache import cache
from .chain import get_substrate, event_index, RPC_URL, ZERO_HASH as CHAIN_ZERO_HASH

logger = logging.getLogger(__name__)

ROOT_PATH = os.environ.get("ROOT_PATH", "")
BLOB_GATEWAY_URL = os.environ.get("BLOB_GATEWAY_URL", "")
BLOB_GATEWAY_API_KEY = os.environ.get("BLOB_GATEWAY_API_KEY", "")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="Materios Explorer", version="0.2.0", root_path=ROOT_PATH)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def _fetch_chain_info():
    """Compute chain-info payload (used by endpoint and cache warmup)."""
    try:
        s = get_substrate()
        genesis = s.get_block_hash(0) or ""
        best = s.get_block_header()["header"]["number"]

        # Finalized block
        finalized = best
        try:
            fh = s.get_chain_finalised_head()
            if fh:
                fb = s.get_block_header(fh)
                finalized = fb["header"]["number"]
        except Exception:
            pass

        receipt_count = s.query("OrinqReceipts", "ReceiptCount")
        members, threshold = query_committee(s)

        # MOTRA stats
        motra = {}
        try:
            ti = s.query("Motra", "TotalIssued")
            tb = s.query("Motra", "TotalBurned")
            motra = {
                "total_issued": str(ti.value) if ti else "0",
                "total_burned": str(tb.value) if tb else "0",
            }
        except Exception:
            pass

        # Trigger incremental event scan (non-blocking)
        import threading
        threading.Thread(target=event_index.scan_new_blocks, daemon=True).start()

        return {
            "chain": s.chain or "Materios",
            "genesis_hash": genesis,
            "best_block": best,
            "finalized_block": finalized,
            "receipt_count": receipt_count.value if receipt_count else 0,
            "committee": {
                "size": len(members),
                "threshold": threshold,
                "members": [str(m) for m in members],
            },
            "motra": motra,
            "receipt_stats": event_index.get_receipt_stats(),
            "rpc_url": RPC_URL,
        }
    except Exception as e:
        return {"error": str(e)}


@app.on_event("startup")
async def startup():
    """Trigger background loading of receipts/anchors on startup."""
    event_index.ensure_initialized()

    # Pre-warm critical caches in background so first visitor doesn't wait
    import threading
    import time as _time

    def _warm():
        for _ in range(60):
            if event_index._initialized:
                break
            _time.sleep(1)
        try:
            cache.get_or_compute("chain-info", _fetch_chain_info, ttl=15.0)
        except Exception:
            pass
        logger.info("Cache pre-warm complete")

    threading.Thread(target=_warm, daemon=True).start()


# ---------------------------------------------------------------------------
# HTML shell
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    with open(html_path) as f:
        return HTMLResponse(f.read())


# ---------------------------------------------------------------------------
# Chain Info (enhanced)
# ---------------------------------------------------------------------------

@app.get("/api/chain-info")
async def chain_info():
    return cache.get_or_compute("chain-info", _fetch_chain_info, ttl=15.0)


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------

@app.get("/api/blocks")
async def list_blocks(page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=50)):
    def _fetch():
        try:
            s = get_substrate()
            best = s.get_block_header()["header"]["number"]
            start = best - (page - 1) * limit
            blocks = []
            for num in range(start, max(start - limit, 0), -1):
                b = cache.get(f"block-summary:{num}")
                if b:
                    blocks.append(b)
                    continue
                try:
                    bh = s.get_block_hash(num)
                    if not bh:
                        continue
                    block = s.get_block(block_hash=bh)
                    header = block["header"] if "header" in block else s.get_block_header(bh)["header"]
                    extrinsics = block.get("extrinsics", [])

                    # Count events
                    events_count = 0
                    try:
                        events = s.get_events(block_hash=bh)
                        events_count = len(events)
                    except Exception:
                        pass

                    # Extract timestamp
                    timestamp = _extract_timestamp(extrinsics)

                    summary = {
                        "number": num,
                        "hash": bh,
                        "parent_hash": header.get("parentHash", header.get("parent_hash", "")),
                        "extrinsics_count": len(extrinsics),
                        "events_count": events_count,
                        "timestamp": timestamp,
                    }
                    cache.set(f"block-summary:{num}", summary, ttl=-1)  # permanent
                    blocks.append(summary)
                except Exception:
                    continue

            return {"blocks": blocks, "best_block": best}
        except Exception as e:
            return {"error": str(e), "blocks": []}

    return cache.get_or_compute(f"blocks-list:{page}:{limit}", _fetch, ttl=30.0)


@app.get("/api/block/{block_id}")
async def get_block(block_id: str):
    def _fetch():
        try:
            s = get_substrate()
            # Accept block number or hash
            if block_id.startswith("0x"):
                bh = block_id
                header = s.get_block_header(bh)["header"]
                num = header["number"]
            else:
                num = int(block_id)
                bh = s.get_block_hash(num)
                if not bh:
                    return {"error": f"Block #{num} not found"}
                header = s.get_block_header(bh)["header"]

            block = s.get_block(block_hash=bh)
            raw_extrinsics = block.get("extrinsics", [])

            # Parse events first to determine extrinsic success/failure
            events = []
            failed_indices = set()
            try:
                raw_events = s.get_events(block_hash=bh)
                for i, ev in enumerate(raw_events):
                    val = ev.value if hasattr(ev, 'value') else ev
                    events.append({
                        "index": i,
                        "module": val.get("module_id", "?"),
                        "event": val.get("event_id", "?"),
                        "phase": str(val.get("phase", "")),
                        "attributes": _safe_attrs(val.get("attributes", {})),
                    })
                    # Track failed extrinsic indices
                    if val.get("module_id") == "System" and val.get("event_id") == "ExtrinsicFailed":
                        phase = val.get("phase", {})
                        ext_idx = None
                        if isinstance(phase, dict):
                            ext_idx = phase.get("ApplyExtrinsic")
                        elif isinstance(phase, (list, tuple)) and len(phase) >= 2:
                            ext_idx = phase[1] if phase[0] == "ApplyExtrinsic" else None
                        elif isinstance(phase, int):
                            ext_idx = phase
                        if ext_idx is not None:
                            failed_indices.add(int(ext_idx))
            except Exception:
                pass

            # Parse extrinsics
            extrinsics = []
            for i, ext in enumerate(raw_extrinsics):
                try:
                    val = ext.value if hasattr(ext, 'value') else ext
                    call = val.get("call", {}) if isinstance(val, dict) else {}
                    extrinsics.append({
                        "index": i,
                        "module": call.get("call_module", "?"),
                        "call": call.get("call_function", "?"),
                        "signer": val.get("address", None) if isinstance(val, dict) else None,
                        "success": i not in failed_indices,
                    })
                except Exception:
                    extrinsics.append({"index": i, "module": "?", "call": "?", "signer": None, "success": i not in failed_indices})

            timestamp = _extract_timestamp(raw_extrinsics)

            return {
                "number": num,
                "hash": bh,
                "parent_hash": header.get("parentHash", header.get("parent_hash", "")),
                "state_root": header.get("stateRoot", header.get("state_root", "")),
                "extrinsics_root": header.get("extrinsicsRoot", header.get("extrinsics_root", "")),
                "timestamp": timestamp,
                "extrinsics": extrinsics,
                "events": events,
            }
        except Exception as e:
            return {"error": str(e)}

    return cache.get_or_compute(f"block-detail:{block_id}", _fetch, ttl=-1)


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

@app.get("/api/receipts")
async def list_receipts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str = Query("", pattern="^(anchored|certified|pending|stale|)$"),
):
    cache_key = f"receipts-list:{page}:{limit}:{status}"

    def _fetch():
        try:
            event_index.ensure_initialized()
            if status:
                items, total = event_index.get_filtered_receipts_page(page, limit, status)
            else:
                items, total = event_index.get_receipts_page(page, limit)

            # Use on-chain count as total if no filter and it's larger
            if not status:
                try:
                    s = get_substrate()
                    rc = s.query("OrinqReceipts", "ReceiptCount")
                    chain_total = rc.value if rc else 0
                    total = max(total, chain_total)
                except Exception:
                    pass

            return {"receipts": items, "total": total, "page": page, "limit": limit}
        except Exception as e:
            return {"error": str(e), "receipts": [], "total": 0}

    return cache.get_or_compute(cache_key, _fetch, ttl=30.0)


@app.get("/api/receipts/recent-certified")
async def recent_certified(limit: int = Query(10, ge=1, le=50)):
    def _fetch():
        try:
            event_index.ensure_initialized()
            items = event_index.get_recent_certified(limit)
            return {"receipts": items}
        except Exception as e:
            return {"error": str(e), "receipts": []}

    return cache.get_or_compute(f"recent-certified:{limit}", _fetch, ttl=30.0)


@app.get("/api/receipts/recent-failed")
async def recent_failed(limit: int = Query(10, ge=1, le=50)):
    """Recent failed receipt submission attempts."""
    def _fetch():
        try:
            event_index.ensure_initialized()
            items = event_index.get_recent_failed(limit)
            return {"failures": items, "total": len(items)}
        except Exception as e:
            return {"error": str(e), "failures": [], "total": 0}

    return cache.get_or_compute(f"recent-failed:{limit}", _fetch, ttl=15.0)


@app.get("/api/receipt/{receipt_id}")
async def get_receipt(receipt_id: str):
    def _fetch():
        try:
            if not receipt_id.startswith("0x"):
                rid = "0x" + receipt_id
            else:
                rid = receipt_id
            s = get_substrate()
            receipt = query_receipt(s, rid)
            if receipt is None:
                # Check if there's a known failure for this receipt_id
                failure = event_index.get_failed_for_receipt(rid)
                if failure:
                    return {
                        "error": "Receipt not found (submission failed)",
                        "failure": failure,
                    }
                return {"error": "Receipt not found"}

            cert_hash = _to_bytes32(receipt["availability_cert_hash"])
            status = "certified" if cert_hash != ZERO_HASH else "pending"

            return {
                "receipt_id": rid,
                "status": status,
                "submitter": receipt.get("submitter", "unknown"),
                "content_hash": _hex(_to_bytes32(receipt["content_hash"])),
                "base_root_sha256": _hex(_to_bytes32(receipt["base_root_sha256"])),
                "availability_cert_hash": _hex(cert_hash),
                "schema_hash": _hex(_to_bytes32(receipt["schema_hash"])),
                "storage_locator_hash": _hex(_to_bytes32(receipt["storage_locator_hash"])),
                "base_manifest_hash": _hex(_to_bytes32(receipt["base_manifest_hash"])),
                "safety_manifest_hash": _hex(_to_bytes32(receipt["safety_manifest_hash"])),
                "monitor_config_hash": _hex(_to_bytes32(receipt["monitor_config_hash"])),
                "attestation_evidence_hash": _hex(_to_bytes32(receipt["attestation_evidence_hash"])),
                "created_at_millis": receipt.get("created_at_millis", 0),
            }
        except Exception as e:
            return {"error": str(e)}

    return cache.get_or_compute(f"receipt:{receipt_id}", _fetch, ttl=30.0)


@app.get("/api/extrinsics")
async def list_extrinsics(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100)):
    def _fetch():
        try:
            event_index.ensure_initialized()
            items, total = event_index.get_extrinsics_page(page, limit)
            return {"extrinsics": items, "total": total, "page": page, "limit": limit}
        except Exception as e:
            return {"error": str(e), "extrinsics": [], "total": 0}

    return cache.get_or_compute(f"extrinsics-list:{page}:{limit}", _fetch, ttl=15.0)


@app.get("/api/extrinsic/{tx_hash}")
async def get_extrinsic(tx_hash: str):
    """Return a single extrinsic detail by tx hash."""
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    def _fetch():
        event_index.ensure_initialized()
        ext = event_index.get_extrinsic_by_hash(tx_hash)
        if ext:
            return ext
        return {"error": "Extrinsic not found"}

    return cache.get_or_compute(f"extrinsic:{tx_hash}", _fetch, ttl=30.0)


@app.get("/api/tx/{tx_hash}")
async def get_tx(tx_hash: str):
    """Look up a transaction/extrinsic hash and resolve to its receipt or extrinsic."""
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    receipt_id = event_index.lookup_tx_hash(tx_hash)
    if receipt_id:
        return {"type": "receipt", "receipt_id": receipt_id}

    # Check extrinsic index
    ext = event_index.get_extrinsic_by_hash(tx_hash)
    if ext:
        return {"type": "tx", "tx_hash": tx_hash, **ext}

    return {"error": "Transaction not found. The tx hash index is built from recent blocks on startup — if this is an older transaction, it may not yet be indexed."}


# ---------------------------------------------------------------------------
# Verification (subprocess-based)
# ---------------------------------------------------------------------------

@app.get("/api/verify/{receipt_id}")
async def verify(receipt_id: str, scan_window: int = 15):
    """Run verification in a subprocess so it can be hard-killed on timeout."""
    import asyncio

    script = f"""
import json, sys
sys.path.insert(0, '/app/materios-verify')
sys.path.insert(0, {os.path.join(os.path.dirname(__file__), '..', 'materios-verify')!r})
from materios_verify.core import verify_receipt
report = verify_receipt(receipt_id={receipt_id!r}, rpc_url={RPC_URL!r}, scan_window={scan_window!r})
print(json.dumps(report.to_dict()))
"""
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=25.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return JSONResponse(
                {"error": "Verification timed out (25s). The receipt may be too old for the pruned RPC node."},
                status_code=504,
            )

        if proc.returncode != 0:
            err = stderr.decode().strip().split("\n")[-1] if stderr else "unknown error"
            return JSONResponse({"error": f"Verification failed: {err}"}, status_code=500)

        return json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        return JSONResponse({"error": f"Invalid verification output: {e}"}, status_code=500)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------

@app.get("/api/anchors")
async def list_anchors(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100)):
    def _fetch():
        try:
            event_index.ensure_initialized()
            items, total = event_index.get_anchors_page(page, limit)
            return {"anchors": items, "total": total, "page": page, "limit": limit}
        except Exception as e:
            return {"error": str(e), "anchors": [], "total": 0}

    return cache.get_or_compute(f"anchors-list:{page}:{limit}", _fetch, ttl=30.0)


@app.get("/api/anchor/{anchor_id}")
async def get_anchor(anchor_id: str):
    def _fetch():
        try:
            if not anchor_id.startswith("0x"):
                aid = "0x" + anchor_id
            else:
                aid = anchor_id
            s = get_substrate()
            anchor = query_anchor(s, aid)
            if anchor is None:
                return {"error": "Anchor not found"}

            return {
                "anchor_id": aid,
                "content_hash": _hex(_to_bytes32(anchor.get("content_hash", b""))),
                "root_hash": _hex(_to_bytes32(anchor.get("root_hash", b""))),
                "manifest_hash": _hex(_to_bytes32(anchor.get("manifest_hash", b""))),
                "submitter": str(anchor.get("submitter", "unknown")),
                "created_at_millis": anchor.get("created_at_millis", 0),
            }
        except Exception as e:
            return {"error": str(e)}

    return cache.get_or_compute(f"anchor:{anchor_id}", _fetch, ttl=-1)


# ---------------------------------------------------------------------------
# Committee Health
# ---------------------------------------------------------------------------

@app.get("/api/committee/health")
async def committee_health():
    def _fetch():
        try:
            s = get_substrate()
            members, threshold = query_committee(s)

            # Fetch heartbeat status from gateway
            heartbeat_data = {}
            if BLOB_GATEWAY_URL:
                try:
                    resp = req.get(
                        f"{BLOB_GATEWAY_URL}/heartbeats/status",
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        heartbeat_data = resp.json()
                except Exception as e:
                    logger.warning(f"Failed to fetch heartbeat status: {e}")

            validators_hb = heartbeat_data.get("validators", {})

            # Build pubkey-hex → heartbeat data mapping to handle SS58 prefix mismatch
            # (on-chain may use prefix 0, daemon uses prefix 42)
            hb_by_pubkey = {}
            for hb_addr, hb_val in validators_hb.items():
                try:
                    pk = ss58_decode(hb_addr)
                    hb_by_pubkey[pk] = hb_val
                except Exception:
                    pass

            # Merge on-chain committee with heartbeat data
            member_list = []
            online_count = 0
            for m in members:
                addr = str(m)
                # Look up by raw public key to handle different SS58 prefixes
                try:
                    pk = ss58_decode(addr)
                    hb = hb_by_pubkey.get(pk, {})
                except Exception:
                    hb = validators_hb.get(addr, {})
                status = hb.get("status", "no_heartbeat")
                if status == "online":
                    online_count += 1

                member_list.append({
                    "address": addr,
                    "label": hb.get("label", ""),
                    "status": status,
                    "verified": hb.get("verified", False),
                    "verified_mode": hb.get("verified_mode", ""),
                    "age_secs": hb.get("age_secs"),
                    "seq": hb.get("seq", 0),
                    "best_block": hb.get("best_block", 0),
                    "finalized_block": hb.get("finalized_block", 0),
                    "finality_gap": hb.get("finality_gap", 0),
                    "pending_receipts": hb.get("pending_receipts", 0),
                    "certs_submitted": hb.get("certs_submitted", 0),
                    "substrate_connected": hb.get("substrate_connected", True),
                    "version": hb.get("version", ""),
                    "uptime_seconds": hb.get("uptime_seconds", 0),
                    "clock_skew_secs": hb.get("clock_skew_secs", 0),
                })

            threshold_met = online_count >= threshold

            return {
                "members": member_list,
                "threshold": threshold,
                "total": len(members),
                "online": online_count,
                "threshold_met": threshold_met,
            }
        except Exception as e:
            return {"error": str(e)}

    return cache.get_or_compute("committee-health", _fetch, ttl=15.0)


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

@app.get("/api/account/{address}")
async def get_account(address: str):
    def _fetch():
        try:
            s = get_substrate()

            # MATRA balance (native)
            matra_balance = 0
            nonce = 0
            try:
                account_info = s.query("System", "Account", [address])
                if account_info:
                    data = account_info.value.get("data", {})
                    matra_balance = data.get("free", 0)
                    nonce = account_info.value.get("nonce", 0)
            except Exception:
                pass

            # MOTRA balance
            motra_balance = 0
            try:
                mb = s.query("Motra", "MotraBalances", [address])
                if mb:
                    motra_balance = mb.value
            except Exception:
                pass

            # Committee membership
            members, threshold = query_committee(s)
            is_committee = address in [str(m) for m in members]

            # Receipts by this submitter
            event_index.ensure_initialized()
            submitted = event_index.get_receipts_by_submitter(address)
            receipts = []
            for r in submitted[:50]:  # cap at 50
                status = "certified" if event_index.is_certified(r["receipt_id"]) else "pending"
                receipts.append({
                    "receipt_id": r["receipt_id"],
                    "status": status,
                    "block_num": r["block_num"],
                    "timestamp": r.get("timestamp", 0),
                    "submitter": r["submitter"],
                })

            return {
                "address": address,
                "matra_balance": str(matra_balance),
                "motra_balance": str(motra_balance),
                "nonce": nonce,
                "is_committee_member": is_committee,
                "receipts_submitted": receipts,
            }
        except Exception as e:
            return {"error": str(e)}

    return cache.get_or_compute(f"account:{address}", _fetch, ttl=30.0)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.get("/api/search")
async def search(q: str = Query("")):
    q = q.strip()
    if not q:
        return {"type": "unknown", "id": ""}

    # Block number
    if re.match(r'^\d+$', q):
        return {"type": "block", "id": q}

    # Hex hash (receipt or anchor or tx hash or block hash)
    if re.match(r'^0x[0-9a-fA-F]{64}$', q):
        # Try receipt first
        try:
            s = get_substrate()
            receipt = query_receipt(s, q)
            if receipt is not None:
                return {"type": "receipt", "id": q}
            anchor = query_anchor(s, q)
            if anchor is not None:
                return {"type": "anchor", "id": q}
        except Exception:
            pass
        # Try tx hash -> receipt mapping from in-memory index
        receipt_id = event_index.lookup_tx_hash(q)
        if receipt_id:
            return {"type": "receipt", "id": receipt_id}
        # Try extrinsic index (general tx hash)
        ext = event_index.get_extrinsic_by_hash(q)
        if ext:
            return {"type": "tx", "id": q}
        return {"type": "receipt", "id": q}  # default to receipt even if not found

    # SS58 address (starts with 5, roughly 47-48 chars)
    if re.match(r'^[1-9A-HJ-NP-Za-km-z]{46,48}$', q):
        return {"type": "account", "id": q}

    return {"type": "unknown", "id": q}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_timestamp(extrinsics) -> int:
    """Extract millisecond timestamp from Timestamp.set inherent."""
    for ext in extrinsics:
        try:
            val = ext.value if hasattr(ext, 'value') else ext
            call = val.get("call", {}) if isinstance(val, dict) else {}
            if call.get("call_module") == "Timestamp" and call.get("call_function") == "set":
                args = call.get("call_args", [])
                if args:
                    return args[0].get("value", 0)
        except Exception:
            continue
    return 0


def _safe_attrs(attrs) -> dict:
    """Convert event attributes to JSON-safe dict."""
    if isinstance(attrs, dict):
        return {k: str(v) for k, v in attrs.items()}
    if isinstance(attrs, (list, tuple)):
        return {f"arg{i}": str(v) for i, v in enumerate(attrs)}
    return {}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Materios Explorer")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    import uvicorn
    print(f"Starting Materios Explorer on http://{args.host}:{args.port}")
    print(f"RPC: {RPC_URL}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
