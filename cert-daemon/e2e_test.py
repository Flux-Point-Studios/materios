#!/usr/bin/env python3
"""
End-to-end test: submit 5 receipts with blobs, verify daemon produces certs.

Run inside the daemon pod:
  kubectl cp materios-cert-daemon/e2e_test.py materios/<pod>:/tmp/e2e_test.py
  kubectl exec -n materios deploy/materios-cert-daemon -- python /tmp/e2e_test.py

Or from a machine with substrate-interface + cbor2 installed:
  MATERIOS_RPC_URL=wss://materios.fluxpointstudios.com/rpc python e2e_test.py
"""

import hashlib
import json
import os
import sys
import time
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# ---------------------------------------------------------------------------
# Merkle tree (matches daemon/merkle.py exactly)
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    if not leaf_hashes:
        return b'\x00' * 32
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    nodes = list(leaf_hashes)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        next_level = []
        for i in range(0, len(nodes), 2):
            next_level.append(sha256(nodes[i] + nodes[i + 1]))
        nodes = next_level
    return nodes[0]


# ---------------------------------------------------------------------------
# Blob chunk server — serves chunks over HTTP on localhost for verification
# ---------------------------------------------------------------------------

_chunk_store: dict[str, bytes] = {}  # path -> data

class ChunkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = _chunk_store.get(self.path)
        if data is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass

def start_chunk_server(port: int = 9999) -> HTTPServer:
    server = HTTPServer(("0.0.0.0", port), ChunkHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ---------------------------------------------------------------------------
# Generate test receipt data
# ---------------------------------------------------------------------------

def generate_test_receipt(receipt_num: int, chunk_count: int = 3, chunk_server_port: int = 9999):
    """Generate blob chunks, compute hashes, build manifest, return receipt params."""
    receipt_id = "0x" + sha256(f"test-receipt-{receipt_num}-{secrets.token_hex(8)}".encode()).hex()
    chunks = []
    chunk_hashes = []
    blob_dir = os.environ.get("BLOB_LOCAL_DIR", "/data/materios-blobs")

    for i in range(chunk_count):
        data = f"test-blob-{receipt_num}-chunk-{i}-{secrets.token_hex(16)}".encode()
        h = sha256(data)
        chunk_hashes.append(h)

        # Write chunk to PVC and serve via HTTP
        path = f"/blobs/{receipt_id[2:]}/chunk_{i}"
        _chunk_store[path] = data

        # Also write chunk to disk as backup
        chunk_dir = os.path.join(blob_dir, receipt_id[2:])
        os.makedirs(chunk_dir, exist_ok=True)
        with open(os.path.join(chunk_dir, f"chunk_{i}"), "wb") as f:
            f.write(data)

        chunks.append({
            "url": f"http://127.0.0.1:{chunk_server_port}{path}",
            "sha256": h.hex(),
            "size": len(data),
        })

    root = merkle_root(chunk_hashes)
    content_hash = sha256(f"content-{receipt_num}".encode())
    schema_hash = sha256(b"materios-schema-v1")
    base_manifest_hash = sha256(json.dumps(chunks, sort_keys=True).encode())
    safety_manifest_hash = sha256(b"safety-manifest-placeholder")
    monitor_config_hash = sha256(b"monitor-config-placeholder")
    attestation_evidence_hash = sha256(b"attestation-evidence-placeholder")
    storage_locator_hash = sha256(f"locator-{receipt_id}".encode())

    manifest = {
        "chunks": chunks,
        "total_size": sum(c["size"] for c in chunks),
    }

    return {
        "receipt_id": receipt_id,
        "content_hash": content_hash,
        "base_root_sha256": root,
        "schema_hash": schema_hash,
        "base_manifest_hash": base_manifest_hash,
        "safety_manifest_hash": safety_manifest_hash,
        "monitor_config_hash": monitor_config_hash,
        "attestation_evidence_hash": attestation_evidence_hash,
        "storage_locator_hash": storage_locator_hash,
        "manifest": manifest,
    }


# ---------------------------------------------------------------------------
# Submit receipt to Materios chain
# ---------------------------------------------------------------------------

def submit_receipt(substrate, keypair, params: dict):
    """Submit a receipt extrinsic and wait for finalization."""
    call = substrate.compose_call(
        call_module="OrinqReceipts",
        call_function="submit_receipt",
        call_params={
            "receipt_id": params["receipt_id"],
            "content_hash": "0x" + params["content_hash"].hex() if isinstance(params["content_hash"], bytes) else params["content_hash"],
            "base_root_sha256": list(params["base_root_sha256"]),
            "zk_root_poseidon": None,
            "poseidon_params_hash": None,
            "base_manifest_hash": list(params["base_manifest_hash"]),
            "safety_manifest_hash": list(params["safety_manifest_hash"]),
            "monitor_config_hash": list(params["monitor_config_hash"]),
            "attestation_evidence_hash": list(params["attestation_evidence_hash"]),
            "storage_locator_hash": list(params["storage_locator_hash"]),
            "schema_hash": list(params["schema_hash"]),
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    return receipt


def check_receipt_cert(substrate, receipt_id: str) -> bytes:
    """Query on-chain receipt and return availability_cert_hash."""
    result = substrate.query(
        module="OrinqReceipts",
        storage_function="Receipts",
        params=[receipt_id],
    )
    if result.value is None:
        return b'\x00' * 32
    cert = result.value["availability_cert_hash"]
    if isinstance(cert, str):
        return bytes.fromhex(cert.removeprefix("0x"))
    if isinstance(cert, list):
        return bytes(cert)
    return cert


# ---------------------------------------------------------------------------
# Place manifest on daemon's filesystem
# ---------------------------------------------------------------------------

def place_manifest(receipt_id: str, manifest: dict, blob_dir: str = "/data/materios-blobs"):
    """Write manifest.json to the daemon's blob directory."""
    clean_id = receipt_id.removeprefix("0x")
    manifest_dir = os.path.join(blob_dir, clean_id)
    os.makedirs(manifest_dir, exist_ok=True)
    manifest_path = os.path.join(manifest_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)
    return manifest_path


# ---------------------------------------------------------------------------
# Main E2E test
# ---------------------------------------------------------------------------

def main():
    from substrateinterface import SubstrateInterface, Keypair

    rpc_url = os.environ.get("MATERIOS_RPC_URL", "ws://materios-rpc.materios.svc.cluster.local:9944")
    blob_dir = os.environ.get("BLOB_LOCAL_DIR", "/data/materios-blobs")
    num_receipts = int(os.environ.get("NUM_RECEIPTS", "5"))
    chunk_server_port = 9999

    print(f"=== Materios Cert Daemon E2E Test ===")
    print(f"RPC: {rpc_url}")
    print(f"Blob dir: {blob_dir}")
    print(f"Receipts to submit: {num_receipts}")
    print()

    # Start chunk server
    print("[1/5] Starting chunk server on :{chunk_server_port}...")
    server = start_chunk_server(chunk_server_port)
    print(f"  Chunk server running")

    # Connect to substrate
    print(f"[2/5] Connecting to Materios chain...")
    substrate = SubstrateInterface(url=rpc_url)
    # Use Bob for receipt submission so we don't collide nonces with daemon (Alice)
    keypair = Keypair.create_from_uri("//Bob")
    print(f"  Connected: chain={substrate.chain}, finalized={substrate.get_chain_finalised_head()}")

    # Generate and submit receipts
    print(f"[3/5] Generating {num_receipts} test receipts with blobs...")
    receipt_ids = []
    for i in range(num_receipts):
        params = generate_test_receipt(i, chunk_count=3, chunk_server_port=chunk_server_port)
        receipt_id = params["receipt_id"]

        # Place manifest on filesystem for daemon to find
        manifest_path = place_manifest(receipt_id, params["manifest"], blob_dir)
        print(f"  [{i+1}] Receipt {receipt_id[:18]}...")
        print(f"       Merkle root: {params['base_root_sha256'].hex()[:16]}...")
        print(f"       Manifest: {manifest_path}")

        # Submit on-chain
        try:
            result = submit_receipt(substrate, keypair, params)
            if result.is_success:
                print(f"       Submitted in block {result.block_hash[:18]}...")
                receipt_ids.append(receipt_id)
            else:
                print(f"       FAILED: {result.error_message}")
        except Exception as e:
            print(f"       FAILED: {e}")

    if not receipt_ids:
        print("\nERROR: No receipts submitted successfully!")
        server.shutdown()
        sys.exit(1)

    print(f"\n  {len(receipt_ids)}/{num_receipts} receipts submitted successfully")

    # Wait for daemon to process
    print(f"\n[4/5] Waiting for daemon to detect events and submit certs...")
    print(f"  (Daemon polls every 12s, cert submission takes ~6-12s per receipt)")
    max_wait = 180  # 3 minutes
    check_interval = 10
    start = time.time()
    certified = set()

    while time.time() - start < max_wait and len(certified) < len(receipt_ids):
        time.sleep(check_interval)
        elapsed = int(time.time() - start)
        for rid in receipt_ids:
            if rid in certified:
                continue
            cert_hash = check_receipt_cert(substrate, rid)
            if cert_hash != b'\x00' * 32:
                certified.add(rid)
                print(f"  [{elapsed}s] CERTIFIED: {rid[:18]}... -> cert_hash={cert_hash.hex()[:16]}...")
        pending = len(receipt_ids) - len(certified)
        if pending > 0:
            print(f"  [{elapsed}s] Waiting... {len(certified)}/{len(receipt_ids)} certified, {pending} pending")

    # Results
    print(f"\n[5/5] === RESULTS ===")
    print(f"  Receipts submitted: {len(receipt_ids)}")
    print(f"  Certs issued:       {len(certified)}")

    for rid in receipt_ids:
        cert_hash = check_receipt_cert(substrate, rid)
        status = "CERTIFIED" if cert_hash != b'\x00' * 32 else "PENDING"
        print(f"  {rid[:18]}... {status}")
        if cert_hash != b'\x00' * 32:
            print(f"    cert_hash: {cert_hash.hex()}")

    # Check daemon metrics
    try:
        import urllib.request
        metrics = urllib.request.urlopen("http://localhost:8080/metrics").read().decode()
        print(f"\n  Daemon metrics:")
        for line in metrics.strip().split("\n"):
            print(f"    {line}")
    except Exception:
        print(f"\n  (Could not read daemon metrics — running outside pod?)")

    server.shutdown()

    if len(certified) == len(receipt_ids):
        print(f"\n  ALL {len(certified)} RECEIPTS CERTIFIED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print(f"\n  WARNING: {len(receipt_ids) - len(certified)} receipts NOT certified within {max_wait}s")
        sys.exit(1)


if __name__ == "__main__":
    main()
