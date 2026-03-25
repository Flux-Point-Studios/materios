"""Heartbeat sender — background thread that posts sr25519-signed heartbeats to the blob gateway."""

import json
import logging
import threading
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

DAEMON_VERSION = "1.1.0"

# Deterministic signing string format — pipe-delimited, fixed field order
SIGNING_PREFIX = "materios-heartbeat-v1"


class HeartbeatSender:
    """Background thread that sends periodic signed heartbeats."""

    def __init__(self, config, health_metrics_ref, metrics_lock, keypair):
        """
        Args:
            config: DaemonConfig instance
            health_metrics_ref: reference to health_server._metrics dict
            metrics_lock: threading.Lock for accessing metrics
            keypair: substrateinterface.Keypair for signing
        """
        self.config = config
        self._metrics = health_metrics_ref
        self._metrics_lock = metrics_lock
        self.keypair = keypair
        self._seq = 0
        self._seq_file = Path(config.data_dir) / "heartbeat-seq.json"
        self._start_time = time.time()
        self._load_seq()

    def _load_seq(self):
        """Load persisted seq counter for crash recovery."""
        try:
            if self._seq_file.exists():
                data = json.loads(self._seq_file.read_text())
                self._seq = data.get("seq", 0)
                logger.info(f"Loaded heartbeat seq={self._seq} from {self._seq_file}")
        except Exception as e:
            logger.warning(f"Failed to load heartbeat seq: {e}")

    def _save_seq(self):
        """Persist seq counter to disk."""
        try:
            self._seq_file.write_text(json.dumps({"seq": self._seq}))
        except Exception as e:
            logger.warning(f"Failed to save heartbeat seq: {e}")

    def _build_signing_string(self, validator_id, seq, timestamp, best_block,
                              finalized_block, finality_gap, pending_receipts,
                              certs_submitted, substrate_connected, version, uptime):
        """Build deterministic pipe-delimited signing string."""
        # substrate_connected as 1/0 integer
        sc = 1 if substrate_connected else 0
        return (
            f"{SIGNING_PREFIX}|{validator_id}|{seq}|{timestamp}|{best_block}|"
            f"{finalized_block}|{finality_gap}|{pending_receipts}|{certs_submitted}|"
            f"{sc}|{version}|{uptime}"
        )

    def _send_heartbeat(self):
        """Build, sign, and POST one heartbeat."""
        try:
            # Read current metrics
            with self._metrics_lock:
                best_block = self._metrics.get("last_processed_block", 0)
                finalized_block = self._metrics.get("finalized_head", 0)
                finality_gap = self._metrics.get("finality_gap", 0)
                pending_receipts = self._metrics.get("pending_receipts", 0)
                certs_submitted = self._metrics.get("certs_submitted_total", 0)
                substrate_connected = self._metrics.get("substrate_connected", False)

            validator_id = self.keypair.ss58_address
            self._seq += 1
            seq = self._seq
            timestamp = int(time.time())
            uptime = int(time.time() - self._start_time)

            # Build signing string
            signing_string = self._build_signing_string(
                validator_id, seq, timestamp, best_block,
                finalized_block, finality_gap, pending_receipts,
                certs_submitted, substrate_connected, DAEMON_VERSION, uptime
            )

            # Sign with sr25519
            sig_bytes = self.keypair.sign(signing_string.encode("utf-8"))
            sig_hex = "0x" + sig_bytes.hex()

            # Build payload (label NOT included — gateway uses server-side label)
            payload = {
                "validator_id": validator_id,
                "seq": seq,
                "timestamp": timestamp,
                "best_block": best_block,
                "finalized_block": finalized_block,
                "finality_gap": finality_gap,
                "pending_receipts": pending_receipts,
                "certs_submitted": certs_submitted,
                "substrate_connected": substrate_connected,
                "version": DAEMON_VERSION,
                "uptime_seconds": uptime,
            }

            # POST to gateway
            url = f"{self.config.heartbeat_url}/heartbeats"
            headers = {
                "Content-Type": "application/json",
                "x-heartbeat-sig": sig_hex,
            }
            if self.config.blob_gateway_api_key:
                headers["x-api-key"] = self.config.blob_gateway_api_key

            resp = requests.post(url, json=payload, headers=headers, timeout=5)

            if resp.status_code == 200:
                logger.debug(f"Heartbeat sent: seq={seq} block={best_block}")
            else:
                logger.warning(f"Heartbeat rejected: {resp.status_code} {resp.text[:200]}")

            self._save_seq()

        except requests.exceptions.RequestException as e:
            logger.warning(f"Heartbeat send failed (network): {e}")
        except Exception as e:
            logger.error(f"Heartbeat send error: {e}", exc_info=True)

    def run_loop(self):
        """Main loop — runs in background daemon thread."""
        logger.info(
            f"Heartbeat sender started: url={self.config.heartbeat_url} "
            f"interval={self.config.heartbeat_interval}s "
            f"validator={self.keypair.ss58_address}"
        )
        while True:
            self._send_heartbeat()
            time.sleep(self.config.heartbeat_interval)


def start_heartbeat_sender(config, health_metrics_ref, metrics_lock, keypair):
    """Start heartbeat sender in a daemon thread."""
    sender = HeartbeatSender(config, health_metrics_ref, metrics_lock, keypair)
    thread = threading.Thread(target=sender.run_loop, daemon=True, name="heartbeat-sender")
    thread.start()
    return sender
