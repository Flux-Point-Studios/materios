"""Watchtower — monitors committee heartbeats and alerts on degradation.

Usage:
    python -m daemon.watchtower

Environment variables:
    BLOB_GATEWAY_URL    - Gateway base URL (e.g. https://materios.fluxpointstudios.com/blobs)
    BLOB_GATEWAY_API_KEY - API key (optional — /heartbeats/status is public)
    DISCORD_WEBHOOK_URL - Discord webhook for alerts
    WATCHTOWER_POLL_INTERVAL - Poll interval in seconds (default: 30)
    WATCHTOWER_THRESHOLD - Override committee threshold (default: auto from heartbeat status)

Designed to run BOTH inside and outside the FPS cluster:
    - Inside: uses K8s service URL
    - Outside: uses public URL (https://materios.fluxpointstudios.com/blobs)
    Only needs /heartbeats/status which is PUBLIC (no auth required).
"""

import json
import logging
import os
import sys
import time
from datetime import datetime

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("watchtower")


class Watchtower:
    def __init__(self):
        self.gateway_url = os.environ.get("BLOB_GATEWAY_URL", "")
        self.discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.poll_interval = int(os.environ.get("WATCHTOWER_POLL_INTERVAL", "30"))
        self.threshold_override = os.environ.get("WATCHTOWER_THRESHOLD", "")

        if not self.gateway_url:
            logger.error("BLOB_GATEWAY_URL is required")
            sys.exit(1)

        # Dedup: track last alert time per condition key
        self._last_alert: dict[str, float] = {}
        self._alert_cooldown = 300  # 5 minutes

    def _should_alert(self, key: str) -> bool:
        """Dedup alerts — max 1 per key per cooldown period."""
        now = time.time()
        last = self._last_alert.get(key, 0)
        if now - last < self._alert_cooldown:
            return False
        self._last_alert[key] = now
        return True

    def _send_discord(self, title: str, description: str, color: int):
        """Send Discord embed via webhook."""
        if not self.discord_url:
            logger.info(f"[ALERT] {title}: {description}")
            return
        try:
            payload = {
                "embeds": [{
                    "title": f"\U0001f514 {title}",
                    "description": description,
                    "color": color,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "footer": {"text": "Materios Watchtower"},
                }]
            }
            resp = requests.post(self.discord_url, json=payload, timeout=10)
            if resp.status_code not in (200, 204):
                logger.warning(f"Discord webhook returned {resp.status_code}")
        except Exception as e:
            logger.error(f"Discord send failed: {e}")

    def _check(self):
        """Fetch heartbeat status and evaluate alert conditions."""
        try:
            resp = requests.get(
                f"{self.gateway_url}/heartbeats/status",
                timeout=10
            )
            if resp.status_code != 200:
                if self._should_alert("gateway_down"):
                    self._send_discord(
                        "Gateway Unreachable",
                        f"Heartbeat status endpoint returned {resp.status_code}",
                        0xFF0000  # red
                    )
                return

            data = resp.json()
            validators = data.get("validators", {})
            summary = data.get("summary", {})

            total = summary.get("total", len(validators))
            online = summary.get("online", 0)

            # Determine threshold
            threshold = int(self.threshold_override) if self.threshold_override else None
            if threshold is None:
                # Default: assume 2-of-N (can be overridden)
                threshold = max(1, total - 1)

            # Alert: any validator stale >90s
            for addr, v in validators.items():
                label = v.get("label", addr[:12])
                age = v.get("age_secs", 999)
                status = v.get("status", "offline")

                if age > 90 and self._should_alert(f"stale:{addr}"):
                    self._send_discord(
                        f"Heartbeat Stale: {label}",
                        f"Validator `{addr}` heartbeat is {age}s old (status: {status})",
                        0xFFAA00  # orange
                    )

                # Alert: substrate disconnected
                if not v.get("substrate_connected", True) and self._should_alert(f"rpc_down:{addr}"):
                    self._send_discord(
                        f"RPC Disconnected: {label}",
                        f"Validator `{addr}` reports substrate_connected=false",
                        0xFFAA00
                    )

                # Alert: high finality gap
                fin_gap = v.get("finality_gap", 0)
                if fin_gap > 10 and self._should_alert(f"fin_gap:{addr}"):
                    self._send_discord(
                        f"High Finality Gap: {label}",
                        f"Validator `{addr}` finality gap is {fin_gap} blocks",
                        0xFFAA00
                    )

                # Alert: clock skew
                skew = abs(v.get("clock_skew_secs", 0))
                if skew > 30 and self._should_alert(f"clock:{addr}"):
                    self._send_discord(
                        f"Clock Drift: {label}",
                        f"Validator `{addr}` clock skew is {skew:.1f}s",
                        0xFFAA00
                    )

            # Alert: quorum at exact threshold (one more failure = loss)
            if online == threshold and self._should_alert("quorum_marginal"):
                self._send_discord(
                    "Quorum Marginal",
                    f"Only {online}/{total} validators online — one more failure loses quorum (threshold={threshold})",
                    0xFFAA00
                )

            # Alert: below threshold (CRITICAL)
            if online < threshold and self._should_alert("quorum_lost"):
                self._send_discord(
                    "QUORUM LOST",
                    f"Only {online}/{total} validators online — BELOW threshold ({threshold}). Attestation halted!",
                    0xFF0000
                )

            # Alert: fork detection (best block divergence)
            best_blocks = [v.get("best_block", 0) for v in validators.values() if v.get("status") == "online"]
            if len(best_blocks) >= 2:
                divergence = max(best_blocks) - min(best_blocks)
                if divergence > 5 and self._should_alert("fork"):
                    self._send_discord(
                        "Block Divergence Detected",
                        f"Online validators disagree by {divergence} blocks (range: {min(best_blocks)}-{max(best_blocks)}). Possible fork.",
                        0xFF0000
                    )

            logger.info(f"Check OK: {online}/{total} online (threshold={threshold})")

        except requests.exceptions.RequestException as e:
            if self._should_alert("gateway_error"):
                self._send_discord(
                    "Gateway Error",
                    f"Failed to fetch heartbeat status: {e}",
                    0xFF0000
                )
            logger.error(f"Check failed: {e}")

    def run(self):
        """Main loop."""
        logger.info(
            f"Watchtower started: gateway={self.gateway_url} "
            f"poll={self.poll_interval}s discord={'configured' if self.discord_url else 'NONE'}"
        )
        if not self.discord_url:
            logger.warning("No DISCORD_WEBHOOK_URL set — alerts will only be logged")

        while True:
            self._check()
            time.sleep(self.poll_interval)


def main():
    wt = Watchtower()
    wt.run()


if __name__ == "__main__":
    main()
