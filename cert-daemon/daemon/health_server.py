import json
import queue
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logger = logging.getLogger(__name__)

# Thread-safe notification queue for push-notify from gateway
_notification_queue = queue.Queue(maxsize=1000)

# Token for authenticating push notifications
_notify_token = ""


def set_notify_token(token: str):
    """Set the expected X-Internal-Token for push-notify auth."""
    global _notify_token
    _notify_token = token


def drain_notifications() -> list:
    """Drain all queued notifications (non-blocking)."""
    items = []
    while True:
        try:
            items.append(_notification_queue.get_nowait())
        except queue.Empty:
            break
    return items


# Global metrics — updated by daemon loop
_metrics = {
    "blocks_processed_total": 0,
    "certs_submitted_total": 0,
    "verification_failures_total": 0,
    "pending_receipts": 0,
    "last_processed_block": 0,
    "last_poll_timestamp": 0.0,
    "substrate_connected": False,
    "finalized_head": 0,
    "finality_gap": 0,
}
_metrics_lock = threading.Lock()


def update_metrics(**kwargs):
    with _metrics_lock:
        _metrics.update(kwargs)


def increment_metric(name: str, amount: int = 1):
    with _metrics_lock:
        _metrics[name] = _metrics.get(name, 0) + amount


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._health()
        elif self.path == "/ready":
            self._ready()
        elif self.path == "/metrics":
            self._metrics()
        elif self.path == "/status":
            self._status()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/notify":
            self._notify()
        else:
            self.send_error(404)

    def _health(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def _ready(self):
        with _metrics_lock:
            connected = _metrics["substrate_connected"]
            last_poll = _metrics["last_poll_timestamp"]
        # Ready if connected and polled within last 2 intervals (24s)
        recent = (time.time() - last_poll) < 24 if last_poll > 0 else False
        if connected and recent:
            self.send_response(200)
            body = {"status": "ready"}
        else:
            self.send_response(503)
            body = {"status": "not_ready", "connected": connected, "last_poll_age": time.time() - last_poll}
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def _metrics(self):
        with _metrics_lock:
            snapshot = dict(_metrics)
        lines = []
        for key, value in snapshot.items():
            if isinstance(value, bool):
                value = 1 if value else 0
            if isinstance(value, (int, float)):
                lines.append(f"materios_cert_daemon_{key} {value}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("\n".join(lines).encode())

    def _notify(self):
        """Handle POST /notify — queue a push notification from the gateway."""
        # Auth check
        token = self.headers.get("X-Internal-Token", "")
        if _notify_token and token != _notify_token:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        # Queue notification
        try:
            _notification_queue.put_nowait(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "queued": True}).encode())
        except queue.Full:
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "accepted", "queued": False, "reason": "queue_full"}).encode())

    def _status(self):
        """Return JSON status (not Prometheus text)."""
        with _metrics_lock:
            snapshot = dict(_metrics)
        body = {
            "status": "ok" if snapshot.get("substrate_connected") else "degraded",
            "bestBlock": snapshot.get("last_processed_block", 0),
            "finalizedBlock": snapshot.get("finalized_head", 0),
            "pendingReceipts": snapshot.get("pending_receipts", 0),
            "certsSubmitted": snapshot.get("certs_submitted_total", 0),
            "lastPollTimestamp": snapshot.get("last_poll_timestamp", 0),
            "connected": snapshot.get("substrate_connected", False),
            "finalityGap": snapshot.get("finality_gap", 0),
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass  # suppress access logs


def start_health_server(port: int) -> HTTPServer:
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Health server listening on :{port}")
    return server
