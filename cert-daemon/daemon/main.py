import asyncio
import logging
import signal
import sys
import os

from daemon.config import DaemonConfig
from daemon.cert_daemon import CertDaemon
from daemon.health_server import start_health_server, set_notify_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def main():
    config = DaemonConfig.from_env()

    # Ensure data directories exist
    for d in [config.data_dir, config.cert_store_dir, config.blob_local_dir]:
        os.makedirs(d, exist_ok=True)

    # Configure push-notify auth token
    if config.notify_token:
        set_notify_token(config.notify_token)

    # Start health server
    health_srv = start_health_server(config.health_port)

    # Create daemon
    daemon = CertDaemon(config)

    # Start heartbeat sender (if configured)
    if config.heartbeat_url:
        from daemon.heartbeat import start_heartbeat_sender
        from daemon.health_server import _metrics, _metrics_lock
        start_heartbeat_sender(config, _metrics, _metrics_lock, daemon.client.keypair)

    # Signal handling
    loop = asyncio.new_event_loop()

    def shutdown(sig, frame):
        logger.info(f"Received {signal.Signals(sig).name}, shutting down...")
        daemon.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        loop.run_until_complete(daemon.run())
    except KeyboardInterrupt:
        daemon.stop()
    finally:
        health_srv.shutdown()
        loop.close()
        logger.info("Daemon exited cleanly")


if __name__ == "__main__":
    main()
