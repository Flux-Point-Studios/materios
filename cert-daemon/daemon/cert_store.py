import os
import logging

from daemon.config import DaemonConfig

logger = logging.getLogger(__name__)


class CertStore:
    def __init__(self, config: DaemonConfig):
        self.store_dir = config.cert_store_dir
        os.makedirs(self.store_dir, exist_ok=True)

    def save(self, receipt_id: str, dcbor_bytes: bytes) -> str:
        clean_id = receipt_id.removeprefix("0x")
        path = os.path.join(self.store_dir, f"{clean_id}.cbor")
        with open(path, "wb") as f:
            f.write(dcbor_bytes)
        logger.info(f"Saved cert for {receipt_id} to {path} ({len(dcbor_bytes)} bytes)")
        return path

    def exists(self, receipt_id: str) -> bool:
        clean_id = receipt_id.removeprefix("0x")
        path = os.path.join(self.store_dir, f"{clean_id}.cbor")
        return os.path.exists(path)

    def load(self, receipt_id: str) -> bytes | None:
        clean_id = receipt_id.removeprefix("0x")
        path = os.path.join(self.store_dir, f"{clean_id}.cbor")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()
