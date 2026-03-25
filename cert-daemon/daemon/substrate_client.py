import logging
import time
from typing import Optional
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

from daemon.config import DaemonConfig
from daemon.models import ReceiptRecord

logger = logging.getLogger(__name__)


def _to_bytes32(val) -> bytes:
    """Convert SCALE-decoded [u8; 32] to bytes. Handles hex strings, lists, and bytes."""
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val.removeprefix("0x"))
    if isinstance(val, (list, tuple)):
        return bytes(val)
    return bytes(val)


class SubstrateClient:
    def __init__(self, config: DaemonConfig):
        self.config = config
        self.substrate: Optional[SubstrateInterface] = None
        self.keypair = Keypair.create_from_uri(config.signer_uri)

    def connect(self) -> bool:
        try:
            self.substrate = SubstrateInterface(url=self.config.rpc_url, config={'strict_scale_decode': False})
            logger.info(f"Connected to {self.config.rpc_url}, chain: {self.substrate.chain}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to substrate: {e}")
            self.substrate = None
            return False

    @property
    def connected(self) -> bool:
        return self.substrate is not None

    def get_finalized_head_number(self) -> int:
        head_hash = self.substrate.get_chain_finalised_head()
        header = self.substrate.get_block_header(head_hash)
        return header["header"]["number"]

    def get_best_block_number(self) -> int:
        header = self.substrate.get_block_header()
        return header["header"]["number"]

    def get_block_events(self, block_number: int) -> list:
        block_hash = self.substrate.get_block_hash(block_number)
        events = self.substrate.get_events(block_hash=block_hash)
        receipt_events = []
        for event in events:
            if (event.value["module_id"] == "OrinqReceipts" and
                event.value["event_id"] == "ReceiptSubmitted"):
                attrs = event.value["attributes"]
                receipt_events.append({
                    "receipt_id": attrs["receipt_id"],
                    "content_hash": attrs["content_hash"],
                    "submitter": attrs["submitter"],
                })
        return receipt_events

    def get_block_certified_events(self, block_number: int) -> list:
        """Scan a block for AvailabilityCertified events."""
        block_hash = self.substrate.get_block_hash(block_number)
        events = self.substrate.get_events(block_hash=block_hash)
        certified = []
        for event in events:
            if (event.value["module_id"] == "OrinqReceipts" and
                event.value["event_id"] == "AvailabilityCertified"):
                attrs = event.value["attributes"]
                certified.append({
                    "receipt_id": attrs["receipt_id"],
                    "cert_hash": attrs["cert_hash"],
                })
        return certified

    def get_receipt(self, receipt_id: str) -> Optional[ReceiptRecord]:
        result = self.substrate.query(
            module="OrinqReceipts",
            storage_function="Receipts",
            params=[receipt_id],
        )
        if result.value is None:
            return None
        r = result.value
        return ReceiptRecord(
            receipt_id=receipt_id,
            content_hash=_to_bytes32(r["content_hash"]),
            base_root_sha256=_to_bytes32(r["base_root_sha256"]),
            storage_locator_hash=_to_bytes32(r["storage_locator_hash"]),
            schema_hash=_to_bytes32(r["schema_hash"]),
            base_manifest_hash=_to_bytes32(r["base_manifest_hash"]),
            safety_manifest_hash=_to_bytes32(r["safety_manifest_hash"]),
            monitor_config_hash=_to_bytes32(r["monitor_config_hash"]),
            attestation_evidence_hash=_to_bytes32(r["attestation_evidence_hash"]),
            zk_root_poseidon=_to_bytes32(r["zk_root_poseidon"]) if r.get("zk_root_poseidon") else None,
            poseidon_params_hash=_to_bytes32(r["poseidon_params_hash"]) if r.get("poseidon_params_hash") else None,
            availability_cert_hash=_to_bytes32(r["availability_cert_hash"]),
            created_at_millis=r["created_at_millis"],
            submitter=str(r["submitter"]),
        )

    def submit_availability_cert(self, receipt_id: str, cert_hash: bytes) -> bool:
        """Submit attest_availability_cert directly (no Sudo). Returns True on finalization."""
        for attempt in range(self.config.tx_max_retries):
            try:
                call = self.substrate.compose_call(
                    call_module="OrinqReceipts",
                    call_function="attest_availability_cert",
                    call_params={
                        "receipt_id": receipt_id,
                        "cert_hash": list(cert_hash),
                    },
                )
                extrinsic = self.substrate.create_signed_extrinsic(
                    call=call,
                    keypair=self.keypair,
                )
                receipt = self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
                if receipt.is_success:
                    logger.info(f"Cert attested for {receipt_id}, block {receipt.block_hash}")
                    return True
                else:
                    logger.error(f"Cert tx failed for {receipt_id}: {receipt.error_message}")
            except SubstrateRequestException as e:
                logger.error(f"Cert tx attempt {attempt + 1} failed for {receipt_id}: {e}")
                if attempt < self.config.tx_max_retries - 1:
                    time.sleep(2 ** attempt)
            except Exception as e:
                logger.error(f"Unexpected error submitting cert for {receipt_id}: {e}")
                if attempt < self.config.tx_max_retries - 1:
                    time.sleep(2 ** attempt)
        return False
