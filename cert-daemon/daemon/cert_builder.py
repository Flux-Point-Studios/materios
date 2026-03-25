import hashlib
import cbor2
from daemon.models import AttestationLevel


def build_cert(
    chain_id: str,
    receipt_id: str,
    content_hash: bytes,
    base_root_sha256: bytes,
    storage_locator_hash: bytes,
    attested_at_epoch: int,
    retention_days: int,
    attestation_level: AttestationLevel,
    cert_schema_version: str = "1.0",
) -> tuple[bytes, bytes]:
    """Build a dCBOR availability certificate.

    Returns (dcbor_bytes, cert_hash) where cert_hash = SHA-256(dcbor_bytes).
    The cert is a 10-element CBOR array per AVAILABILITY_CERT_SPEC.md.
    """
    cert_array = [
        "materios-availability-cert-v1",  # 0: domain separator
        chain_id,                          # 1: Materios chain genesis hash
        receipt_id,                        # 2: receipt ID hex string
        content_hash,                      # 3: bytes32
        base_root_sha256,                  # 4: bytes32
        storage_locator_hash,              # 5: bytes32
        attested_at_epoch,                 # 6: Cardano epoch
        retention_days,                    # 7: retention commitment
        attestation_level.value,           # 8: 1/2/3
        cert_schema_version,               # 9: schema version
    ]
    dcbor_bytes = cbor2.dumps(cert_array, canonical=True)
    cert_hash = hashlib.sha256(dcbor_bytes).digest()
    return dcbor_bytes, cert_hash
