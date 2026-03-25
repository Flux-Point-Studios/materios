from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class AttestationLevel(IntEnum):
    FETCHED = 1       # L1: data retrievable
    HASH_VERIFIED = 2 # L2: each chunk matches hash
    ROOT_VERIFIED = 3 # L3: full Merkle root matches


@dataclass
class ReceiptRecord:
    receipt_id: str           # hex string, 0x-prefixed
    content_hash: bytes       # 32 bytes
    base_root_sha256: bytes   # 32 bytes
    storage_locator_hash: bytes  # 32 bytes
    schema_hash: bytes
    base_manifest_hash: bytes
    safety_manifest_hash: bytes
    monitor_config_hash: bytes
    attestation_evidence_hash: bytes
    zk_root_poseidon: Optional[bytes] = None
    poseidon_params_hash: Optional[bytes] = None
    availability_cert_hash: bytes = b'\x00' * 32
    created_at_millis: int = 0
    submitter: str = ""


@dataclass
class BlobManifest:
    receipt_id: str
    chunks: list  # list of ChunkInfo
    total_size: int = 0


@dataclass
class ChunkInfo:
    index: int
    url: str
    sha256_hash: bytes  # expected hash of this chunk
    size: int = 0


@dataclass
class VerificationResult:
    attestation_level: AttestationLevel
    computed_root: Optional[bytes] = None
    errors: list = field(default_factory=list)
    chunks_verified: int = 0
    chunks_total: int = 0
    chunk_data_list: list = field(default_factory=list)


@dataclass
class PendingReceipt:
    receipt_id: str
    receipt: ReceiptRecord
    first_seen: float  # time.time()
    retries: int = 0
    last_error: str = ""
