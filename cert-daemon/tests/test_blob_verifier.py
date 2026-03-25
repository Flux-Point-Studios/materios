import asyncio
import hashlib
from unittest.mock import AsyncMock, patch
from daemon.blob_verifier import BlobVerifier
from daemon.config import DaemonConfig
from daemon.models import AttestationLevel, BlobManifest, ChunkInfo, ReceiptRecord
from daemon.merkle import sha256, merkle_root


def make_receipt(root: bytes) -> ReceiptRecord:
    return ReceiptRecord(
        receipt_id="0xtest",
        content_hash=b'\x00' * 32,
        base_root_sha256=root,
        storage_locator_hash=b'\x00' * 32,
        schema_hash=b'\x00' * 32,
        base_manifest_hash=b'\x00' * 32,
        safety_manifest_hash=b'\x00' * 32,
        monitor_config_hash=b'\x00' * 32,
        attestation_evidence_hash=b'\x00' * 32,
    )


def test_verify_l3_success():
    chunk_data = [b"chunk0", b"chunk1"]
    chunk_hashes = [sha256(d) for d in chunk_data]
    root = merkle_root(chunk_hashes)
    receipt = make_receipt(root)
    manifest = BlobManifest(
        receipt_id="0xtest",
        chunks=[
            ChunkInfo(index=0, url="http://test/0", sha256_hash=chunk_hashes[0]),
            ChunkInfo(index=1, url="http://test/1", sha256_hash=chunk_hashes[1]),
        ],
    )
    config = DaemonConfig()
    verifier = BlobVerifier(config)

    async def mock_get(url):
        idx = int(url.split("/")[-1])
        return chunk_data[idx]

    with patch.object(verifier, '_fetch_chunk', side_effect=mock_get):
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(receipt, manifest)
        )

    assert result.attestation_level == AttestationLevel.ROOT_VERIFIED
    assert result.chunks_verified == 2
    assert not result.errors
