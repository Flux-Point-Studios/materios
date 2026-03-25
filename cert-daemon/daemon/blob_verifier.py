import logging
import os
from typing import Optional
import aiohttp

from daemon.config import DaemonConfig
from daemon.models import (
    AttestationLevel,
    BlobManifest,
    ReceiptRecord,
    VerificationResult,
)
from daemon.merkle import sha256, merkle_root

logger = logging.getLogger(__name__)


class BlobVerifier:
    def __init__(self, config: DaemonConfig):
        self.config = config

    async def verify(self, receipt: ReceiptRecord, manifest: BlobManifest) -> VerificationResult:
        """Fetch all chunks, verify hashes (L2), then verify Merkle root (L3)."""
        result = VerificationResult(
            attestation_level=AttestationLevel.FETCHED,
            chunks_total=len(manifest.chunks),
        )
        chunk_hashes = []
        chunk_data_list = []
        timeout = aiohttp.ClientTimeout(total=self.config.blob_fetch_timeout)

        # Build default headers with API key for gateway-hosted chunks
        default_headers = {}
        api_key = os.environ.get("BLOB_GATEWAY_API_KEY", "") or getattr(self.config, "blob_gateway_api_key", "")
        if api_key:
            default_headers["x-api-key"] = api_key

        async with aiohttp.ClientSession(timeout=timeout, headers=default_headers) as session:
            for chunk in manifest.chunks:
                chunk_data = await self._fetch_chunk(session, chunk.url)
                if chunk_data is None:
                    result.errors.append(f"Failed to fetch chunk {chunk.index}: {chunk.url}")
                    return result  # L1 only — couldn't fetch all chunks

                if len(chunk_data) > self.config.max_chunk_size:
                    result.errors.append(f"Chunk {chunk.index} exceeds max size: {len(chunk_data)}")
                    return result

                computed_hash = sha256(chunk_data)
                if computed_hash != chunk.sha256_hash:
                    result.errors.append(
                        f"Chunk {chunk.index} hash mismatch: "
                        f"expected {chunk.sha256_hash.hex()}, got {computed_hash.hex()}"
                    )
                    return result  # hash mismatch — can't trust data

                chunk_hashes.append(computed_hash)
                chunk_data_list.append(chunk_data)
                result.chunks_verified += 1

        # All chunks fetched and hash-verified → L2
        result.attestation_level = AttestationLevel.HASH_VERIFIED
        result.chunk_data_list = chunk_data_list

        # Compute Merkle root and compare to on-chain value
        computed_root = merkle_root(chunk_hashes)
        result.computed_root = computed_root

        if computed_root == receipt.base_root_sha256:
            result.attestation_level = AttestationLevel.ROOT_VERIFIED
        else:
            result.errors.append(
                f"Merkle root mismatch: on-chain {receipt.base_root_sha256.hex()}, "
                f"computed {computed_root.hex()}"
            )
            logger.critical(
                f"Merkle root mismatch for {receipt.receipt_id}: "
                f"on-chain={receipt.base_root_sha256.hex()}, computed={computed_root.hex()}"
            )

        return result

    async def _fetch_chunk(self, session: aiohttp.ClientSession, url: str) -> Optional[bytes]:
        # Support file:// URLs for local chunk reading (used by chaos drills and local tests)
        if url.startswith("file://"):
            path = os.path.normpath(url[7:])
            # Block path traversal — file:// reads must stay within blob_local_dir
            allowed_dir = os.path.normpath(self.config.blob_local_dir)
            if not path.startswith(allowed_dir):
                logger.warning(f"Path traversal blocked in file:// URL: {path}")
                return None
            try:
                with open(path, "rb") as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Local chunk read failed {path}: {e}")
                return None

        for attempt in range(self.config.max_blob_fetch_retries):
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.read()
                    logger.warning(f"Chunk fetch {url} returned {resp.status} (attempt {attempt + 1})")
            except Exception as e:
                logger.warning(f"Chunk fetch {url} failed (attempt {attempt + 1}): {e}")
        return None
