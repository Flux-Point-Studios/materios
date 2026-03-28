import asyncio
import json
import logging
import os
import time
from typing import Optional
import aiohttp

from daemon.config import DaemonConfig
from daemon.models import AttestationLevel, PendingReceipt
from daemon.substrate_client import SubstrateClient
from daemon.locator_registry import LocatorRegistry
from daemon.blob_verifier import BlobVerifier
from daemon.cert_builder import build_cert
from daemon.cert_store import CertStore
from daemon.checkpoint import CardanoCheckpointer
from daemon.content_validator import ContentValidator
from daemon import health_server
from daemon.health_server import drain_notifications

logger = logging.getLogger(__name__)

class CertDaemon:
    def __init__(self, config: DaemonConfig):
        self.config = config
        self.client = SubstrateClient(config)
        self.locator = LocatorRegistry(config)
        self.verifier = BlobVerifier(config)
        self.content_validator = ContentValidator(config)
        self.cert_store = CertStore(config)
        self.checkpointer = CardanoCheckpointer(
            config,
            state_file=os.path.join(config.data_dir, "checkpoint-state.json"),
        )
        self.pending: dict[str, PendingReceipt] = {}
        self.last_processed_block: int = 0
        self._running = True
        self._notified_ids: dict[str, float] = {}  # receipt_id -> timestamp for dedupe

    def stop(self):
        self._running = False

    def load_state(self):
        if os.path.exists(self.config.state_file):
            try:
                with open(self.config.state_file) as f:
                    state = json.load(f)
                self.last_processed_block = state.get("last_processed_block", 0)
                logger.info(f"Loaded state: last_processed_block={self.last_processed_block}")
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")

    def save_state(self):
        try:
            state = {"last_processed_block": self.last_processed_block}
            tmp = self.config.state_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(state, f)
            os.replace(tmp, self.config.state_file)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    async def send_discord(self, message: str, level: str = "info"):
        if not self.config.discord_webhook_url:
            return
        prefix = {"info": "\u2139\ufe0f", "warning": "\u26a0\ufe0f", "critical": "\ud83d\udea8"}.get(level, "")
        payload = {"content": f"{prefix} **materios-cert-daemon**: {message}"}
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.config.discord_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                )
        except Exception as e:
            logger.warning(f"Discord notification failed: {e}")

    def get_cardano_epoch(self) -> int:
        """Get current Cardano epoch from Ogmios /health endpoint."""
        try:
            import requests as _requests
            resp = _requests.get(
                f"{self.config.ogmios_url}/health",
                headers={"Accept": "application/json"},
                timeout=5,
            )
            data = resp.json()
            epoch = data.get("currentEpoch")
            if epoch is not None:
                return int(epoch)
            # fallback: derive from lastKnownTip slot
            tip = data.get("lastKnownTip", {})
            slot = tip.get("slot", 0)
            if slot > 0:
                return slot // 432000  # preprod epoch length
            return 0
        except Exception as e:
            logger.warning(f"Failed to get Cardano epoch from Ogmios: {e}")
            return 0

    async def process_receipt(self, receipt_id: str):
        receipt = self.client.get_receipt(receipt_id)
        if receipt is None:
            logger.warning(f"Receipt {receipt_id} not found on chain")
            return

        # Skip if already certified
        if receipt.availability_cert_hash != b'\x00' * 32:
            logger.info(f"Receipt {receipt_id} already certified, skipping")
            return

        # Skip if we already have a cert stored
        if self.cert_store.exists(receipt_id):
            logger.info(f"Cert already stored for {receipt_id}, skipping")
            return

        # Resolve blob locations (try receipt_id first, then content_hash fallback)
        content_hash_hex = receipt.content_hash.hex() if isinstance(receipt.content_hash, bytes) else str(receipt.content_hash)
        manifest = await self.locator.resolve(receipt_id, content_hash=content_hash_hex)
        if manifest is None:
            logger.info(f"No locator found for {receipt_id}, adding to pending")
            if receipt_id not in self.pending:
                self.pending[receipt_id] = PendingReceipt(
                    receipt_id=receipt_id,
                    receipt=receipt,
                    first_seen=time.time(),
                )
            return

        # Verify blobs
        verification = await self.verifier.verify(receipt, manifest)
        logger.info(
            f"Verification for {receipt_id}: level={verification.attestation_level.name}, "
            f"chunks={verification.chunks_verified}/{verification.chunks_total}"
        )

        if verification.attestation_level < AttestationLevel.HASH_VERIFIED:
            logger.warning(f"Verification failed for {receipt_id}: {verification.errors}")
            health_server.increment_metric("verification_failures_total")
            await self.send_discord(
                f"Verification failed for `{receipt_id[:16]}...`: {verification.errors[0] if verification.errors else 'unknown'}",
                "warning",
            )
            return

        # Content validation gate (if enabled)
        if self.config.content_validation_enabled:
            validation = self.content_validator.validate(
                verification.chunk_data_list, receipt_id
            )
            if not validation.valid:
                logger.warning(
                    f"Content validation FAILED for {receipt_id}: {validation.errors}"
                )
                health_server.increment_metric("content_validation_failures_total")
                await self.send_discord(
                    f"Content rejected for `{receipt_id[:16]}...`: {validation.errors[0]}",
                    "warning",
                )
                return  # Don't certify — receipt stays with zero cert hash

        # Get Cardano epoch
        epoch = self.get_cardano_epoch()

        # Build cert
        dcbor_bytes, cert_hash = build_cert(
            chain_id=self.config.chain_id,
            receipt_id=receipt_id,
            content_hash=receipt.content_hash,
            base_root_sha256=receipt.base_root_sha256,
            storage_locator_hash=receipt.storage_locator_hash,
            attested_at_epoch=epoch,
            retention_days=self.config.retention_days,
            attestation_level=verification.attestation_level,
            cert_schema_version=self.config.cert_schema_version,
        )

        # Store cert to filesystem
        self.cert_store.save(receipt_id, dcbor_bytes)

        # Submit on-chain
        success = self.client.submit_availability_cert(receipt_id, cert_hash)
        if success:
            health_server.increment_metric("certs_submitted_total")
            self.pending.pop(receipt_id, None)
            await self.send_discord(
                f"Cert submitted for `{receipt_id[:16]}...` (L{verification.attestation_level})",
                "info",
            )
        else:
            health_server.increment_metric("verification_failures_total")
            await self.send_discord(
                f"Failed to submit cert tx for `{receipt_id[:16]}...` after {self.config.tx_max_retries} retries",
                "critical",
            )

    async def retry_pending(self):
        now = time.time()
        to_remove = []
        for receipt_id, pending in list(self.pending.items()):
            content_hash_hex = pending.receipt.content_hash.hex() if isinstance(pending.receipt.content_hash, bytes) else str(pending.receipt.content_hash)
            manifest = await self.locator.resolve(receipt_id, content_hash=content_hash_hex)
            if manifest is None:
                pending.retries += 1
                if now - pending.first_seen > self.config.pending_alert_seconds and pending.retries % 60 == 0:
                    await self.send_discord(
                        f"Receipt `{receipt_id[:16]}...` pending for {int((now - pending.first_seen) / 60)}min, no locator found",
                        "warning",
                    )
                continue

            # Found locator — process it
            await self.process_receipt(receipt_id)
            to_remove.append(receipt_id)

        for rid in to_remove:
            self.pending.pop(rid, None)

    async def _ensure_committee_membership(self):
        """Check if this daemon's signer is in the attestation committee. If not, join."""
        try:
            my_address = self.client.keypair.ss58_address
            committee = self.client.substrate.query("OrinqReceipts", "CommitteeMembers")

            # Check if we're already a member (handle different SS58 prefixes)
            my_pubkey = self.client.keypair.public_key.hex()
            is_member = False
            for member in committee or []:
                member_str = str(member)
                try:
                    from substrateinterface.utils.ss58 import ss58_decode
                    if ss58_decode(member_str) == my_pubkey:
                        is_member = True
                        break
                except Exception:
                    if member_str == my_address:
                        is_member = True
                        break

            if is_member:
                logger.info(f"Already in attestation committee as {my_address}")
                return

            logger.info(f"Not in committee — calling join_committee as {my_address}")
            call = self.client.substrate.compose_call(
                call_module="OrinqReceipts",
                call_function="join_committee",
                call_params={},
            )
            extrinsic = self.client.substrate.create_signed_extrinsic(
                call=call,
                keypair=self.client.keypair,
            )
            receipt = self.client.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

            if receipt.is_success:
                logger.info(f"Successfully joined attestation committee!")
                await self.send_discord(f"Joined attestation committee as `{my_address[:16]}...`", "info")
            else:
                error = receipt.error_message or "unknown error"
                logger.warning(f"join_committee failed: {error}")
                # Common failure: can't pay fees (no MOTRA). Request faucet drip.
                if "pay" in str(error).lower() or "fee" in str(error).lower():
                    await self._request_faucet_drip(my_address)

        except Exception as e:
            logger.warning(f"Committee membership check failed: {e}")

    async def _request_faucet_drip(self, address: str):
        """Request a MATRA airdrop from the gateway faucet to pay for join_committee."""
        gateway_url = self.config.blob_base_url
        if not gateway_url:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{gateway_url}/faucet/drip",
                    json={"address": address},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        logger.info(f"Faucet drip received: {data.get('amount')} MATRA")
                        # Wait for MOTRA to generate, then retry join
                        await asyncio.sleep(30)
                        await self._ensure_committee_membership()
                    else:
                        logger.warning(f"Faucet request failed: {data.get('error', resp.status)}")
        except Exception as e:
            logger.warning(f"Faucet request error: {e}")

    async def run(self):
        await self.send_discord("Daemon starting up", "info")
        self.load_state()

        if not self.client.connect():
            await self.send_discord("Failed to connect to substrate node", "critical")
            return

        health_server.update_metrics(substrate_connected=True)

        # Auto-join the attestation committee if not already a member
        await self._ensure_committee_membership()

        logger.info(f"Starting poll loop, interval={self.config.poll_interval}s")

        while self._running:
            notifications = []  # defined outside try so adaptive sleep can see it
            try:
                # Drain push notifications from gateway
                notifications = drain_notifications()
                now_ts = time.time()

                # Clean expired entries from dedupe set (>5 min old)
                expired = [rid for rid, ts in self._notified_ids.items() if now_ts - ts > 300]
                for rid in expired:
                    del self._notified_ids[rid]

                # Process new notifications
                for notif in notifications:
                    receipt_id = notif.get("receiptId", "")
                    if receipt_id and receipt_id not in self._notified_ids:
                        self._notified_ids[receipt_id] = now_ts
                        logger.info(f"Push notification for {receipt_id[:16]}...")
                        try:
                            await self.process_receipt(receipt_id)
                        except Exception as e:
                            logger.warning(f"Error processing notified receipt {receipt_id[:16]}...: {e}")

                head = self.client.get_best_block_number()

                if self.last_processed_block == 0:
                    # On first run, start from current head block (don't replay history)
                    self.last_processed_block = head
                    self.save_state()
                    logger.info(f"First run, starting from block {head}")

                for block_num in range(self.last_processed_block + 1, head + 1):
                    if not self._running:
                        break
                    events = self.client.get_block_events(block_num)
                    for event in events:
                        await self.process_receipt(event["receipt_id"])
                    self.last_processed_block = block_num
                    health_server.increment_metric("blocks_processed_total")

                    # Scan for AvailabilityCertified events for checkpointing
                    if self.config.checkpoint_enabled:
                        certified = self.client.get_block_certified_events(block_num)
                        for cert_event in certified:
                            cert_hash_bytes = bytes.fromhex(cert_event["cert_hash"].removeprefix("0x"))
                            self.checkpointer.add_cert(cert_event["receipt_id"], cert_hash_bytes, block_num)

                    self.save_state()

                # Retry pending receipts
                await self.retry_pending()

                # Periodic L1 checkpoint flush
                if self.config.checkpoint_enabled and self.checkpointer.should_flush():
                    self.checkpointer.flush(current_best_block=head)

                # Track finalized head for health metrics
                try:
                    finalized = self.client.get_finalized_head_number()
                    finality_gap = head - finalized
                    health_server.update_metrics(
                        finalized_head=finalized,
                        finality_gap=finality_gap,
                    )
                except Exception:
                    pass  # Don't fail main loop if finalized head query fails

                health_server.update_metrics(
                    last_processed_block=self.last_processed_block,
                    last_poll_timestamp=time.time(),
                    pending_receipts=len(self.pending),
                )

            except Exception as e:
                logger.error(f"Poll loop error: {e}", exc_info=True)
                health_server.update_metrics(substrate_connected=False)
                # Try to reconnect
                try:
                    self.client.connect()
                    health_server.update_metrics(substrate_connected=True)
                except Exception:
                    await self.send_discord(f"Connection lost: {e}", "critical")

            # Adaptive polling: fast when work pending, idle when not
            has_pending = len(self.pending) > 0 or len(notifications) > 0
            interval = self.config.poll_interval_fast if has_pending else self.config.poll_interval_idle
            await asyncio.sleep(interval)

        await self.send_discord("Daemon shutting down", "info")
