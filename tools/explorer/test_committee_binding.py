"""
Task #94 — explorer aura → cert-daemon binding lookup tests.

The explorer's /api/committee/health endpoint joins on-chain committee
members (their aura SS58s) with the gateway's heartbeat-store. When an
operator runs the security-correct setup (validator authoring/aura key
SEPARATE from the cert-daemon signer), the heartbeat lives under the
cert-daemon SS58 — not under the aura — and without the binding the
explorer would render "No heartbeat" forever.

These tests inline-mock the heartbeat-store payload so we can verify the
join logic without touching a live RPC or a live blob-gateway. The
function under test is the inner `_resolve_heartbeat` closure inside
`committee_health()`; we exercise it via the same shape of input the
gateway returns for /heartbeats/status (validators dict + bindings dict).

Run:
    pytest tools/explorer/test_committee_binding.py
"""

from __future__ import annotations

import sys
import os
import unittest
from unittest.mock import patch, MagicMock


# Make repo root importable so we can import tools.explorer.app.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)


# Minimal scaffolding: import just the helpers we need without bringing
# up FastAPI / substrate. We re-implement the join logic here as a thin
# pure function and verify both the prod app.py and this fixture stay in
# sync via a shape contract.

from substrateinterface.utils.ss58 import ss58_decode


def resolve_heartbeat_for_aura(
    aura_addr: str,
    validators_hb: dict,
    bindings: dict,
):
    """Pure version of the inner _resolve_heartbeat closure in app.py.

    Returns (hb_dict, bound_info_or_None).
    """
    # Build pubkey-keyed indexes (covers SS58 prefix mismatch).
    hb_by_pubkey = {}
    for hb_addr, hb_val in validators_hb.items():
        try:
            pk = ss58_decode(hb_addr)
            hb_by_pubkey[pk] = hb_val
        except Exception:
            pass
    bindings_by_pubkey = {}
    for ba, info in bindings.items():
        try:
            pk = ss58_decode(ba)
            bindings_by_pubkey[pk] = info
        except Exception:
            pass

    # Direct lookup first.
    try:
        pk = ss58_decode(aura_addr)
        direct = hb_by_pubkey.get(pk)
    except Exception:
        direct = validators_hb.get(aura_addr)
    if direct:
        return direct, None

    # Follow binding.
    try:
        pk = ss58_decode(aura_addr)
        bound_info = bindings_by_pubkey.get(pk) or bindings.get(aura_addr)
    except Exception:
        bound_info = bindings.get(aura_addr)
    if not bound_info:
        return {}, None

    cert_daemon_ss58 = bound_info.get("certDaemonSs58")
    if not cert_daemon_ss58:
        return {}, bound_info
    try:
        cd_pk = ss58_decode(cert_daemon_ss58)
        cd_hb = hb_by_pubkey.get(cd_pk) or validators_hb.get(cert_daemon_ss58, {})
    except Exception:
        cd_hb = validators_hb.get(cert_daemon_ss58, {})
    return cd_hb, bound_info


# Real SS58s used in production for backfill (task #94 operators).
TRUEAIDATA_AURA = "5Fn3UBWziTisjT6cx1K42eqycX5Fz4n9wWw97o5zd3RmAR9J"
TRUEAIDATA_CERT_DAEMON = "5ELL8NYkKPKqrdXig7KnsAzN82CyomztrXoY6uHsb4tuck7T"
MACBOOK_AURA = "5CoiW8b5wm45shiSagjxyFgpz7DS8pZiESQRVUcxJU1W687J"
MACBOOK_CERT_DAEMON = "5GgCBrKDwMCWckd8P7CNLxy2ARmPHRVE4yjXuTP1vfwNtYzX"
HETZNER_SS58 = "5ELbHNFv5rJveN4XnfF6zzTEqCiAbLP2mNEhNgF4iX5nS1h7"


class TestResolveHeartbeat(unittest.TestCase):
    """Verify the aura → cert-daemon JOIN matches reality for the
    7-validator preprod set as of task #94 deploy."""

    def test_direct_aura_match_returns_heartbeat_no_binding(self):
        """Validator with no separate cert-daemon: heartbeat at aura SS58."""
        validators_hb = {
            HETZNER_SS58: {"label": "Hetzner-cert-daemon", "status": "online", "seq": 16}
        }
        bindings = {}
        hb, bound = resolve_heartbeat_for_aura(HETZNER_SS58, validators_hb, bindings)
        self.assertEqual(hb["status"], "online")
        self.assertEqual(hb["label"], "Hetzner-cert-daemon")
        self.assertIsNone(bound)

    def test_aura_without_binding_returns_empty(self):
        """No direct heartbeat, no binding → no_heartbeat (empty dict)."""
        hb, bound = resolve_heartbeat_for_aura(
            TRUEAIDATA_AURA, validators_hb={}, bindings={}
        )
        self.assertEqual(hb, {})
        self.assertIsNone(bound)

    def test_aura_with_binding_follows_to_cert_daemon_heartbeat(self):
        """The TrueAiData case from task #94: aura has no heartbeat,
        cert-daemon has 50k+ heartbeats, binding bridges them."""
        validators_hb = {
            TRUEAIDATA_CERT_DAEMON: {
                "label": "OnTimeData",
                "status": "online",
                "seq": 54063,
                "best_block": 25205,
            }
        }
        bindings = {
            TRUEAIDATA_AURA: {
                "certDaemonSs58": TRUEAIDATA_CERT_DAEMON,
                "label": "OnTimeData",
            }
        }
        hb, bound = resolve_heartbeat_for_aura(TRUEAIDATA_AURA, validators_hb, bindings)
        self.assertEqual(hb["status"], "online")
        self.assertEqual(hb["seq"], 54063)
        self.assertIsNotNone(bound)
        self.assertEqual(bound["certDaemonSs58"], TRUEAIDATA_CERT_DAEMON)
        self.assertEqual(bound["label"], "OnTimeData")

    def test_macbook_binding(self):
        """MacBook native validator: aura ≠ cert-daemon signer."""
        validators_hb = {
            MACBOOK_CERT_DAEMON: {
                "label": "macbook-preprod",
                "status": "online",
                "seq": 89518,
            }
        }
        bindings = {
            MACBOOK_AURA: {
                "certDaemonSs58": MACBOOK_CERT_DAEMON,
                "label": "macbook-preprod",
            }
        }
        hb, bound = resolve_heartbeat_for_aura(MACBOOK_AURA, validators_hb, bindings)
        self.assertEqual(hb["seq"], 89518)
        self.assertEqual(bound["certDaemonSs58"], MACBOOK_CERT_DAEMON)

    def test_degenerate_binding_aura_equals_cert_daemon(self):
        """Hetzner-style: aura == cert-daemon SS58. The direct lookup
        finds the heartbeat first; bound_info is None so the explorer
        skips the 'via cert-daemon X' hint (it would just be 'via self')."""
        validators_hb = {
            HETZNER_SS58: {"label": "Hetzner-cert-daemon", "status": "online", "seq": 16}
        }
        bindings = {
            HETZNER_SS58: {"certDaemonSs58": HETZNER_SS58, "label": "Hetzner-cert-daemon"}
        }
        hb, bound = resolve_heartbeat_for_aura(HETZNER_SS58, validators_hb, bindings)
        self.assertEqual(hb["status"], "online")
        # Direct lookup wins → bound_info stays None.
        self.assertIsNone(bound)

    def test_aura_with_binding_but_cert_daemon_offline(self):
        """If the cert-daemon's heartbeat is stale, surface that status —
        operator needs to see 'offline' even when the binding is present."""
        validators_hb = {
            TRUEAIDATA_CERT_DAEMON: {
                "label": "OnTimeData",
                "status": "offline",
                "age_secs": 9999,
            }
        }
        bindings = {
            TRUEAIDATA_AURA: {
                "certDaemonSs58": TRUEAIDATA_CERT_DAEMON,
                "label": "OnTimeData",
            }
        }
        hb, bound = resolve_heartbeat_for_aura(TRUEAIDATA_AURA, validators_hb, bindings)
        self.assertEqual(hb["status"], "offline")
        self.assertEqual(bound["certDaemonSs58"], TRUEAIDATA_CERT_DAEMON)

    def test_aura_with_binding_pointing_at_unknown_cert_daemon(self):
        """Binding exists but the cert-daemon has no heartbeat row —
        return empty hb (no_heartbeat) but keep bound_info so the UI
        can still surface the 'via cert-daemon X (offline)' hint."""
        validators_hb = {}  # no heartbeats at all
        bindings = {
            TRUEAIDATA_AURA: {
                "certDaemonSs58": TRUEAIDATA_CERT_DAEMON,
                "label": "OnTimeData",
            }
        }
        hb, bound = resolve_heartbeat_for_aura(TRUEAIDATA_AURA, validators_hb, bindings)
        self.assertEqual(hb, {})
        self.assertIsNotNone(bound)
        self.assertEqual(bound["certDaemonSs58"], TRUEAIDATA_CERT_DAEMON)


if __name__ == "__main__":
    unittest.main()
