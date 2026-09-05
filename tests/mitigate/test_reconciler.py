"""Tests for mitigate/reconciler.py — startup reconciliation."""

import json
import time
import unittest

from sentry.collect.window import WindowManager
from sentry.core.models import MitigationAction, ThreatVerdict
from sentry.mitigate.executor import Executor
from sentry.mitigate.ledger import AuditLedger
from sentry.mitigate.reconciler import Reconciler
from sentry.mitigate.verifier import Verifier
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport


class TestReconciler(unittest.TestCase):
    """Test startup reconciliation logic."""

    def setUp(self):
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)
        self.executor = Executor(self.client, dry_run=True)
        self.ledger = AuditLedger("test_reconciler_ledger.jsonl")
        self.ledger.clear()
        self.window_manager = WindowManager()
        self.verifier = Verifier(self.client)
        self.reconciler = Reconciler(
            self.executor, self.verifier, self.ledger, self.window_manager
        )

    def tearDown(self):
        self.ledger.clear()

    def _add_applied_entry(self, action_id: str, subject_id: str = "10.0.0.1",
                           expires_in: int = 600) -> None:
        """Add an 'applied' entry to the ledger."""
        now = int(time.time())
        verdict = ThreatVerdict(
            threat_type="SYN_FLOOD",
            subject_id=subject_id,
            severity="high",
            confidence=0.9,
            timestamp=now,
            evidence={"device_id": "of:1"},
        )
        action = MitigationAction(
            action_id=action_id,
            threat_verdict=verdict,
            stage=2,
            action_type="install_flow",
            device_id="of:1",
            payload={"flow_rule": {"priority": 50}},
            applied_at=now,
            expires_at=now + expires_in,
            status="applied",
        )
        self.ledger.append_action(action)

    def test_reconcile_empty_ledger(self):
        """Reconciling an empty ledger does nothing."""
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["verified"], 0)
        self.assertEqual(stats["revoked"], 0)
        self.assertEqual(stats["frozen"], 0)

    def test_reconcile_verifies_active_rule(self):
        """Active rules still on the switch are verified and baselines frozen."""
        self._add_applied_entry("m-001", expires_in=600)
        # FakeTransport returns empty flows → verification fails
        # We need to register a matching flow
        now = int(time.time())
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "sentry-flow",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 40000,
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["verified"], 1)
        self.assertEqual(stats["frozen"], 1)
        self.assertTrue(self.window_manager.is_frozen("10.0.0.1"))

    def test_reconcile_revokes_stale_rule(self):
        """Expired rules still on the switch are revoked."""
        self._add_applied_entry("m-002", expires_in=-600)  # Already expired
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "sentry-stale",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 40000,
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["revoked"], 1)

    def test_reconcile_revokes_missing_rule(self):
        """Rules not found on the switch are marked as revoked (crash recovery)."""
        self._add_applied_entry("m-003", expires_in=600)
        # Empty flow table = rule already gone
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["revoked"], 1)

    def test_reconcile_mixed_actions(self):
        """Reconciler handles a mix of valid, stale, and missing rules."""
        self._add_applied_entry("m-valid", subject_id="10.0.0.1", expires_in=600)
        self._add_applied_entry("m-stale", subject_id="10.0.0.2", expires_in=-100)
        self._add_applied_entry("m-missing", subject_id="10.0.0.3", expires_in=600)

        # Only m-valid has a matching flow on the switch
        now = int(time.time())
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "valid-flow",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 40000,
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["verified"], 1)
        self.assertEqual(stats["revoked"], 2)
        self.assertEqual(stats["frozen"], 1)

    def test_reconcile_ignores_non_applied_entries(self):
        """Only 'applied' entries are reconciled."""
        now = int(time.time())
        verdict = ThreatVerdict(
            threat_type="SYN_FLOOD",
            subject_id="10.0.0.1",
            severity="high",
            confidence=0.9,
            timestamp=now,
            evidence={"device_id": "of:1"},
        )
        action = MitigationAction(
            action_id="m-old",
            threat_verdict=verdict,
            stage=2,
            action_type="install_flow",
            device_id="of:1",
            payload={"flow_rule": {"priority": 50}},
            applied_at=now,
            expires_at=now + 600,
            status="revoked",  # Not applied
        )
        self.ledger.append_action(action)
        stats = self.reconciler.reconcile()
        self.assertEqual(stats["verified"], 0)
        self.assertEqual(stats["revoked"], 0)


if __name__ == "__main__":
    unittest.main()
