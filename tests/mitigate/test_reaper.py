"""Tests for mitigate/reaper.py — background TTL expiry thread."""

import time
import unittest
from unittest.mock import MagicMock

from sentry.core.models import MitigationAction, ThreatVerdict
from sentry.collect.window import WindowManager
from sentry.mitigate.executor import Executor
from sentry.mitigate.ledger import AuditLedger
from sentry.mitigate.reaper import Reaper
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport


def _make_action(
    action_id: str = "m-000001",
    subject_id: str = "10.0.0.1",
    stage: int = 1,
    ttl: int = -1,  # -1 = already expired
) -> MitigationAction:
    now = int(time.time())
    verdict = ThreatVerdict(
        threat_type="SYN_FLOOD",
        subject_id=subject_id,
        severity="high",
        confidence=0.9,
        timestamp=now,
        evidence={"device_id": "of:1"},
    )
    return MitigationAction(
        action_id=action_id,
        threat_verdict=verdict,
        stage=stage,
        action_type="install_meter",
        device_id="of:1",
        payload={"rate": "100pps"},
        applied_at=now,
        expires_at=now + ttl,
        status="applied",
    )


class TestReaper(unittest.TestCase):
    """Test Reaper background expiry logic."""

    def setUp(self):
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)
        self.executor = Executor(self.client, dry_run=True)
        self.ledger = AuditLedger("test_reaper_ledger.jsonl")
        self.ledger.clear()
        self.window_manager = WindowManager()
        self.reaper = Reaper(
            self.executor, self.ledger, self.window_manager, check_interval=1
        )

    def tearDown(self):
        self.reaper.stop()
        self.ledger.clear()

    def test_register_and_track_action(self):
        """Registered actions are tracked by the reaper."""
        action = _make_action(ttl=300)
        self.reaper.register_action(action)
        self.assertEqual(self.reaper.get_active_count(), 1)
        actions = self.reaper.get_active_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].action_id, "m-000001")

    def test_expired_action_removed_on_check(self):
        """Expired actions are removed from tracking on check."""
        action = _make_action(ttl=-1)  # Already expired
        self.reaper.register_action(action)
        expired = self.reaper._check_and_expire()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].status, "expired")
        self.assertEqual(self.reaper.get_active_count(), 0)

    def test_active_action_not_expired(self):
        """Actions with future expiry are not expired."""
        action = _make_action(ttl=300)  # Expires in 5 min
        self.reaper.register_action(action)
        expired = self.reaper._check_and_expire()
        self.assertEqual(len(expired), 0)
        self.assertEqual(self.reaper.get_active_count(), 1)

    def test_expiry_unfreezes_baselines(self):
        """Expiring an action unfreezes the subject's baselines."""
        action = _make_action(ttl=-1)
        self.window_manager.freeze_subject("10.0.0.1")
        self.assertTrue(self.window_manager.is_frozen("10.0.0.1"))
        self.reaper.register_action(action)
        self.reaper._check_and_expire()
        self.assertFalse(self.window_manager.is_frozen("10.0.0.1"))

    def test_non_applied_actions_skipped(self):
        """Already expired/revoked actions are not re-processed."""
        action = _make_action(ttl=-1)
        action.status = "revoked"
        self.reaper.register_action(action)
        expired = self.reaper._check_and_expire()
        self.assertEqual(len(expired), 0)

    def test_thread_start_stop(self):
        """Reaper thread starts and stops cleanly."""
        self.reaper.start()
        self.assertTrue(self.reaper._thread.is_alive())
        self.reaper.stop()
        self.assertFalse(self.reaper._thread.is_alive())

    def test_start_idempotent(self):
        """Starting an already-running reaper is a no-op."""
        self.reaper.start()
        thread1 = self.reaper._thread
        self.reaper.start()  # Should not create a new thread
        self.assertIs(self.reaper._thread, thread1)
        self.reaper.stop()

    def test_multiple_actions_tracked(self):
        """Multiple actions are tracked independently."""
        a1 = _make_action(action_id="m-001", ttl=-1)
        a2 = _make_action(action_id="m-002", ttl=-1)
        a3 = _make_action(action_id="m-003", ttl=300)
        self.reaper.register_action(a1)
        self.reaper.register_action(a2)
        self.reaper.register_action(a3)
        self.assertEqual(self.reaper.get_active_count(), 3)
        expired = self.reaper._check_and_expire()
        self.assertEqual(len(expired), 2)
        self.assertEqual(self.reaper.get_active_count(), 1)


if __name__ == "__main__":
    unittest.main()
