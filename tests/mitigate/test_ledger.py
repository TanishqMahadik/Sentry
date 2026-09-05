"""Tests for mitigate/ledger.py — tamper-evident audit ledger."""

import json
import os
import tempfile
import time
import unittest
from sentry.core.models import ThreatVerdict, MitigationAction
from sentry.mitigate.ledger import AuditLedger


def _make_action(action_id: str = "mitigation-000001", ledger_path: str = "") -> MitigationAction:
    verdict = ThreatVerdict(
        threat_type="SYN_FLOOD",
        subject_id="10.0.0.1",
        severity="high",
        confidence=0.9,
        timestamp=int(time.time()),
        evidence={"device_id": "of:0000000000000001"},
    )
    return MitigationAction(
        action_id=action_id,
        threat_verdict=verdict,
        stage=1,
        action_type="install_meter",
        device_id="of:0000000000000001",
        payload={"action": "install_meter"},
        applied_at=int(time.time()),
        expires_at=int(time.time()) + 60,
        status="applied",
    )


class TestAuditLedger(unittest.TestCase):
    """Test ledger append, verify, and tamper detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ledger_path = os.path.join(self.tmpdir, "audit_test.jsonl")

    def tearDown(self):
        # Clean up
        if os.path.exists(self.ledger_path):
            os.remove(self.ledger_path)
        try:
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    def test_append_and_verify(self):
        ledger = AuditLedger(self.ledger_path)
        action = _make_action()
        ledger.append_action(action)
        ok, errors = ledger.verify()
        self.assertTrue(ok)
        self.assertEqual(len(errors), 0)

    def test_multiple_entries_verify(self):
        ledger = AuditLedger(self.ledger_path)
        for i in range(5):
            action = _make_action(action_id=f"mitigation-{i:06d}")
            ledger.append_action(action)
        ok, errors = ledger.verify()
        self.assertTrue(ok)
        self.assertEqual(ledger.get_entry_count(), 5)

    def test_tampered_entry_fails_verification(self):
        ledger = AuditLedger(self.ledger_path)
        for i in range(3):
            action = _make_action(action_id=f"mitigation-{i:06d}")
            ledger.append_action(action)

        # Tamper: overwrite second entry
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        entry = json.loads(lines[1])
        entry["stage"] = 99  # Tamper
        lines[1] = json.dumps(entry, sort_keys=True) + "\n"

        with open(self.ledger_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        ok, errors = ledger.verify()
        self.assertFalse(ok)
        self.assertGreater(len(errors), 0)

    def test_empty_ledger_verifies(self):
        ledger = AuditLedger(self.ledger_path)
        ok, errors = ledger.verify()
        self.assertTrue(ok)
        self.assertEqual(len(errors), 0)

    def test_get_entries_counts_correctly(self):
        ledger = AuditLedger(self.ledger_path)
        for i in range(3):
            action = _make_action(action_id=f"mitigation-{i:06d}")
            ledger.append_action(action)
        entries = ledger.get_entries()
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["entry_index"], 0)
        self.assertEqual(entries[2]["entry_index"], 2)

    def test_clear_resets_ledger(self):
        ledger = AuditLedger(self.ledger_path)
        ledger.append_action(_make_action())
        ledger.clear()
        self.assertEqual(ledger.get_entry_count(), 0)
        self.assertFalse(os.path.exists(self.ledger_path))


if __name__ == "__main__":
    unittest.main()
