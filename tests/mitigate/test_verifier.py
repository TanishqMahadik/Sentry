"""Tests for mitigate/verifier.py — read-back validation."""

import time
import unittest

from sentry.core.models import MitigationAction, ThreatVerdict
from sentry.mitigate.verifier import Verifier
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport


def _make_action(
    action_id: str = "m-000001",
    subject_id: str = "10.0.0.1",
    action_type: str = "install_flow",
    priority: int = 100,
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
        stage=2,
        action_type=action_type,
        device_id="of:1",
        payload={"flow_rule": {"priority": priority}},
        applied_at=now,
        expires_at=now + 600,
        status="applied",
    )


class TestVerifier(unittest.TestCase):
    """Test Verifier read-back logic."""

    def setUp(self):
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)
        self.verifier = Verifier(self.client)

    def test_verify_install_passes_when_flow_exists(self):
        """Verification passes when the expected flow is found on the switch."""
        action = _make_action(priority=100)
        # Register a matching flow in FakeTransport
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "sentry-drop-001",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 100,
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        self.assertTrue(self.verifier.verify_install(action))

    def test_verify_install_fails_when_no_match(self):
        """Verification fails when the flow is not found."""
        action = _make_action(priority=100)
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "other-flow",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 200,  # Different priority
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        self.assertFalse(self.verifier.verify_install(action))

    def test_verify_install_passes_for_non_flow_action(self):
        """Non-flow actions (disable_port, observe) skip verification."""
        action = _make_action(action_type="disable_port")
        self.assertTrue(self.verifier.verify_install(action))

    def test_verify_install_fails_on_client_error(self):
        """Verification fails if the client returns error response."""
        action = _make_action()
        # Register a fixture with an error structure that causes get_flows to return []
        self.transport.register_fixture("/flows/of:1", {})
        # With empty dict, get_flows returns [] → no match found → False
        self.assertFalse(self.verifier.verify_install(action))

    def test_verify_removal_passes_when_flow_gone(self):
        """Removal verification passes when the flow is no longer on the switch."""
        action = _make_action()
        # Empty flow table = rule successfully removed
        self.transport.register_fixture("/flows/of:1", {"flows": []})
        self.assertTrue(self.verifier.verify_removal(action))

    def test_verify_removal_fails_when_flow_still_exists(self):
        """Removal verification fails if the flow is still on the switch."""
        action = _make_action(priority=100)
        self.transport.register_fixture("/flows/of:1", {
            "flows": [{
                "id": "sentry-drop-001",
                "deviceId": "of:1",
                "tableId": 0,
                "appId": "sentry",
                "priority": 100,
                "timeout": 60,
                "isPermanent": False,
                "state": "ADDED",
                "selector": {"criteria": [{"type": "IP_SRC", "ip": "10.0.0.1"}]},
                "treatment": {"instructions": [{"type": "DROP"}]},
            }]
        })
        self.assertFalse(self.verifier.verify_removal(action))

    def test_verify_install_fails_on_exception(self):
        """Verification fails if the client throws an exception."""
        from unittest.mock import patch
        action = _make_action()
        with patch.object(self.client, 'get_flows', side_effect=ConnectionError("ONOS down")):
            self.assertFalse(self.verifier.verify_install(action))

    def test_verify_removal_fails_on_exception(self):
        """Removal verification fails if the client throws."""
        from unittest.mock import patch
        action = _make_action()
        with patch.object(self.client, 'get_flows', side_effect=ConnectionError("ONOS down")):
            self.assertFalse(self.verifier.verify_removal(action))


if __name__ == "__main__":
    unittest.main()
