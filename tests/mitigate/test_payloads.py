"""Tests for mitigate/payloads.py — OpenFlow payload construction."""

import unittest

from sentry.mitigate.payloads import (
    STAGE_TTLS,
    build_observe_payload,
    build_payload,
    build_port_isolation_payload,
    build_quarantine_payload,
    build_selective_drop_payload,
    build_throttle_payload,
)


class TestObservePayload(unittest.TestCase):
    """Test Stage 0 observe payload."""

    def test_observe_returns_no_rule(self):
        payload = build_observe_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertEqual(payload["stage"], 0)
        self.assertEqual(payload["action"], "none")


class TestThrottlePayload(unittest.TestCase):
    """Test Stage 1 throttle payload."""

    def test_throttle_has_meter(self):
        payload = build_throttle_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertEqual(payload["stage"], 1)
        self.assertFalse(payload["isPermanent"])  # NFR-1 fail-open
        self.assertEqual(payload["meter"]["bands"][0]["type"], "DROP")

    def test_throttle_has_timeout(self):
        payload = build_throttle_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertGreater(payload["timeout"], 0)


class TestSelectiveDropPayload(unittest.TestCase):
    """Test Stage 2 selective drop payload."""

    def test_drop_has_drop_instruction(self):
        payload = build_selective_drop_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertEqual(payload["stage"], 2)
        self.assertFalse(payload["isPermanent"])
        instructions = payload["flow_rule"]["treatment"]["instructions"]
        self.assertEqual(instructions[0]["type"], "DROP")

    def test_drop_has_selector_criteria(self):
        payload = build_selective_drop_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        criteria = payload["flow_rule"]["selector"]["criteria"]
        self.assertEqual(criteria[0]["type"], "IP_SRC")

    def test_drop_with_dst_port(self):
        payload = build_selective_drop_payload(
            "of:1", "10.0.0.1", "SYN_FLOOD", dst_port=80
        )
        criteria = payload["flow_rule"]["selector"]["criteria"]
        self.assertTrue(any(c["type"] == "TCP_DST" for c in criteria))


class TestQuarantinePayload(unittest.TestCase):
    """Test Stage 3 quarantine payload."""

    def test_quarantine_redirects(self):
        payload = build_quarantine_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertEqual(payload["stage"], 3)
        self.assertFalse(payload["isPermanent"])
        instructions = payload["flow_rule"]["treatment"]["instructions"]
        self.assertEqual(instructions[0]["type"], "OUTPUT")


class TestPortIsolationPayload(unittest.TestCase):
    """Test Stage 4 port isolation payload."""

    def test_port_isolation_disables(self):
        payload = build_port_isolation_payload("of:1", "10.0.0.1", "SYN_FLOOD")
        self.assertEqual(payload["stage"], 4)
        self.assertFalse(payload["port_mod"]["isEnabled"])


class TestBuildPayloadDispatch(unittest.TestCase):
    """Test the build_payload dispatcher."""

    def test_build_payload_all_stages(self):
        for stage in range(5):
            payload = build_payload(
                stage, "of:1", "10.0.0.1", "SYN_FLOOD"
            )
            self.assertEqual(payload["stage"], stage)

    def test_invalid_stage_raises(self):
        with self.assertRaises(ValueError):
            build_payload(5, "of:1", "10.0.0.1", "SYN_FLOOD")

    def test_stage_ttls_all_positive_for_action_stages(self):
        for stage in range(1, 5):
            self.assertGreater(STAGE_TTLS[stage], 0)


if __name__ == "__main__":
    unittest.main()
