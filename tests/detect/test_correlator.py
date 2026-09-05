"""Tests for detect/correlator.py — threat state machine with hysteresis."""

import time
import unittest

from sentry.core.models import ThreatVerdict
from sentry.detect.correlator import Correlator, SubjectState, ThreatStage


def _make_verdict(threat_type: str = "SYN_FLOOD", subject_id: str = "test") -> ThreatVerdict:
    """Helper to create a ThreatVerdict with required fields."""
    return ThreatVerdict(
        threat_type=threat_type,
        subject_id=subject_id,
        severity="high",
        confidence=0.8,
        timestamp=int(time.time()),
        evidence={},
    )


class TestSubjectState(unittest.TestCase):
    """Test individual subject state transitions."""

    def test_starts_clean(self):
        state = SubjectState("test")
        self.assertEqual(state.stage, ThreatStage.CLEAN)

    def test_single_detection_goes_to_suspected(self):
        state = SubjectState("test", confirm_threshold=2)
        verdict = _make_verdict()
        stage = state.update(verdict)
        self.assertEqual(stage, ThreatStage.SUSPECTED)
        self.assertEqual(state.positive_count, 1)

    def test_two_detections_stay_suspected(self):
        state = SubjectState("test", confirm_threshold=2)
        verdict = _make_verdict()
        state.update(verdict)
        stage = state.update(verdict)
        self.assertEqual(stage, ThreatStage.SUSPECTED)
        self.assertEqual(state.positive_count, 2)

    def test_three_detections_confirm(self):
        state = SubjectState("test", confirm_threshold=2)
        verdict = _make_verdict()
        state.update(verdict)
        state.update(verdict)
        # After 2 positives: SUSPECTED. Need confirm_threshold + 2 = 4 for CONFIRMED.
        stage = state.update(verdict)
        self.assertEqual(stage, ThreatStage.SUSPECTED)
        stage = state.update(verdict)
        self.assertEqual(stage, ThreatStage.CONFIRMED)

    def test_clean_resets_after_threshold(self):
        state = SubjectState("test", confirm_threshold=2, clear_threshold=3)
        verdict = _make_verdict()
        state.update(verdict)
        state.update(verdict)

        # 3 clean windows should clear
        state.update(None)
        state.update(None)
        stage = state.update(None)
        self.assertEqual(stage, ThreatStage.CLEAN)
        self.assertIsNone(state.threat_type)

    def test_clean_count_resets_on_detection(self):
        state = SubjectState("test", confirm_threshold=2, clear_threshold=3)
        verdict = _make_verdict()
        state.update(verdict)
        state.update(None)
        state.update(None)
        # 2 clean, then detection resets clean count and increments positive
        state.update(verdict)
        self.assertEqual(state.clean_count, 0)
        self.assertEqual(state.positive_count, 1)

    def test_topology_poisoning_caps_at_suspected(self):
        state = SubjectState("test", confirm_threshold=2)
        state._alert_only_types = {"TOPOLOGY_POISONING"}
        verdict = _make_verdict(threat_type="TOPOLOGY_POISONING")
        for _ in range(10):
            stage = state.update(verdict)
        self.assertEqual(stage, ThreatStage.SUSPECTED)


class TestCorrelator(unittest.TestCase):
    """Test correlator with hysteresis."""

    def test_returns_empty_for_clean_metrics(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        verdicts = corr.evaluate_cycle({}, {}, {})
        self.assertEqual(len(verdicts), 0)

    def test_single_detection_returns_empty(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        verdicts = corr.evaluate_cycle(port_metrics, {}, {})
        # Single detection should not confirm (confirm_threshold=2)
        self.assertEqual(len(verdicts), 0)

    def test_two_detections_confirm(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        # First cycle: SUSPECTED (single detection, not enough for confirm)
        corr.evaluate_cycle(port_metrics, {}, {})
        # Multiple cycles needed: confirm_threshold + 2 = 4 positives for CONFIRMED
        corr.evaluate_cycle(port_metrics, {}, {})
        corr.evaluate_cycle(port_metrics, {}, {})
        verdicts = corr.evaluate_cycle(port_metrics, {}, {})
        self.assertGreater(len(verdicts), 0)

    def test_get_active_threats(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        corr.evaluate_cycle(port_metrics, {}, {})
        corr.evaluate_cycle(port_metrics, {}, {})
        active = corr.get_active_threats()
        self.assertGreater(len(active), 0)

    def test_threat_clears_after_clean_windows(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        corr.evaluate_cycle(port_metrics, {}, {})
        corr.evaluate_cycle(port_metrics, {}, {})

        # 3 clean cycles
        for _ in range(3):
            corr.evaluate_cycle({}, {}, {})

        active = corr.get_active_threats()
        self.assertEqual(len(active), 0)

    def test_reset_clears_all(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        corr.evaluate_cycle(port_metrics, {}, {})
        corr.evaluate_cycle(port_metrics, {}, {})
        corr.reset()
        self.assertEqual(len(corr.get_all_states()), 0)

    def test_multiple_rules_independently(self):
        corr = Correlator(confirm_threshold=2, clear_threshold=3)
        # Flow-table exhaustion: needs many flows
        flow_metrics_a = {"flow_count": 900, "subject_id": "device_a"}
        corr.evaluate_cycle({}, flow_metrics_a, {})
        corr.evaluate_cycle({}, flow_metrics_a, {})

        # ARP spoofing: needs low entropy
        flow_metrics_b = {"arp_entropy": 0.1, "duplicate_macs": 0, "subject_id": "device_b"}
        corr.evaluate_cycle({}, flow_metrics_b, {})
        corr.evaluate_cycle({}, flow_metrics_b, {})

        active = corr.get_active_threats()
        self.assertGreaterEqual(len(active), 2)


if __name__ == "__main__":
    unittest.main()
