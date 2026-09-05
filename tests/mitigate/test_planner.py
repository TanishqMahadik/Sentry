"""Tests for mitigate/planner.py — escalation ladder and safety rails."""

import time
import unittest
from sentry.core.models import MitigationAction, ThreatVerdict
from sentry.detect.correlator import ThreatStage
from sentry.mitigate.planner import Planner, SafetyRails


def _make_verdict(
    threat_type: str = "SYN_FLOOD",
    subject_id: str = "10.0.0.1",
    severity: str = "high",
    confidence: float = 0.9,
) -> ThreatVerdict:
    return ThreatVerdict(
        threat_type=threat_type,
        subject_id=subject_id,
        severity=severity,
        confidence=confidence,
        timestamp=int(time.time()),
        evidence={"device_id": "of:0000000000000001"},
    )


class TestSafetyRails(unittest.TestCase):
    """Test individual safety rail checks."""

    def test_low_confidence_fails(self):
        rails = SafetyRails(min_confidence=0.7)
        verdict = _make_verdict(confidence=0.5)
        failures = rails.check(verdict, 1, {})
        self.assertGreater(len(failures), 0)
        self.assertTrue(any("Confidence" in f for f in failures))

    def test_topology_poisoning_blocked(self):
        rails = SafetyRails()
        verdict = _make_verdict(threat_type="TOPOLOGY_POISONING", confidence=0.9)
        failures = rails.check(verdict, 1, {})
        self.assertGreater(len(failures), 0)

    def test_empty_subject_id_fails(self):
        rails = SafetyRails()
        verdict = _make_verdict(subject_id="", confidence=0.9)
        failures = rails.check(verdict, 1, {})
        self.assertGreater(len(failures), 0)

    def test_future_timestamp_fails(self):
        rails = SafetyRails()
        verdict = _make_verdict(confidence=0.9)
        verdict.timestamp = int(time.time()) + 600
        failures = rails.check(verdict, 1, {})
        self.assertGreater(len(failures), 0)

    def test_clean_verdict_passes(self):
        rails = SafetyRails()
        verdict = _make_verdict(threat_type="SYN_FLOOD", confidence=0.9)
        failures = rails.check(verdict, 1, {}, current_stage=0)
        self.assertEqual(len(failures), 0)

    def test_max_stage_exceeded(self):
        rails = SafetyRails(max_stage_for_auto=2)
        verdict = _make_verdict(confidence=0.9)
        failures = rails.check(verdict, 3, {})
        self.assertTrue(any("max automated stage" in f for f in failures))

    def test_stage_skip_fails(self):
        rails = SafetyRails()
        verdict = _make_verdict(confidence=0.9)
        failures = rails.check(verdict, 3, {}, current_stage=0)
        self.assertTrue(any("skip stages" in f for f in failures))

    def test_already_mitigated_fails(self):
        rails = SafetyRails()
        verdict = _make_verdict(subject_id="10.0.0.1", confidence=0.9)
        existing = MitigationAction(
            action_id="m-000001",
            threat_verdict=verdict,
            stage=1,
            action_type="install_meter",
            device_id="of:1",
            payload={},
            applied_at=int(time.time()),
            expires_at=int(time.time()) + 60,
            status="applied",
        )
        failures = rails.check(verdict, 1, {"10.0.0.1": existing})
        self.assertTrue(any("already mitigated" in f for f in failures))


class TestPlanner(unittest.TestCase):
    """Test the escalation planner."""

    def test_topology_poisoning_never_planned(self):
        planner = Planner()
        verdict = _make_verdict(threat_type="TOPOLOGY_POISONING", confidence=0.9)
        action = planner.plan_action(verdict, ThreatStage.CONFIRMED, 0, {})
        self.assertIsNone(action)

    def test_low_severity_escalates_to_throttle(self):
        planner = Planner()
        verdict = _make_verdict(severity="low", confidence=0.9)
        action = planner.plan_action(verdict, ThreatStage.CONFIRMED, 0, {})
        # severity "low" maps to stage 0, but max(0, 0+1)=1 -> throttle
        self.assertIsNotNone(action)
        self.assertEqual(action.stage, 1)

    def test_high_severity_throttle(self):
        planner = Planner()
        verdict = _make_verdict(severity="high", confidence=0.9)
        action = planner.plan_action(verdict, ThreatStage.CONFIRMED, 0, {})
        # high -> stage 2, but from stage 0 can only go to 1 (rail 5)
        # Actually: max(severity_stage=2, 0+1=1) = 2, but current_stage=0 so 2 > 0+1
        # This should fail the stage skip rail, so None
        # Use fresh state where current_stage makes sense
        self.assertIsNone(action)  # Fails stage skip rail

    def test_high_from_stage_1_escalates(self):
        planner = Planner()
        verdict = _make_verdict(severity="high", confidence=0.9)
        action = planner.plan_action(verdict, ThreatStage.CONFIRMED, 1, {})
        # high -> 2, from stage 1 can go to 2 (1+1=2) -> ok
        self.assertIsNotNone(action)
        self.assertEqual(action.stage, 2)
        self.assertFalse(action.payload.get("isPermanent", True))

    def test_action_has_valid_ttl(self):
        planner = Planner()
        verdict = _make_verdict(severity="medium", confidence=0.9)
        action = planner.plan_action(verdict, ThreatStage.CONFIRMED, 0, {})
        self.assertIsNotNone(action)
        self.assertGreater(action.expires_at, action.applied_at)


if __name__ == "__main__":
    unittest.main()
