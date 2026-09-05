"""Tests for sentry.ml.advisory — scoring facade and API annotation."""

from __future__ import annotations

import unittest

from sentry.core.models import ThreatVerdict
from sentry.ml.advisory import (
    FEATURE_ORDER,
    AdvisoryScorer,
    _band_for,
    _recommendation_for,
    vector_from_metrics,
)
from tests.ml._helpers import (
    attack_metrics,
    benign_metrics,
    build_test_scorer,
)

_ARP = FEATURE_ORDER.index("arp_entropy")
_PPS_RX = FEATURE_ORDER.index("pps_rx")
_FLOW = FEATURE_ORDER.index("flow_count")


class TestVectorFromMetrics(unittest.TestCase):
    """Feature-vector construction."""

    def test_length_and_defaults(self):
        vector = vector_from_metrics({}, {})
        self.assertEqual(len(vector), len(FEATURE_ORDER))
        # arp_entropy defaults to 1.0 (healthy); everything else 0.
        self.assertEqual(vector[_ARP], 1.0)
        self.assertEqual(vector[_PPS_RX], 0.0)
        self.assertEqual(vector[_FLOW], 0.0)

    def test_maps_port_metrics(self):
        vector = vector_from_metrics({"p1": {"pps_rx": 5000.0}}, {})
        self.assertEqual(vector[_PPS_RX], 5000.0)

    def test_takes_max_across_ports(self):
        port_metrics = {
            "p1": {"pps_rx": 100.0},
            "p2": {"pps_rx": 900.0},
        }
        vector = vector_from_metrics(port_metrics, {})
        self.assertEqual(vector[_PPS_RX], 900.0)

    def test_maps_flow_metrics(self):
        vector = vector_from_metrics({}, {"flow_count": 42.0, "arp_entropy": 0.1})
        self.assertEqual(vector[_FLOW], 42.0)
        self.assertEqual(vector[_ARP], 0.1)

    def test_computes_ratios(self):
        port_metrics = {"p1": {"pps_rx": 10.0, "pps_tx": 2.0, "bps_rx": 500.0, "bps_tx": 100.0}}
        vector = vector_from_metrics(port_metrics, {})
        tx_rx = FEATURE_ORDER.index("tx_rx_ratio")
        pkt = FEATURE_ORDER.index("packet_size_ratio")
        self.assertAlmostEqual(vector[tx_rx], 0.2)
        self.assertAlmostEqual(vector[pkt], 50.0)


class TestBands(unittest.TestCase):
    """Band threshold boundaries mirror detect/rules.py."""

    def test_boundaries(self):
        self.assertEqual(_band_for(0.85), "CRITICAL")
        self.assertEqual(_band_for(0.8499), "HIGH")
        self.assertEqual(_band_for(0.60), "HIGH")
        self.assertEqual(_band_for(0.5999), "MEDIUM")
        self.assertEqual(_band_for(0.40), "MEDIUM")
        self.assertEqual(_band_for(0.3999), "LOW")
        self.assertEqual(_band_for(0.0), "LOW")

    def test_recommendation_per_band(self):
        self.assertIn("no action", _recommendation_for("LOW", "benign"))
        self.assertIn("Review", _recommendation_for("MEDIUM", "benign"))
        self.assertIn("Stage 1-2", _recommendation_for("HIGH", "syn_flood"))
        self.assertIn("escalation", _recommendation_for("CRITICAL", "syn_flood"))


class TestScorerUnavailable(unittest.TestCase):
    """Graceful degradation without weights."""

    def test_default_unavailable(self):
        scorer = AdvisoryScorer()
        self.assertFalse(scorer.available)
        self.assertIsNone(scorer.score({}, {}))

    def test_missing_path_unavailable(self):
        scorer = AdvisoryScorer(weights_path="nope/missing.json")
        self.assertFalse(scorer.available)
        self.assertIsNone(scorer.score({}, {}))


class TestScorerCrafted(unittest.TestCase):
    """End-to-end scoring with deterministic crafted weights."""

    def test_attack_scores_critical(self):
        scorer = build_test_scorer()
        port_metrics, flow_metrics = attack_metrics()
        verdict = scorer.score(port_metrics, flow_metrics)
        self.assertIsNotNone(verdict)
        self.assertGreater(verdict.score, 0.8)
        self.assertIn(verdict.band, ("HIGH", "CRITICAL"))
        self.assertEqual(verdict.predicted, "attack")
        self.assertTrue(verdict.top_features)

    def test_benign_scores_low(self):
        scorer = build_test_scorer()
        port_metrics, flow_metrics = benign_metrics()
        verdict = scorer.score(port_metrics, flow_metrics)
        self.assertIsNotNone(verdict)
        self.assertLess(verdict.score, 0.4)
        self.assertEqual(verdict.band, "LOW")
        self.assertEqual(verdict.predicted, "benign")

    def test_verdict_to_dict_shape(self):
        scorer = build_test_scorer()
        port_metrics, flow_metrics = attack_metrics()
        data = scorer.score(port_metrics, flow_metrics).to_dict()
        for key in ("score", "predicted", "band", "top_features", "recommendation"):
            self.assertIn(key, data)
        self.assertIsInstance(data["score"], float)


class TestAttachToThreats(unittest.TestCase):
    """API threat-feed annotation."""

    def _threat(self) -> ThreatVerdict:
        return ThreatVerdict(
            threat_type="syn_flood",
            subject_id="10.0.0.5",
            severity="high",
            confidence=0.9,
            timestamp=123,
            evidence={"pps_rx": 5000.0},
            message="SYN flood detected",
        )

    def test_appends_advisory_when_available(self):
        scorer = build_test_scorer()
        port_metrics, flow_metrics = attack_metrics()
        entries = scorer.attach_to_threats([self._threat()], port_metrics, flow_metrics)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["threat_type"], "syn_flood")
        self.assertEqual(entry["subject_id"], "10.0.0.5")
        self.assertIn("advisory", entry)
        self.assertIn("band", entry["advisory"])

    def test_no_advisory_when_unavailable(self):
        scorer = AdvisoryScorer()
        entries = scorer.attach_to_threats([self._threat()], {}, {})
        self.assertEqual(len(entries), 1)
        self.assertNotIn("advisory", entries[0])
        # Threat fields still preserved.
        self.assertEqual(entries[0]["threat_type"], "syn_flood")


if __name__ == "__main__":
    unittest.main()
