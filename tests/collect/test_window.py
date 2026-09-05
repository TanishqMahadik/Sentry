"""Tests for collect/window.py baseline management."""

import unittest

from sentry.collect.window import WindowManager


class TestWindowManager(unittest.TestCase):
    """Test window baseline management and Invariant I9 freeze."""

    def setUp(self):
        """Set up test environment."""
        self.wm = WindowManager(window_seconds=5, warmup_windows=3, ewma_alpha=0.3)

    def test_first_update_creates_baseline(self):
        """First update should initialize baseline with the given value."""
        baseline = self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)
        self.assertEqual(baseline.ewma_mean, 100.0)
        self.assertEqual(baseline.sample_count, 1)
        self.assertEqual(baseline.mad_deviation, 0.0)

    def test_ewma_calculation(self):
        """EWMA should smooth values correctly."""
        # alpha = 0.3
        # Update 1: mean = 100
        self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)

        # Update 2: mean = 0.3*120 + 0.7*100 = 36 + 70 = 106
        baseline = self.wm.update_baseline("host1", "pps_rx", 120.0, 1001)
        self.assertAlmostEqual(baseline.ewma_mean, 106.0, places=1)
        self.assertEqual(baseline.sample_count, 2)

        # MAD should be updated too
        self.assertGreater(baseline.mad_deviation, 0)

    def test_warmup_gating(self):
        """Warmup should require N windows before completion."""
        # Warmup = 3 windows
        self.assertFalse(self.wm.is_warmup_complete("host1"))

        self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)
        self.assertFalse(self.wm.is_warmup_complete("host1"))

        self.wm.update_baseline("host1", "pps_rx", 110.0, 1001)
        self.assertFalse(self.wm.is_warmup_complete("host1"))

        self.wm.update_baseline("host1", "pps_rx", 105.0, 1002)
        self.assertTrue(self.wm.is_warmup_complete("host1"))

    def test_anomaly_detection_mad_threshold(self):
        """Anomaly detection using MAD threshold."""
        # Build baseline: mean ~ 100, mad ~ 5
        for i in range(10):
            self.wm.update_baseline("host1", "pps_rx", 100.0 + (i % 5), 1000 + i)

        baseline = self.wm.get_baseline("host1", "pps_rx")
        self.assertIsNotNone(baseline)

        # Normal value within 3 MAD
        is_anom, score = self.wm.is_anomalous("host1", "pps_rx", 105.0, mad_threshold=3.0)
        self.assertFalse(is_anom)

        # Anomalous value: 500 is far from baseline mean
        is_anom, score = self.wm.is_anomalous("host1", "pps_rx", 500.0, mad_threshold=3.0)
        self.assertTrue(is_anom)
        self.assertGreater(score, 3.0)

    def test_invariant_i9_freeze(self):
        """Invariant I9: frozen subjects should not update baselines."""
        # Build baseline
        self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)
        baseline_before = self.wm.get_baseline("host1", "pps_rx")
        mean_before = baseline_before.ewma_mean

        # Freeze subject
        self.wm.freeze_subject("host1")
        self.assertTrue(self.wm.is_frozen("host1"))
        self.assertTrue(baseline_before.frozen)

        # Attempt to update - should be ignored
        self.wm.update_baseline("host1", "pps_rx", 500.0, 1001)
        baseline_after = self.wm.get_baseline("host1", "pps_rx")

        # Mean should not have changed
        self.assertEqual(baseline_after.ewma_mean, mean_before)

    def test_unfreeze_subject(self):
        """Unfreezing should allow baseline updates again."""
        self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)
        self.wm.freeze_subject("host1")

        # Unfreeze
        self.wm.unfreeze_subject("host1")
        self.assertFalse(self.wm.is_frozen("host1"))

        # Update should now work
        baseline = self.wm.update_baseline("host1", "pps_rx", 120.0, 1001)
        self.assertNotEqual(baseline.ewma_mean, 100.0)
        self.assertFalse(baseline.frozen)

    def test_multiple_metrics_per_subject(self):
        """Each subject can track multiple metrics independently."""
        self.wm.update_baseline("host1", "pps_rx", 100.0, 1000)
        self.wm.update_baseline("host1", "bps_rx", 50000.0, 1000)

        baseline_pps = self.wm.get_baseline("host1", "pps_rx")
        baseline_bps = self.wm.get_baseline("host1", "bps_rx")

        self.assertEqual(baseline_pps.ewma_mean, 100.0)
        self.assertEqual(baseline_bps.ewma_mean, 50000.0)


if __name__ == "__main__":
    unittest.main()
