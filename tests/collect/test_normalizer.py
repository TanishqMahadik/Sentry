"""Tests for collect/normalizer.py telemetry normalizer."""

import unittest
from sentry.collect.normalizer import TelemetryNormalizer
from sentry.core.models import PortStats, TelemetrySnapshot


class TestTelemetryNormalizer(unittest.TestCase):
    """Test normalizer delta calculations and edge cases."""

    def setUp(self):
        """Set up test environment."""
        self.normalizer = TelemetryNormalizer()

    def test_first_snapshot_returns_empty(self):
        """First snapshot should store state and return empty (no delta possible)."""
        snapshot = TelemetrySnapshot(
            timestamp=1000,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1000,
                    packets_received=100,
                    packets_sent=200,
                )
            ],
        )

        rates = self.normalizer.normalize_snapshot(snapshot)
        self.assertEqual(len(rates), 0)

    def test_second_snapshot_calculates_rates(self):
        """Second snapshot should calculate per-second rates correctly."""
        # First snapshot at t=1000
        snap1 = TelemetrySnapshot(
            timestamp=1000,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1000,
                    packets_received=100,
                    packets_sent=200,
                    bytes_received=10000,
                    bytes_sent=20000,
                )
            ],
        )
        self.normalizer.normalize_snapshot(snap1)

        # Second snapshot at t=1002 (2 seconds later)
        snap2 = TelemetrySnapshot(
            timestamp=1002,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1002,
                    packets_received=300,  # +200 packets in 2s = 100 pps
                    packets_sent=400,  # +200 packets in 2s = 100 pps
                    bytes_received=30000,  # +20000 bytes in 2s = 10000 bps
                    bytes_sent=40000,  # +20000 bytes in 2s = 10000 bps
                )
            ],
        )
        rates = self.normalizer.normalize_snapshot(snap2)

        self.assertIn("of:1:1", rates)
        self.assertEqual(rates["of:1:1"]["pps_rx"], 100.0)
        self.assertEqual(rates["of:1:1"]["pps_tx"], 100.0)
        self.assertEqual(rates["of:1:1"]["bps_rx"], 10000.0)
        self.assertEqual(rates["of:1:1"]["bps_tx"], 10000.0)

    def test_counter_reset_handling(self):
        """Counter reset (switch reboot) should be detected and interval skipped."""
        # First snapshot: 1000 packets
        snap1 = TelemetrySnapshot(
            timestamp=1000,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1000,
                    packets_received=1000,
                )
            ],
        )
        self.normalizer.normalize_snapshot(snap1)

        # Second snapshot: 50 packets (counter reset occurred!)
        snap2 = TelemetrySnapshot(
            timestamp=1002,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1002,
                    packets_received=50,  # < 1000, reset!
                )
            ],
        )
        rates = self.normalizer.normalize_snapshot(snap2)

        # Should skip this port due to reset
        self.assertNotIn("of:1:1", rates)

        # Third snapshot: 150 packets (delta from 50 = 100 in 2s = 50 pps)
        snap3 = TelemetrySnapshot(
            timestamp=1004,
            port_stats=[
                PortStats(
                    device_id="of:1",
                    port_number="1",
                    timestamp=1004,
                    packets_received=150,
                )
            ],
        )
        rates = self.normalizer.normalize_snapshot(snap3)
        self.assertIn("of:1:1", rates)
        self.assertEqual(rates["of:1:1"]["pps_rx"], 50.0)


if __name__ == "__main__":
    unittest.main()
