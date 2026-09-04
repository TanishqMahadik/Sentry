"""Tests for features/extractor.py feature extraction."""

import unittest
from sentry.core.models import (
    Device,
    Flow,
    Host,
    Link,
    PortStats,
    TelemetrySnapshot,
)
from sentry.features.extractor import FeatureExtractor


class TestFeatureExtractor(unittest.TestCase):
    """Test feature extraction from telemetry snapshots."""

    def setUp(self):
        """Set up test environment."""
        self.extractor = FeatureExtractor()

    def test_extract_port_features_basic(self):
        """Test basic port feature extraction."""
        rate_metrics = {
            "pps_rx": 100.0,
            "pps_tx": 50.0,
            "bps_rx": 15000.0,
            "bps_tx": 7500.0,
            "drops_rx_rate": 0.0,
            "drops_tx_rate": 0.0,
            "errors_rx_rate": 0.0,
            "errors_tx_rate": 0.0,
        }

        snapshot = TelemetrySnapshot(
            timestamp=1000,
            hosts=[
                Host(host_id="h1", mac="00:01", vlan="", ip_addresses=["10.0.0.1"]),
                Host(host_id="h2", mac="00:02", vlan="", ip_addresses=["10.0.0.2"]),
            ],
            flows=[],
        )

        features = self.extractor.extract_port_features("of:1:1", rate_metrics, snapshot)

        # Check basic rate features
        self.assertEqual(features["pps_rx"], 100.0)
        self.assertEqual(features["pps_tx"], 50.0)
        self.assertEqual(features["bps_rx"], 15000.0)
        self.assertEqual(features["bps_tx"], 7500.0)

        # Check derived features
        # packet_size_ratio = (15000 + 7500) / (100 + 50) = 22500 / 150 = 150 bytes/packet
        self.assertAlmostEqual(features["packet_size_ratio"], 150.0, places=1)

        # tx_rx_ratio = 50 / 100 = 0.5
        self.assertAlmostEqual(features["tx_rx_ratio"], 0.5, places=2)

    def test_extract_host_features(self):
        """Test host feature extraction."""
        snapshot = TelemetrySnapshot(
            timestamp=1000,
            flows=[
                Flow(
                    flow_id="f1",
                    device_id="of:1",
                    table_id=0,
                    app_id="app1",
                    priority=100,
                    timeout=60,
                    is_permanent=False,
                    state="ADDED",
                    packets=1000,
                    bytes=150000,
                ),
                Flow(
                    flow_id="f2",
                    device_id="of:1",
                    table_id=0,
                    app_id="app1",
                    priority=100,
                    timeout=60,
                    is_permanent=False,
                    state="ADDED",
                    packets=500,
                    bytes=75000,
                ),
            ],
        )

        features = self.extractor.extract_host_features("10.0.0.1", snapshot)
        # Basic checks - flows are present
        self.assertIn("flow_count", features)
        self.assertIn("total_packets", features)
        self.assertIn("avg_packet_size", features)

    def test_extract_device_features(self):
        """Test device feature extraction."""
        snapshot = TelemetrySnapshot(
            timestamp=1000,
            flows=[
                Flow(
                    flow_id="f1",
                    device_id="of:0000000000000001",
                    table_id=0,
                    app_id="app1",
                    priority=100,
                    timeout=60,
                    is_permanent=False,
                    state="ADDED",
                    packets=1000,
                    bytes=150000,
                ),
                Flow(
                    flow_id="f2",
                    device_id="of:0000000000000001",
                    table_id=0,
                    app_id="app1",
                    priority=100,
                    timeout=60,
                    is_permanent=False,
                    state="PENDING_ADD",
                    packets=0,
                    bytes=0,
                ),
            ],
            port_stats=[
                PortStats(
                    device_id="of:0000000000000001",
                    port_number="1",
                    timestamp=1000,
                    packets_received=10000,
                    packets_rx_dropped=100,
                )
            ],
        )

        features = self.extractor.extract_device_features("of:0000000000000001", snapshot)

        self.assertEqual(features["flow_count"], 2.0)
        self.assertEqual(features["pending_flow_count"], 1.0)
        self.assertEqual(features["total_packets_rx"], 10000.0)
        self.assertEqual(features["total_drops"], 100.0)
        self.assertAlmostEqual(features["drop_ratio"], 0.01, places=3)

    def test_extract_topology_features(self):
        """Test topology-level feature extraction."""
        snapshot = TelemetrySnapshot(
            timestamp=1000,
            devices=[
                Device(device_id="of:1", available=True, role="MASTER", type="SWITCH"),
                Device(device_id="of:2", available=True, role="MASTER", type="SWITCH"),
            ],
            hosts=[
                Host(host_id="h1", mac="00:01", vlan="", ip_addresses=["10.0.0.1"]),
            ],
            links=[
                Link(
                    src_device="of:1",
                    src_port="1",
                    dst_device="of:2",
                    dst_port="1",
                    link_type="DIRECT",
                    state="ACTIVE",
                ),
            ],
        )

        features = self.extractor.extract_topology_features(snapshot)

        self.assertEqual(features["device_count"], 2.0)
        self.assertEqual(features["host_count"], 1.0)
        self.assertEqual(features["link_count"], 1.0)
        self.assertEqual(features["active_link_count"], 1.0)
        self.assertEqual(features["link_health_ratio"], 1.0)
        self.assertEqual(features["available_device_count"], 2.0)
        self.assertEqual(features["device_availability_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
