"""Feature extraction for threat detection.

Extracts 16 statistical features from telemetry windows for detector consumption.
All features are normalized/scaled for consistent ML/rule-based processing.
"""

from __future__ import annotations

import logging
from typing import Any

from sentry.core.models import TelemetrySnapshot
from sentry.features.entropy import compute_ip_entropy, compute_port_entropy

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extracts 16-feature vectors from telemetry windows."""

    def __init__(self) -> None:
        """Initialize feature extractor."""
        pass

    def extract_port_features(
        self, port_key: str, rate_metrics: dict[str, float], snapshot: TelemetrySnapshot
    ) -> dict[str, float]:
        """Extract features for a single port.

        16 Features:
        1-4: Traffic rates (pps_rx, pps_tx, bps_rx, bps_tx)
        5-6: Drop rates (drops_rx_rate, drops_tx_rate)
        7-8: Error rates (errors_rx_rate, errors_tx_rate)
        9: Packet size ratio (bps/pps, indicates avg packet size)
        10: TX/RX ratio (traffic asymmetry indicator)
        11-12: Source IP entropy, Destination IP entropy
        13-14: Source port entropy, Destination port entropy
        15: Protocol entropy
        16: Flow table utilization (device-level)

        Args:
            port_key: Port identifier (device_id:port_number)
            rate_metrics: Rate metrics from normalizer
            snapshot: Full telemetry snapshot

        Returns:
            Dictionary of 16 feature values
        """
        features: dict[str, float] = {}

        # Features 1-8: Direct rate metrics
        features["pps_rx"] = rate_metrics.get("pps_rx", 0.0)
        features["pps_tx"] = rate_metrics.get("pps_tx", 0.0)
        features["bps_rx"] = rate_metrics.get("bps_rx", 0.0)
        features["bps_tx"] = rate_metrics.get("bps_tx", 0.0)
        features["drops_rx_rate"] = rate_metrics.get("drops_rx_rate", 0.0)
        features["drops_tx_rate"] = rate_metrics.get("drops_tx_rate", 0.0)
        features["errors_rx_rate"] = rate_metrics.get("errors_rx_rate", 0.0)
        features["errors_tx_rate"] = rate_metrics.get("errors_tx_rate", 0.0)

        # Feature 9: Packet size ratio (avg bytes per packet)
        pps_total = features["pps_rx"] + features["pps_tx"]
        bps_total = features["bps_rx"] + features["bps_tx"]
        features["packet_size_ratio"] = bps_total / pps_total if pps_total > 0 else 0.0

        # Feature 10: TX/RX asymmetry ratio
        if features["pps_rx"] > 0:
            features["tx_rx_ratio"] = features["pps_tx"] / features["pps_rx"]
        else:
            features["tx_rx_ratio"] = 0.0

        # Features 11-15: Entropy features (computed from flows/hosts)
        # For now, use simplified heuristics based on available data
        # In full implementation, these would analyze flow-level detail

        # Simplified IP entropy from hosts
        src_ips = [h.ip_addresses[0] for h in snapshot.hosts if h.ip_addresses]
        dst_ips = [h.ip_addresses[0] for h in snapshot.hosts if h.ip_addresses]
        features["src_ip_entropy"] = compute_ip_entropy(src_ips) if src_ips else 0.0
        features["dst_ip_entropy"] = compute_ip_entropy(dst_ips) if dst_ips else 0.0

        # Simplified port entropy placeholder
        # Full implementation would parse flows for actual port distributions
        features["src_port_entropy"] = 0.0
        features["dst_port_entropy"] = 0.0

        # Protocol entropy placeholder
        features["protocol_entropy"] = 0.0

        # Feature 16: Flow table utilization (device-level)
        device_id = port_key.split(":")[0]
        device_flows = [f for f in snapshot.flows if f.device_id == device_id]
        # Assume typical switch has ~1000 flow table entries
        FLOW_TABLE_CAPACITY = 1000
        features["flow_table_utilization"] = len(device_flows) / FLOW_TABLE_CAPACITY

        return features

    def extract_host_features(
        self, host_id: str, snapshot: TelemetrySnapshot
    ) -> dict[str, float]:
        """Extract features for a single host.

        Simplified feature set focusing on host-level patterns.

        Args:
            host_id: Host identifier (IP or MAC)
            snapshot: Full telemetry snapshot

        Returns:
            Dictionary of feature values
        """
        features: dict[str, float] = {}

        # Count flows involving this host
        host_flows = [
            f
            for f in snapshot.flows
            if host_id in str(f.selector)  # Simplified matching
        ]
        features["flow_count"] = float(len(host_flows))

        # Aggregate traffic from flows
        total_packets = sum(f.packets for f in host_flows)
        total_bytes = sum(f.bytes for f in host_flows)

        features["total_packets"] = float(total_packets)
        features["total_bytes"] = float(total_bytes)
        features["avg_packet_size"] = total_bytes / total_packets if total_packets > 0 else 0.0

        return features

    def extract_device_features(
        self, device_id: str, snapshot: TelemetrySnapshot
    ) -> dict[str, float]:
        """Extract features for a single device (switch).

        Device-level features for control-plane and flow-table attacks.

        Args:
            device_id: Device identifier
            snapshot: Full telemetry snapshot

        Returns:
            Dictionary of feature values
        """
        features: dict[str, float] = {}

        # Flow table metrics
        device_flows = [f for f in snapshot.flows if f.device_id == device_id]
        features["flow_count"] = float(len(device_flows))

        FLOW_TABLE_CAPACITY = 1000
        features["flow_table_utilization"] = len(device_flows) / FLOW_TABLE_CAPACITY

        # Count pending flows (control-plane load indicator)
        pending_flows = [f for f in device_flows if f.state == "PENDING_ADD"]
        features["pending_flow_count"] = float(len(pending_flows))

        # Port-level aggregation
        device_port_stats = [s for s in snapshot.port_stats if s.device_id == device_id]
        total_packets_rx = sum(s.packets_received for s in device_port_stats)
        total_drops = sum(s.packets_rx_dropped for s in device_port_stats)

        features["total_packets_rx"] = float(total_packets_rx)
        features["total_drops"] = float(total_drops)
        features["drop_ratio"] = total_drops / total_packets_rx if total_packets_rx > 0 else 0.0

        return features

    def extract_topology_features(self, snapshot: TelemetrySnapshot) -> dict[str, float]:
        """Extract topology-level features.

        Global network health indicators.

        Args:
            snapshot: Full telemetry snapshot

        Returns:
            Dictionary of feature values
        """
        features: dict[str, float] = {}

        features["device_count"] = float(len(snapshot.devices))
        features["host_count"] = float(len(snapshot.hosts))
        features["link_count"] = float(len(snapshot.links))

        # Link health
        active_links = [link for link in snapshot.links if link.state == "ACTIVE"]
        features["active_link_count"] = float(len(active_links))
        features["link_health_ratio"] = (
            len(active_links) / len(snapshot.links) if snapshot.links else 1.0
        )

        # Device availability
        available_devices = [d for d in snapshot.devices if d.available]
        features["available_device_count"] = float(len(available_devices))
        features["device_availability_ratio"] = (
            len(available_devices) / len(snapshot.devices) if snapshot.devices else 1.0
        )

        return features
