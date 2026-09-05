"""Threat detection rules for 8 attack vectors.

Each rule implements a threshold-based or entropy-based detector
that consumes normalized telemetry metrics and produces ThreatVerdicts.

Rules:
  - SynFloodRule, UdpFloodRule, IcmpFloodRule: pps_rx threshold
  - PortScanRule: flow count + IP entropy
  - FlowTableExhaustionRule: flow count per device
  - ArpSpoofRule: ARP protocol entropy drop
  - CpSaturationRule: control-plane metric threshold
  - TopologyPoisoningRule: link state anomaly (alert-only)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sentry.core.models import ThreatVerdict

logger = logging.getLogger(__name__)

# Severity mapping based on confidence thresholds
_SEVERITY_LEVELS = [
    (0.8, "critical"),
    (0.6, "high"),
    (0.4, "medium"),
    (0.0, "low"),
]


def _severity_from_confidence(confidence: float) -> str:
    """Map confidence score to severity string."""
    for threshold, severity in _SEVERITY_LEVELS:
        if confidence >= threshold:
            return severity
    return "low"


class DetectionRule:
    """Base class for threat detection rules."""

    name: str = "base"
    threat_type: str = "unknown"
    description: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize rule with optional config overrides.

        Args:
            config: Optional dict of threshold overrides
        """
        self.config = config or {}

    def _make_verdict(
        self,
        subject_id: str,
        confidence: float,
        evidence: dict[str, Any],
    ) -> ThreatVerdict:
        """Create a ThreatVerdict with severity and timestamp auto-filled."""
        return ThreatVerdict(
            threat_type=self.threat_type,
            subject_id=subject_id,
            severity=_severity_from_confidence(confidence),
            confidence=confidence,
            timestamp=int(time.time()),
            evidence=evidence,
        )

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        """Evaluate detection rule against current metrics.

        Args:
            port_metrics: Per-port normalized rates from normalizer
            flow_metrics: Flow-level stats (count, entropy, etc.)
            baseline_metrics: Per-subject baseline (mean, mad) tuples

        Returns:
            ThreatVerdict if threat detected, None otherwise
        """
        raise NotImplementedError


class SynFloodRule(DetectionRule):
    """SYN flood detection: high pps_rx with low pps_tx ratio."""

    name = "syn_flood"
    threat_type = "SYN_FLOOD"
    description = "SYN flood detected: asymmetric high packet rate"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.pps_rx_threshold = self.config.get("pps_rx_threshold", 1000)
        self.tx_rx_ratio_max = self.config.get("tx_rx_ratio_max", 0.3)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        for port_key, metrics in port_metrics.items():
            pps_rx = metrics.get("pps_rx", 0)
            pps_tx = metrics.get("pps_tx", 0)

            if pps_rx < self.pps_rx_threshold:
                continue

            # Check asymmetry: SYN flood has low response rate
            ratio = pps_tx / pps_rx if pps_rx > 0 else 1.0
            if ratio <= self.tx_rx_ratio_max:
                confidence = min(1.0, pps_rx / (self.pps_rx_threshold * 5))
                return self._make_verdict(
                    port_key, confidence, {"pps_rx": pps_rx, "pps_tx": pps_tx, "tx_rx_ratio": ratio}
                )

        # Also check MAD-based anomaly from baselines
        for subject_id, bl in baseline_metrics.items():
            if "pps_rx" in bl:
                mean, mad = bl["pps_rx"]
                if mad > 0 and subject_id in port_metrics:
                    pps_rx = port_metrics[subject_id].get("pps_rx", 0)
                    deviation = abs(pps_rx - mean) / mad
                    if deviation > 3.0 and pps_rx > self.pps_rx_threshold:
                        return self._make_verdict(
                            subject_id,
                            min(1.0, deviation / 10.0),
                            {"pps_rx": pps_rx, "baseline_mean": mean, "mad_score": deviation},
                        )

        return None


class UdpFloodRule(DetectionRule):
    """UDP flood detection: very high pps_rx."""

    name = "udp_flood"
    threat_type = "UDP_FLOOD"
    description = "UDP flood detected: excessive packet rate"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.pps_rx_threshold = self.config.get("pps_rx_threshold", 2000)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        for port_key, metrics in port_metrics.items():
            pps_rx = metrics.get("pps_rx", 0)
            if pps_rx >= self.pps_rx_threshold:
                confidence = min(1.0, pps_rx / (self.pps_rx_threshold * 5))
                return self._make_verdict(port_key, confidence, {"pps_rx": pps_rx})

        for subject_id, bl in baseline_metrics.items():
            if "pps_rx" in bl:
                mean, mad = bl["pps_rx"]
                if mad > 0 and subject_id in port_metrics:
                    pps_rx = port_metrics[subject_id].get("pps_rx", 0)
                    deviation = abs(pps_rx - mean) / mad
                    if deviation > 3.0 and pps_rx > self.pps_rx_threshold:
                        return self._make_verdict(
                            subject_id,
                            min(1.0, deviation / 10.0),
                            {"pps_rx": pps_rx, "baseline_mean": mean, "mad_score": deviation},
                        )

        return None


class IcmpFloodRule(DetectionRule):
    """ICMP flood detection: high pps_rx with symmetric tx (echo replies)."""

    name = "icmp_flood"
    threat_type = "ICMP_FLOOD"
    description = "ICMP flood detected: excessive ICMP packet rate"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.pps_rx_threshold = self.config.get("pps_rx_threshold", 500)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        for port_key, metrics in port_metrics.items():
            pps_rx = metrics.get("pps_rx", 0)
            if pps_rx >= self.pps_rx_threshold:
                confidence = min(1.0, pps_rx / (self.pps_rx_threshold * 5))
                return self._make_verdict(port_key, confidence, {"pps_rx": pps_rx})

        for subject_id, bl in baseline_metrics.items():
            if "pps_rx" in bl:
                mean, mad = bl["pps_rx"]
                if mad > 0 and subject_id in port_metrics:
                    pps_rx = port_metrics[subject_id].get("pps_rx", 0)
                    deviation = abs(pps_rx - mean) / mad
                    if deviation > 3.0 and pps_rx > self.pps_rx_threshold:
                        return self._make_verdict(
                            subject_id,
                            min(1.0, deviation / 10.0),
                            {"pps_rx": pps_rx, "baseline_mean": mean, "mad_score": deviation},
                        )

        return None


class PortScanRule(DetectionRule):
    """Port scan detection: many unique flows + low per-flow packet count."""

    name = "port_scan"
    threat_type = "PORT_SCAN"
    description = "Port scan detected: many short-lived flows to unique ports"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.flow_count_threshold = self.config.get("flow_count_threshold", 20)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        flow_count = flow_metrics.get("flow_count", 0)
        unique_ports = flow_metrics.get("unique_dst_ports", 0)
        avg_packets_per_flow = flow_metrics.get("avg_packets_per_flow", 0)

        if flow_count >= self.flow_count_threshold and unique_ports >= 10:
            # Port scan: many flows, many unique ports, low packets per flow
            if avg_packets_per_flow < 20:
                confidence = min(1.0, flow_count / (self.flow_count_threshold * 3))
                return self._make_verdict(
                    flow_metrics.get("subject_id", "unknown"),
                    confidence,
                    {
                        "flow_count": flow_count,
                        "unique_ports": unique_ports,
                        "avg_packets_per_flow": avg_packets_per_flow,
                    },
                )

        # MAD-based flow count anomaly
        for subject_id, bl in baseline_metrics.items():
            if "flow_count" in bl:
                mean, mad = bl["flow_count"]
                if mad > 0:
                    deviation = abs(flow_count - mean) / mad
                    if deviation > 3.0 and flow_count >= self.flow_count_threshold:
                        return self._make_verdict(
                            subject_id,
                            min(1.0, deviation / 10.0),
                            {
                                "flow_count": flow_count,
                                "baseline_mean": mean,
                                "mad_score": deviation,
                            },
                        )

        return None


class FlowTableExhaustionRule(DetectionRule):
    """Flow table exhaustion: excessive flows per device."""

    name = "flow_table_exhaustion"
    threat_type = "FLOW_TABLE_EXHAUSTION"
    description = "Flow table exhaustion: device flow count near capacity"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.flow_count_threshold = self.config.get("flow_count_threshold", 500)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        flow_count = flow_metrics.get("flow_count", 0)

        if flow_count >= self.flow_count_threshold:
            confidence = min(1.0, flow_count / (self.flow_count_threshold * 2))
            return self._make_verdict(
                flow_metrics.get("subject_id", "unknown"),
                confidence,
                {"flow_count": flow_count, "threshold": self.flow_count_threshold},
            )

        # MAD-based detection
        for subject_id, bl in baseline_metrics.items():
            if "flow_count" in bl:
                mean, mad = bl["flow_count"]
                if mad > 0:
                    deviation = abs(flow_count - mean) / mad
                    if deviation > 3.0 and flow_count >= self.flow_count_threshold:
                        return self._make_verdict(
                            subject_id,
                            min(1.0, deviation / 10.0),
                            {
                                "flow_count": flow_count,
                                "baseline_mean": mean,
                                "mad_score": deviation,
                            },
                        )

        return None


class ArpSpoofRule(DetectionRule):
    """ARP spoofing detection: entropy drop in ARP traffic + duplicate MACs."""

    name = "arp_spoofing"
    threat_type = "ARP_SPOOFING"
    description = "ARP spoofing detected: low ARP entropy or duplicate MACs"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.entropy_threshold = self.config.get("entropy_threshold", 0.3)
        self.duplicate_mac_threshold = self.config.get("duplicate_mac_threshold", 2)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        arp_entropy = flow_metrics.get("arp_entropy", 1.0)
        duplicate_macs = flow_metrics.get("duplicate_macs", 0)

        if arp_entropy < self.entropy_threshold or duplicate_macs >= self.duplicate_mac_threshold:
            confidence = max(1.0 - arp_entropy, duplicate_macs / 10.0)
            return self._make_verdict(
                flow_metrics.get("subject_id", "unknown"),
                min(1.0, confidence),
                {"arp_entropy": arp_entropy, "duplicate_macs": duplicate_macs},
            )

        return None


class CpSaturationRule(DetectionRule):
    """Control-plane saturation: high CPU/control-plane utilization."""

    name = "cp_saturation"
    threat_type = "CP_SATURATION"
    description = "Control-plane saturation detected"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.cpu_threshold = self.config.get("cpu_threshold", 0.85)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        cpu_util = flow_metrics.get("cpu_utilization", 0.0)

        if cpu_util >= self.cpu_threshold:
            confidence = min(1.0, (cpu_util - self.cpu_threshold) / (1.0 - self.cpu_threshold))
            return self._make_verdict(
                flow_metrics.get("subject_id", "unknown"),
                confidence,
                {"cpu_utilization": cpu_util, "threshold": self.cpu_threshold},
            )

        return None


class TopologyPoisoningRule(DetectionRule):
    """Topology poisoning detection: unexpected link state changes.

    ALERT-ONLY per FR-1: must never reach Planner/Executor for mitigation.
    """

    name = "topology_poisoning"
    threat_type = "TOPOLOGY_POISONING"
    description = "Topology poisoning detected (alert-only, no automated mitigation)"
    alert_only = True

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.link_flap_threshold = self.config.get("link_flap_threshold", 3)

    def evaluate(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> ThreatVerdict | None:
        link_flaps = flow_metrics.get("link_flap_count", 0)

        if link_flaps >= self.link_flap_threshold:
            confidence = min(1.0, link_flaps / (self.link_flap_threshold * 3))
            return self._make_verdict(
                flow_metrics.get("subject_id", "unknown"),
                confidence,
                {"link_flap_count": link_flaps, "alert_only": True},
            )

        return None


# Rule registry — ordered by evaluation priority
RULES: list[type[DetectionRule]] = [
    SynFloodRule,
    UdpFloodRule,
    IcmpFloodRule,
    PortScanRule,
    FlowTableExhaustionRule,
    ArpSpoofRule,
    CpSaturationRule,
    TopologyPoisoningRule,
]
