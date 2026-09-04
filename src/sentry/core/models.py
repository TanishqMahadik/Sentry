"""Core data models for Sentry telemetry, network topology, and threat tracking.

Uses dataclasses with type hints for clean, type-safe data structures.
All models are stdlib-only (NFR-3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Device:
    """SDN switch/device in the network topology."""

    device_id: str
    available: bool
    role: str  # "MASTER", "STANDBY", "NONE"
    type: str  # e.g., "SWITCH"
    manufacturer: str = ""
    hw_version: str = ""
    sw_version: str = ""
    serial_number: str = ""
    chassis_id: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class Port:
    """Port on a device."""

    port_number: str
    is_enabled: bool
    type: str  # "copper", "fiber", etc.
    port_speed: int = 0  # Mbps


@dataclass
class Host:
    """End host connected to the network."""

    host_id: str
    mac: str
    vlan: str
    inner_vlan: str = ""
    outer_tpid: str = ""
    configured: bool = False
    suspended: bool = False
    ip_addresses: list[str] = field(default_factory=list)
    locations: list[dict[str, Any]] = field(default_factory=list)  # elementId, port


@dataclass
class Link:
    """Link between two network elements (device-to-device or device-to-host)."""

    src_device: str
    src_port: str
    dst_device: str
    dst_port: str
    link_type: str  # "DIRECT", "INDIRECT", "EDGE"
    state: str  # "ACTIVE", "INACTIVE"
    is_durable: bool = False


@dataclass
class Flow:
    """OpenFlow flow entry installed on a device."""

    flow_id: str
    device_id: str
    table_id: int
    app_id: str
    priority: int
    timeout: int
    is_permanent: bool
    state: str  # "ADDED", "PENDING_ADD", "PENDING_REMOVE", "REMOVED"
    life_secs: int = 0
    packets: int = 0
    bytes: int = 0
    selector: dict[str, Any] = field(default_factory=dict)  # match criteria
    treatment: dict[str, Any] = field(default_factory=dict)  # actions


@dataclass
class PortStats:
    """Port-level statistics from a device."""

    device_id: str
    port_number: str
    timestamp: int  # Unix epoch seconds
    packets_received: int = 0
    packets_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    packets_rx_dropped: int = 0
    packets_tx_dropped: int = 0
    packets_rx_errors: int = 0
    packets_tx_errors: int = 0
    duration_sec: int = 0


@dataclass
class FlowStats:
    """Flow-level statistics."""

    device_id: str
    flow_id: str
    table_id: int
    packets: int
    bytes: int
    life_secs: int
    timestamp: int  # Unix epoch seconds


@dataclass
class TelemetrySnapshot:
    """Complete network telemetry snapshot at a point in time."""

    timestamp: int  # Unix epoch seconds
    devices: list[Device] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    port_stats: list[PortStats] = field(default_factory=list)
    flow_stats: list[FlowStats] = field(default_factory=list)


@dataclass
class ThreatVerdict:
    """Threat detection result from a detector."""

    threat_type: str  # "syn_flood", "udp_flood", etc.
    subject_id: str  # host IP, device ID, or port identifier
    severity: str  # "low", "medium", "high", "critical"
    confidence: float  # 0.0 to 1.0
    timestamp: int  # Unix epoch seconds
    evidence: dict[str, Any] = field(default_factory=dict)  # feature vectors, thresholds
    message: str = ""


@dataclass
class MitigationAction:
    """Mitigation action applied to the data plane."""

    action_id: str
    threat_verdict: ThreatVerdict
    stage: int  # 0=Observe, 1=Throttle, 2=Drop, 3=Quarantine, 4=Isolate
    action_type: str  # "meter", "flow_rule", "port_disable"
    device_id: str
    payload: dict[str, Any]  # OpenFlow payload sent to ONOS
    applied_at: int  # Unix epoch seconds
    expires_at: int  # Unix epoch seconds (TTL)
    status: str = "pending"  # "pending", "applied", "expired", "revoked"


@dataclass
class BaselineWindow:
    """Statistical baseline for a subject (host, port, flow)."""

    subject_id: str
    metric_name: str
    ewma_mean: float  # Exponentially weighted moving average
    mad_deviation: float  # Median absolute deviation
    sample_count: int
    last_updated: int  # Unix epoch seconds
    frozen: bool = False  # Frozen during active mitigations (Invariant I9)
