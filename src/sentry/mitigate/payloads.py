"""OpenFlow payload construction for mitigation actions.

Builds ONOS-compatible OpenFlow rule payloads for each mitigation stage.
All rules use isPermanent=false (NFR-1: fail-open safety) with hard timeouts.

Stages:
  0 = Observe (no action, just log)
  1 = Throttle (rate-limit via meter)
  2 = Selective Drop (drop matching flows)
  3 = Quarantine (redirect to quarantine VLAN/port)
  4 = Port Isolation (disable port entirely)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Default TTLs per stage (seconds)
STAGE_TTLS = {
    0: 0,      # Observe: no rule installed
    1: 30,     # Throttle: 30s
    2: 60,     # Selective Drop: 60s
    3: 120,    # Quarantine: 120s
    4: 300,    # Port Isolation: 300s (5 min)
}

# Stage names
STAGE_NAMES = {
    0: "observe",
    1: "throttle",
    2: "selective_drop",
    3: "quarantine",
    4: "port_isolation",
}


def build_observe_payload(
    device_id: str,
    subject_id: str,
    threat_type: str,
) -> dict[str, Any]:
    """Stage 0: Observe — no OpenFlow rule, just logging.

    Returns an empty payload (no action taken).
    """
    return {
        "stage": 0,
        "stage_name": "observe",
        "action": "none",
        "device_id": device_id,
        "subject_id": subject_id,
        "threat_type": threat_type,
    }


def build_throttle_payload(
    device_id: str,
    subject_id: str,
    threat_type: str,
    rate_kbps: int = 1000,
    burst_kbps: int = 1200,
) -> dict[str, Any]:
    """Stage 1: Throttle — rate-limit traffic via meter band.

    Args:
        device_id: Target switch
        subject_id: IP or port to throttle
        threat_type: Type of threat detected
        rate_kbps: Rate limit in kbps
        burst_kbps: Burst size in kbps
    """
    return {
        "stage": 1,
        "stage_name": "throttle",
        "action": "install_meter",
        "device_id": device_id,
        "subject_id": subject_id,
        "threat_type": threat_type,
        "isPermanent": False,
        "timeout": STAGE_TTLS[1],
        "meter": {
            "meterId": 1,
            "bands": [
                {
                    "type": "DROP",
                    "rate": rate_kbps,
                    "burstSize": burst_kbps,
                }
            ],
        },
        "flow_rule": {
            "priority": 30000,
            "timeout": STAGE_TTLS[1],
            "isPermanent": False,
            "treatment": {
                "instructions": [
                    {"type": "METER", "meterId": 1},
                    {"type": "OUTPUT", "port": "NORMAL"},
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "IP_SRC", "ip": subject_id},
                ]
            },
        },
    }


def build_selective_drop_payload(
    device_id: str,
    subject_id: str,
    threat_type: str,
    protocol: str = "tcp",
    dst_port: int | None = None,
) -> dict[str, Any]:
    """Stage 2: Selective Drop — drop matching packets.

    Args:
        device_id: Target switch
        subject_id: Source IP to block
        threat_type: Type of threat detected
        protocol: Protocol to match (tcp, udp, icmp)
        dst_port: Optional destination port to match
    """
    criteria: list[dict[str, Any]] = [
        {"type": "IP_SRC", "ip": subject_id},
    ]

    if protocol:
        proto_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(protocol, 0)
        if proto_num:
            criteria.append({"type": "IP_PROTO", "protocol": proto_num})

    if dst_port is not None:
        criteria.append({"type": "TCP_DST", "tcpPort": dst_port})

    return {
        "stage": 2,
        "stage_name": "selective_drop",
        "action": "install_flow",
        "device_id": device_id,
        "subject_id": subject_id,
        "threat_type": threat_type,
        "isPermanent": False,
        "timeout": STAGE_TTLS[2],
        "flow_rule": {
            "priority": 40000,
            "timeout": STAGE_TTLS[2],
            "isPermanent": False,
            "treatment": {
                "instructions": [
                    {"type": "DROP"}
                ]
            },
            "selector": {
                "criteria": criteria,
            },
        },
    }


def build_quarantine_payload(
    device_id: str,
    subject_id: str,
    threat_type: str,
    quarantine_port: str = "9999",
) -> dict[str, Any]:
    """Stage 3: Quarantine — redirect traffic to quarantine port/VLAN.

    Args:
        device_id: Target switch
        subject_id: Host IP to quarantine
        threat_type: Type of threat detected
        quarantine_port: Port number for quarantine sink
    """
    return {
        "stage": 3,
        "stage_name": "quarantine",
        "action": "install_flow",
        "device_id": device_id,
        "subject_id": subject_id,
        "threat_type": threat_type,
        "isPermanent": False,
        "timeout": STAGE_TTLS[3],
        "flow_rule": {
            "priority": 50000,
            "timeout": STAGE_TTLS[3],
            "isPermanent": False,
            "treatment": {
                "instructions": [
                    {"type": "OUTPUT", "port": quarantine_port},
                ]
            },
            "selector": {
                "criteria": [
                    {"type": "IP_SRC", "ip": subject_id},
                ]
            },
        },
    }


def build_port_isolation_payload(
    device_id: str,
    subject_id: str,
    threat_type: str,
    port_number: str = "1",
) -> dict[str, Any]:
    """Stage 4: Port Isolation — disable port entirely.

    Args:
        device_id: Target switch
        subject_id: Subject being isolated
        threat_type: Type of threat detected
        port_number: Port to disable
    """
    return {
        "stage": 4,
        "stage_name": "port_isolation",
        "action": "disable_port",
        "device_id": device_id,
        "subject_id": subject_id,
        "threat_type": threat_type,
        "isPermanent": False,
        "timeout": STAGE_TTLS[4],
        "port_mod": {
            "portNumber": port_number,
            "isEnabled": False,
        },
    }


# Payload builder dispatch (heterogeneous signatures — called dynamically)
PAYLOAD_BUILDERS: dict[int, Callable[..., dict[str, Any]]] = {
    0: build_observe_payload,
    1: build_throttle_payload,
    2: build_selective_drop_payload,
    3: build_quarantine_payload,
    4: build_port_isolation_payload,
}


def build_payload(
    stage: int,
    device_id: str,
    subject_id: str,
    threat_type: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build payload for a given mitigation stage.

    Args:
        stage: Mitigation stage (0-4)
        device_id: Target switch
        subject_id: Subject identifier
        threat_type: Type of threat
        **kwargs: Additional stage-specific parameters

    Returns:
        OpenFlow payload dict

    Raises:
        ValueError: If stage is out of range
    """
    if stage not in PAYLOAD_BUILDERS:
        raise ValueError(f"Invalid stage: {stage}. Must be 0-4.")

    builder = PAYLOAD_BUILDERS[stage]
    if stage == 0:
        return builder(device_id, subject_id, threat_type)
    return builder(device_id, subject_id, threat_type, **kwargs)
