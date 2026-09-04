"""ONOS REST API client.

Wraps ONOS REST endpoints and returns parsed model instances.
Uses HttpTransport abstraction for testability.
"""

from __future__ import annotations

import time
from typing import Any

from sentry.core.models import (
    Device,
    Flow,
    FlowStats,
    Host,
    Link,
    Port,
    PortStats,
    TelemetrySnapshot,
)
from sentry.onos.transport import HttpTransport


class OnosClient:
    """Client for ONOS REST API."""

    def __init__(self, transport: HttpTransport) -> None:
        """Initialize ONOS client with a transport layer.

        Args:
            transport: HttpTransport implementation (real or mock)
        """
        self.transport = transport

    def get_devices(self) -> list[Device]:
        """Fetch all devices from ONOS."""
        response = self.transport.get("/devices")
        devices_data = response.get("devices", [])

        devices = []
        for d in devices_data:
            devices.append(
                Device(
                    device_id=d.get("id", ""),
                    available=d.get("available", False),
                    role=d.get("role", "NONE"),
                    type=d.get("type", "SWITCH"),
                    manufacturer=d.get("mfr", ""),
                    hw_version=d.get("hw", ""),
                    sw_version=d.get("sw", ""),
                    serial_number=d.get("serial", ""),
                    chassis_id=d.get("chassisId", ""),
                    annotations=d.get("annotations", {}),
                )
            )
        return devices

    def get_hosts(self) -> list[Host]:
        """Fetch all hosts from ONOS."""
        response = self.transport.get("/hosts")
        hosts_data = response.get("hosts", [])

        hosts = []
        for h in hosts_data:
            hosts.append(
                Host(
                    host_id=h.get("id", ""),
                    mac=h.get("mac", ""),
                    vlan=h.get("vlan", ""),
                    inner_vlan=h.get("innerVlan", ""),
                    outer_tpid=h.get("outerTpid", ""),
                    configured=h.get("configured", False),
                    suspended=h.get("suspended", False),
                    ip_addresses=h.get("ipAddresses", []),
                    locations=h.get("locations", []),
                )
            )
        return hosts

    def get_links(self) -> list[Link]:
        """Fetch all links from ONOS."""
        response = self.transport.get("/links")
        links_data = response.get("links", [])

        links = []
        for link in links_data:
            src = link.get("src", {})
            dst = link.get("dst", {})
            links.append(
                Link(
                    src_device=src.get("device", ""),
                    src_port=src.get("port", ""),
                    dst_device=dst.get("device", ""),
                    dst_port=dst.get("port", ""),
                    link_type=link.get("type", "DIRECT"),
                    state=link.get("state", "ACTIVE"),
                    is_durable=link.get("durable", False),
                )
            )
        return links

    def get_flows(self, device_id: str | None = None) -> list[Flow]:
        """Fetch flows from ONOS.

        Args:
            device_id: Optional device ID to filter flows for a specific device
        """
        if device_id:
            url = f"/flows/{device_id}"
        else:
            url = "/flows"

        response = self.transport.get(url)
        flows_data = response.get("flows", [])

        flows = []
        for f in flows_data:
            flows.append(
                Flow(
                    flow_id=f.get("id", ""),
                    device_id=f.get("deviceId", ""),
                    table_id=f.get("tableId", 0),
                    app_id=f.get("appId", ""),
                    priority=f.get("priority", 0),
                    timeout=f.get("timeout", 0),
                    is_permanent=f.get("isPermanent", False),
                    state=f.get("state", "ADDED"),
                    life_secs=f.get("life", 0),
                    packets=f.get("packets", 0),
                    bytes=f.get("bytes", 0),
                    selector=f.get("selector", {}),
                    treatment=f.get("treatment", {}),
                )
            )
        return flows

    def get_port_statistics(self, device_id: str | None = None) -> list[PortStats]:
        """Fetch port statistics from ONOS.

        Args:
            device_id: Optional device ID to filter stats
        """
        if device_id:
            url = f"/statistics/ports/{device_id}"
        else:
            url = "/statistics/ports"

        response = self.transport.get(url)
        stats_data = response.get("statistics", [])

        timestamp = int(time.time())
        stats = []

        for stat in stats_data:
            stats.append(
                PortStats(
                    device_id=stat.get("deviceId", device_id or ""),
                    port_number=str(stat.get("port", "")),
                    timestamp=timestamp,
                    packets_received=stat.get("packetsReceived", 0),
                    packets_sent=stat.get("packetsSent", 0),
                    bytes_received=stat.get("bytesReceived", 0),
                    bytes_sent=stat.get("bytesSent", 0),
                    packets_rx_dropped=stat.get("packetsRxDropped", 0),
                    packets_tx_dropped=stat.get("packetsTxDropped", 0),
                    packets_rx_errors=stat.get("packetsRxErrors", 0),
                    packets_tx_errors=stat.get("packetsTxErrors", 0),
                    duration_sec=stat.get("durationSec", 0),
                )
            )
        return stats

    def get_flow_statistics(self, device_id: str | None = None) -> list[FlowStats]:
        """Fetch flow statistics from ONOS.

        Args:
            device_id: Optional device ID to filter stats
        """
        if device_id:
            url = f"/statistics/flows/{device_id}"
        else:
            url = "/statistics/flows"

        response = self.transport.get(url)
        stats_data = response.get("statistics", [])

        timestamp = int(time.time())
        stats = []

        for stat in stats_data:
            stats.append(
                FlowStats(
                    device_id=stat.get("deviceId", device_id or ""),
                    flow_id=stat.get("flowId", ""),
                    table_id=stat.get("tableId", 0),
                    packets=stat.get("packets", 0),
                    bytes=stat.get("bytes", 0),
                    life_secs=stat.get("life", 0),
                    timestamp=timestamp,
                )
            )
        return stats

    def get_telemetry_snapshot(self) -> TelemetrySnapshot:
        """Fetch complete telemetry snapshot from ONOS.

        Collects devices, hosts, links, flows, port stats, and flow stats.
        """
        timestamp = int(time.time())

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=self.get_devices(),
            hosts=self.get_hosts(),
            links=self.get_links(),
            flows=self.get_flows(),
            port_stats=self.get_port_statistics(),
            flow_stats=self.get_flow_statistics(),
        )

    def install_flow(self, device_id: str, flow_rule: dict[str, Any]) -> dict[str, Any]:
        """Install a flow rule on a device.

        Args:
            device_id: Target device ID
            flow_rule: Flow rule payload (selector, treatment, priority, timeout)

        Returns:
            Response from ONOS
        """
        url = f"/flows/{device_id}"
        return self.transport.post(url, flow_rule)

    def remove_flow(self, device_id: str, flow_id: str) -> dict[str, Any]:
        """Remove a flow rule from a device.

        Args:
            device_id: Device ID
            flow_id: Flow ID to remove

        Returns:
            Response from ONOS
        """
        url = f"/flows/{device_id}/{flow_id}"
        return self.transport.delete(url)
