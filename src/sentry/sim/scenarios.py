"""Synthetic telemetry scenario generators for offline testing.

Generates realistic telemetry patterns for benign traffic and 8 attack vectors.
Used by replay harness to test detection without requiring live ONOS/Docker/root.
"""

from __future__ import annotations

import random
import time

from sentry.core.models import (
    Device,
    Flow,
    Host,
    Link,
    PortStats,
    TelemetrySnapshot,
)


class ScenarioGenerator:
    """Base class for telemetry scenario generators."""

    def __init__(self, seed: int = 42) -> None:
        """Initialize scenario generator.

        Args:
            seed: Random seed for reproducible scenarios
        """
        random.seed(seed)
        self.start_time = int(time.time())
        self.tick = 0

    def generate_snapshot(self) -> TelemetrySnapshot:
        """Generate one telemetry snapshot.

        Returns:
            TelemetrySnapshot for current tick
        """
        raise NotImplementedError

    def advance_tick(self) -> None:
        """Advance to next time window."""
        self.tick += 1


class BenignTraffic(ScenarioGenerator):
    """Benign baseline traffic scenario."""

    def generate_snapshot(self) -> TelemetrySnapshot:
        """Generate benign traffic snapshot."""
        timestamp = self.start_time + self.tick

        # Simple 2-switch, 2-host topology
        devices = [
            Device(device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"),
            Device(device_id="of:0000000000000002", available=True, role="MASTER", type="SWITCH"),
        ]

        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            ),
            Host(
                host_id="00:00:00:00:00:02/-1", mac="00:00:00:00:00:02", vlan="-1",
                ip_addresses=["10.0.0.2"]
            ),
        ]

        links = [
            Link(
                src_device="of:0000000000000001", src_port="2",
                dst_device="of:0000000000000002", dst_port="1",
                link_type="DIRECT", state="ACTIVE"
            ),
        ]

        # Normal traffic: 100-200 pps, stable
        base_packets = 1000 + self.tick * 150
        base_bytes = base_packets * 1500  # Typical Ethernet frame

        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=base_packets + random.randint(-10, 10),
                packets_sent=base_packets - 50,
                bytes_received=base_bytes + random.randint(-1000, 1000),
                bytes_sent=base_bytes - 5000,
            ),
        ]

        flows = [
            Flow(
                flow_id="flow1",
                device_id="of:0000000000000001",
                table_id=0,
                app_id="org.onosproject.core",
                priority=100,
                timeout=60,
                is_permanent=False,
                state="ADDED",
                packets=base_packets,
                bytes=base_bytes,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=links,
            flows=flows,
            port_stats=port_stats,
        )


class SynFloodAttack(ScenarioGenerator):
    """SYN flood attack scenario."""

    def __init__(self, seed: int = 42) -> None:
        super().__init__(seed)
        self.cumulative_packets = 1000

    def generate_snapshot(self) -> TelemetrySnapshot:
        """Generate SYN flood telemetry."""
        timestamp = self.start_time + self.tick

        devices = [
            Device(
                device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"
            )
        ]
        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            ),
            Host(
                host_id="00:00:00:00:00:99/-1", mac="00:00:00:00:00:99", vlan="-1",
                ip_addresses=["10.0.0.99"]
            ),
        ]

        # Attack starts at tick 3
        if self.tick < 3:
            pps = 100
        else:
            # SYN flood: spike to 2000+ pps
            pps = 2000

        # Accumulate packets (monotonic counter)
        self.cumulative_packets += pps
        base_bytes = self.cumulative_packets * 64  # Small SYN packets

        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=self.cumulative_packets,
                packets_sent=self.cumulative_packets // 10,  # Asymmetric: victim can't respond
                bytes_received=base_bytes,
                bytes_sent=base_bytes // 10,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=[],
            flows=[],
            port_stats=port_stats,
        )


class UdpFloodAttack(ScenarioGenerator):
    """UDP flood attack scenario."""

    def __init__(self, seed: int = 42) -> None:
        super().__init__(seed)
        self.cumulative_packets = 1000

    def generate_snapshot(self) -> TelemetrySnapshot:
        timestamp = self.start_time + self.tick
        devices = [
            Device(
                device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"
            )
        ]
        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            )
        ]

        if self.tick < 3:
            pps = 100
        else:
            pps = 3000  # High UDP packet rate

        self.cumulative_packets += pps
        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=self.cumulative_packets,
                packets_sent=self.cumulative_packets // 20,
                bytes_received=self.cumulative_packets * 512,
                bytes_sent=self.cumulative_packets * 20,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=[],
            flows=[],
            port_stats=port_stats,
        )


class IcmpFloodAttack(ScenarioGenerator):
    """ICMP flood attack scenario."""

    def __init__(self, seed: int = 42) -> None:
        super().__init__(seed)
        self.cumulative_packets = 500

    def generate_snapshot(self) -> TelemetrySnapshot:
        timestamp = self.start_time + self.tick
        devices = [
            Device(
                device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"
            )
        ]
        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            )
        ]

        if self.tick < 3:
            pps = 50
        else:
            pps = 1000  # ICMP flood

        self.cumulative_packets += pps
        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=self.cumulative_packets,
                packets_sent=self.cumulative_packets,  # Echo replies
                bytes_received=self.cumulative_packets * 64,
                bytes_sent=self.cumulative_packets * 64,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=[],
            flows=[],
            port_stats=port_stats,
        )


class PortScanAttack(ScenarioGenerator):
    """Port scan attack scenario."""

    def __init__(self, seed: int = 42) -> None:
        super().__init__(seed)
        self.cumulative_packets = 1000

    def generate_snapshot(self) -> TelemetrySnapshot:
        timestamp = self.start_time + self.tick
        devices = [
            Device(
                device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"
            )
        ]
        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            )
        ]

        # Port scan: many flows to different ports
        flows = []
        if self.tick >= 3:
            for port in range(1, 30):  # 30 unique destination ports
                flows.append(
                    Flow(
                        flow_id=f"scan_flow_{port}",
                        device_id="of:0000000000000001",
                        table_id=0,
                        app_id="org.onosproject.core",
                        priority=100,
                        timeout=10,
                        is_permanent=False,
                        state="ADDED",
                        packets=5,
                        bytes=320,
                    )
                )

        self.cumulative_packets += 150
        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=self.cumulative_packets,
                packets_sent=self.cumulative_packets // 2,
                bytes_received=self.cumulative_packets * 64,
                bytes_sent=self.cumulative_packets * 32,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=[],
            flows=flows,
            port_stats=port_stats,
        )


class FlowTableExhaustionAttack(ScenarioGenerator):
    """Flow table exhaustion attack scenario."""

    def generate_snapshot(self) -> TelemetrySnapshot:
        timestamp = self.start_time + self.tick
        devices = [
            Device(
                device_id="of:0000000000000001", available=True, role="MASTER", type="SWITCH"
            )
        ]
        hosts = [
            Host(
                host_id="00:00:00:00:00:01/-1", mac="00:00:00:00:00:01", vlan="-1",
                ip_addresses=["10.0.0.1"]
            )
        ]

        # Attack: flood with many unique flows
        flows = []
        if self.tick >= 3:
            for i in range(900):  # 90% of typical 1000-entry table
                flows.append(
                    Flow(
                        flow_id=f"exhaust_flow_{i}",
                        device_id="of:0000000000000001",
                        table_id=0,
                        app_id="attacker",
                        priority=50,
                        timeout=120,
                        is_permanent=False,
                        state="ADDED",
                        packets=10,
                        bytes=1500,
                    )
                )

        port_stats = [
            PortStats(
                device_id="of:0000000000000001",
                port_number="1",
                timestamp=timestamp,
                packets_received=5000,
                packets_sent=4000,
                bytes_received=750000,
                bytes_sent=600000,
            ),
        ]

        return TelemetrySnapshot(
            timestamp=timestamp,
            devices=devices,
            hosts=hosts,
            links=[],
            flows=flows,
            port_stats=port_stats,
        )


# Scenario registry
SCENARIOS = {
    "benign": BenignTraffic,
    "syn_flood": SynFloodAttack,
    "udp_flood": UdpFloodAttack,
    "icmp_flood": IcmpFloodAttack,
    "port_scan": PortScanAttack,
    "flow_table_exhaustion": FlowTableExhaustionAttack,
    # TODO Phase 4: arp_spoofing, cp_saturation, topology_poisoning
}
