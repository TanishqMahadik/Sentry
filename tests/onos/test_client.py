"""Tests for onos/client.py ONOS REST client."""

import unittest
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport


class TestOnosClient(unittest.TestCase):
    """Test ONOS client methods using FakeTransport."""

    def setUp(self):
        """Set up test client with FakeTransport."""
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)

    def test_get_devices(self):
        """Test parsing devices endpoint."""
        mock_data = {
            "devices": [
                {
                    "id": "of:0000000000000001",
                    "type": "SWITCH",
                    "available": True,
                    "role": "MASTER",
                    "mfr": "Open Networking Foundation",
                    "hw": "OpenFlow 1.3",
                    "sw": "2.17.0",
                }
            ]
        }
        self.transport.register_fixture("/devices", mock_data)

        devices = self.client.get_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].device_id, "of:0000000000000001")
        self.assertTrue(devices[0].available)
        self.assertEqual(devices[0].role, "MASTER")
        self.assertEqual(devices[0].manufacturer, "Open Networking Foundation")

    def test_get_hosts(self):
        """Test parsing hosts endpoint."""
        mock_data = {
            "hosts": [
                {
                    "id": "00:00:00:00:00:01/None",
                    "mac": "00:00:00:00:00:01",
                    "vlan": "None",
                    "ipAddresses": ["10.0.0.1"],
                    "locations": [{"elementId": "of:0000000000000001", "port": "1"}],
                }
            ]
        }
        self.transport.register_fixture("/hosts", mock_data)

        hosts = self.client.get_hosts()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].mac, "00:00:00:00:00:01")
        self.assertEqual(hosts[0].ip_addresses, ["10.0.0.1"])

    def test_get_links(self):
        """Test parsing links endpoint."""
        mock_data = {
            "links": [
                {
                    "src": {"device": "of:0000000000000001", "port": "2"},
                    "dst": {"device": "of:0000000000000002", "port": "1"},
                    "type": "DIRECT",
                    "state": "ACTIVE",
                }
            ]
        }
        self.transport.register_fixture("/links", mock_data)

        links = self.client.get_links()
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].src_device, "of:0000000000000001")
        self.assertEqual(links[0].dst_device, "of:0000000000000002")
        self.assertEqual(links[0].state, "ACTIVE")

    def test_get_telemetry_snapshot(self):
        """Test full telemetry snapshot assembly."""
        self.transport.register_fixture("/devices", {"devices": [{"id": "of:1"}]})
        self.transport.register_fixture("/hosts", {"hosts": [{"id": "h1", "mac": "00:01"}]})
        self.transport.register_fixture(
            "/links", {"links": [{"src": {"device": "of:1"}, "dst": {"device": "of:2"}}]}
        )
        self.transport.register_fixture("/flows", {"flows": [{"id": "f1", "deviceId": "of:1"}]})
        self.transport.register_fixture(
            "/statistics/ports", {"statistics": [{"deviceId": "of:1", "port": "1"}]}
        )
        self.transport.register_fixture(
            "/statistics/flows", {"statistics": [{"deviceId": "of:1", "flowId": "f1"}]}
        )

        snapshot = self.client.get_telemetry_snapshot()
        self.assertEqual(len(snapshot.devices), 1)
        self.assertEqual(len(snapshot.hosts), 1)
        self.assertEqual(len(snapshot.links), 1)
        self.assertEqual(len(snapshot.flows), 1)
        self.assertEqual(len(snapshot.port_stats), 1)
        self.assertEqual(len(snapshot.flow_stats), 1)
        self.assertGreater(snapshot.timestamp, 0)


if __name__ == "__main__":
    unittest.main()
