"""Tests for onos/transport.py HTTP transport and FakeTransport."""

import unittest

from sentry.onos.transport import FakeTransport, UrllibTransport


class TestTransport(unittest.TestCase):
    """Test transport classes."""

    def test_fake_transport_default_responses(self):
        """Test FakeTransport returns appropriate defaults for endpoints."""
        transport = FakeTransport()

        devices = transport.get("/devices")
        self.assertEqual(devices, {"devices": []})

        hosts = transport.get("/hosts")
        self.assertEqual(hosts, {"hosts": []})

        links = transport.get("/links")
        self.assertEqual(links, {"links": []})

        flows = transport.get("/flows")
        self.assertEqual(flows, {"flows": []})

    def test_fake_transport_custom_fixtures(self):
        """Test FakeTransport fixture registration."""
        transport = FakeTransport()
        mock_devices = {
            "devices": [
                {
                    "id": "of:0000000000000001",
                    "type": "SWITCH",
                    "available": True,
                    "role": "MASTER",
                }
            ]
        }
        transport.register_fixture("/devices", mock_devices)

        response = transport.get("/devices")
        self.assertEqual(response, mock_devices)

    def test_fake_transport_call_logging(self):
        """Test that FakeTransport accurately logs calls."""
        transport = FakeTransport()
        transport.get("/devices")
        transport.post("/flows/of:0000000000000001", {"priority": 100})
        transport.delete("/flows/of:0000000000000001/12345")

        log = transport.get_call_log()
        self.assertEqual(len(log), 3)
        self.assertEqual(log[0], ("GET", "/devices", None))
        self.assertEqual(log[1], ("POST", "/flows/of:0000000000000001", {"priority": 100}))
        self.assertEqual(log[2], ("DELETE", "/flows/of:0000000000000001/12345", None))

    def test_urllib_transport_init(self):
        """Test UrllibTransport sets up headers correctly."""
        transport = UrllibTransport(
            base_url="http://127.0.0.1:8181/onos/v1",
            username="onos",
            password="rocks",
        )
        self.assertEqual(transport.base_url, "http://127.0.0.1:8181/onos/v1")
        self.assertTrue(transport.auth_header.startswith("Basic "))


if __name__ == "__main__":
    unittest.main()
