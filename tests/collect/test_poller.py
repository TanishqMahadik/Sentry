"""Tests for collect/poller.py telemetry poller."""

import unittest

from sentry.collect.poller import TelemetryPoller
from sentry.onos.client import OnosClient
from sentry.onos.transport import FakeTransport


class TestTelemetryPoller(unittest.TestCase):
    """Test telemetry poller functionality."""

    def setUp(self):
        """Set up test environment."""
        self.transport = FakeTransport()
        self.client = OnosClient(self.transport)
        self.poller = TelemetryPoller(self.client, poll_interval=0.1)

    def test_poll_once_success(self):
        """Test successful single poll."""
        snapshot = self.poller.poll_once()
        self.assertIsNotNone(snapshot)
        self.assertEqual(self.poller.get_stats()["poll_count"], 1)
        self.assertEqual(self.poller.get_stats()["error_count"], 0)

    def test_start_run_once(self):
        """Test start with run_once=True calls callback once."""
        received_snapshots = []

        def callback(snapshot):
            received_snapshots.append(snapshot)

        self.poller.start(callback, run_once=True)
        self.assertEqual(len(received_snapshots), 1)
        self.assertIsNotNone(received_snapshots[0])


if __name__ == "__main__":
    unittest.main()
