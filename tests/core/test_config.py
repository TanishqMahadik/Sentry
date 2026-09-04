"""Tests for core/config.py configuration loading."""

import unittest
import tempfile
import os
from sentry.core.config import load_config, setup_logging


class TestConfig(unittest.TestCase):
    """Test configuration loading."""

    def test_load_default_config(self):
        """Test loading default config files."""
        config = load_config()

        # Verify service config
        self.assertEqual(config.service.name, "sentry")
        self.assertEqual(config.service.mode, "dry-run")
        self.assertEqual(config.service.poll_interval, 2.0)
        self.assertEqual(config.service.warmup_windows, 5)

        # Verify ONOS config
        self.assertEqual(config.onos.host, "127.0.0.1")
        self.assertEqual(config.onos.port, 8181)
        self.assertEqual(config.onos.username, "onos")
        self.assertEqual(config.onos.password, "rocks")

        # Verify API config
        self.assertEqual(config.api.port, 9090)
        self.assertEqual(config.api.session_ttl_seconds, 43200)

        # Verify threat configs exist
        self.assertIn("syn_flood", config.threats)
        self.assertTrue(config.threats["syn_flood"].enabled)
        self.assertEqual(config.threats["syn_flood"].threshold_pps, 500)

        self.assertIn("topology_poisoning", config.threats)
        self.assertTrue(config.threats["topology_poisoning"].alert_only)

        # Verify mitigation config
        self.assertEqual(config.mitigation.default_ttl_seconds, 60)
        self.assertTrue(config.mitigation.prevent_gateway_quarantine)
        self.assertTrue(config.mitigation.require_operator_ack_stage_4)

    def test_setup_logging(self):
        """Test structured JSON logging setup."""
        setup_logging("DEBUG")
        import logging
        logger = logging.getLogger("test")
        self.assertEqual(logger.getEffectiveLevel(), logging.DEBUG)


if __name__ == "__main__":
    unittest.main()
