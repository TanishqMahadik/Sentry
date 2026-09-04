"""Tests for core/minyaml.py zero-dependency YAML parser."""

import unittest
from sentry.core.minyaml import parse_yaml, load_yaml_file


class TestMinYaml(unittest.TestCase):
    """Test minyaml parsing capabilities."""

    def test_parse_simple_key_value(self):
        """Test simple string key-value pairs."""
        text = """
        app_name: sentry
        version: 1.0.0
        mode: dry-run
        """
        result = parse_yaml(text)
        self.assertEqual(result["app_name"], "sentry")
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["mode"], "dry-run")

    def test_parse_data_types(self):
        """Test numbers, booleans, nulls."""
        text = """
        port: 8181
        rate_limit: 10.5
        enabled: true
        debug: false
        empty_val: null
        tilde_val: ~
        """
        result = parse_yaml(text)
        self.assertEqual(result["port"], 8181)
        self.assertEqual(result["rate_limit"], 10.5)
        self.assertTrue(result["enabled"])
        self.assertFalse(result["debug"])
        self.assertIsNone(result["empty_val"])
        self.assertIsNone(result["tilde_val"])

    def test_parse_nested_dict(self):
        """Test nested dictionaries via indentation."""
        text = """
        onos:
          host: 127.0.0.1
          port: 8181
          auth:
            username: onos
            password: rocks
        server:
          port: 9090
        """
        result = parse_yaml(text)
        self.assertEqual(result["onos"]["host"], "127.0.0.1")
        self.assertEqual(result["onos"]["port"], 8181)
        self.assertEqual(result["onos"]["auth"]["username"], "onos")
        self.assertEqual(result["onos"]["auth"]["password"], "rocks")
        self.assertEqual(result["server"]["port"], 9090)

    def test_parse_simple_list(self):
        """Test simple list of scalars."""
        text = """
        attacks:
          - syn_flood
          - udp_flood
          - icmp_flood
          - port_scan
        """
        result = parse_yaml(text)
        self.assertEqual(
            result["attacks"],
            ["syn_flood", "udp_flood", "icmp_flood", "port_scan"],
        )

    def test_parse_list_of_dicts(self):
        """Test list of dictionaries."""
        text = """
        rules:
          - name: syn_detector
            threshold: 100
            enabled: true
          - name: udp_detector
            threshold: 200
            enabled: false
        """
        result = parse_yaml(text)
        self.assertEqual(len(result["rules"]), 2)
        self.assertEqual(result["rules"][0]["name"], "syn_detector")
        self.assertEqual(result["rules"][0]["threshold"], 100)
        self.assertTrue(result["rules"][0]["enabled"])
        self.assertEqual(result["rules"][1]["name"], "udp_detector")
        self.assertFalse(result["rules"][1]["enabled"])

    def test_parse_comments_and_blank_lines(self):
        """Test that comments (#) and blank lines are ignored."""
        text = """
        # Global Sentry Config
        service:
          # Port for REST API
          port: 9090

          # Log level
          log_level: DEBUG # inline comment
        """
        result = parse_yaml(text)
        self.assertEqual(result["service"]["port"], 9090)
        self.assertEqual(result["service"]["log_level"], "DEBUG")

    def test_quoted_strings(self):
        """Test single and double quoted strings."""
        text = """
        msg_double: "hello world"
        msg_single: 'hello world'
        ip_range: "10.0.0.0/24"
        special: "true"
        """
        result = parse_yaml(text)
        self.assertEqual(result["msg_double"], "hello world")
        self.assertEqual(result["msg_single"], "hello world")
        self.assertEqual(result["ip_range"], "10.0.0.0/24")
        self.assertEqual(result["special"], "true")  # Should be string, not bool


if __name__ == "__main__":
    unittest.main()
