"""Tests for detect/rules.py — 8 threat detection rules."""

import unittest

from sentry.detect.rules import (
    RULES,
    ArpSpoofRule,
    CpSaturationRule,
    FlowTableExhaustionRule,
    IcmpFloodRule,
    PortScanRule,
    SynFloodRule,
    TopologyPoisoningRule,
    UdpFloodRule,
)


class TestSynFloodRule(unittest.TestCase):
    """Test SYN flood detection."""

    def test_detects_high_pps_asymmetric(self):
        rule = SynFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 100}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "SYN_FLOOD")

    def test_no_alert_on_balanced_traffic(self):
        rule = SynFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 2000, "pps_tx": 1900}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNone(verdict)

    def test_no_alert_below_threshold(self):
        rule = SynFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 500, "pps_tx": 100}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNone(verdict)

    def test_mad_based_detection(self):
        rule = SynFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 5000, "pps_tx": 100}}
        baselines = {"of:1:1": {"pps_rx": (200.0, 30.0)}}
        verdict = rule.evaluate(port_metrics, {}, baselines)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "SYN_FLOOD")


class TestUdpFloodRule(unittest.TestCase):
    """Test UDP flood detection."""

    def test_detects_high_pps(self):
        rule = UdpFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 3000, "pps_tx": 500}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "UDP_FLOOD")

    def test_no_alert_below_threshold(self):
        rule = UdpFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 500, "pps_tx": 400}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNone(verdict)


class TestIcmpFloodRule(unittest.TestCase):
    """Test ICMP flood detection."""

    def test_detects_high_pps(self):
        rule = IcmpFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 1000, "pps_tx": 900}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "ICMP_FLOOD")

    def test_no_alert_below_threshold(self):
        rule = IcmpFloodRule()
        port_metrics = {"of:1:1": {"pps_rx": 100, "pps_tx": 90}}
        verdict = rule.evaluate(port_metrics, {}, {})
        self.assertIsNone(verdict)


class TestPortScanRule(unittest.TestCase):
    """Test port scan detection."""

    def test_detects_many_flows_unique_ports(self):
        rule = PortScanRule()
        flow_metrics = {
            "flow_count": 30,
            "unique_dst_ports": 25,
            "avg_packets_per_flow": 3,
            "subject_id": "of:1:1",
        }
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "PORT_SCAN")

    def test_no_alert_few_flows(self):
        rule = PortScanRule()
        flow_metrics = {
            "flow_count": 5,
            "unique_dst_ports": 3,
            "avg_packets_per_flow": 100,
            "subject_id": "of:1:1",
        }
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)

    def test_no_alert_high_packets_per_flow(self):
        rule = PortScanRule()
        flow_metrics = {
            "flow_count": 30,
            "unique_dst_ports": 25,
            "avg_packets_per_flow": 50,
            "subject_id": "of:1:1",
        }
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)


class TestFlowTableExhaustionRule(unittest.TestCase):
    """Test flow table exhaustion detection."""

    def test_detects_many_flows(self):
        rule = FlowTableExhaustionRule()
        flow_metrics = {"flow_count": 900, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "FLOW_TABLE_EXHAUSTION")

    def test_no_alert_few_flows(self):
        rule = FlowTableExhaustionRule()
        flow_metrics = {"flow_count": 50, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)


class TestArpSpoofRule(unittest.TestCase):
    """Test ARP spoofing detection."""

    def test_detects_low_entropy(self):
        rule = ArpSpoofRule()
        flow_metrics = {"arp_entropy": 0.1, "duplicate_macs": 0, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "ARP_SPOOFING")

    def test_detects_duplicate_macs(self):
        rule = ArpSpoofRule()
        flow_metrics = {"arp_entropy": 0.8, "duplicate_macs": 3, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "ARP_SPOOFING")

    def test_no_alert_normal_entropy(self):
        rule = ArpSpoofRule()
        flow_metrics = {"arp_entropy": 0.9, "duplicate_macs": 0, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)


class TestCpSaturationRule(unittest.TestCase):
    """Test control-plane saturation detection."""

    def test_detects_high_cpu(self):
        rule = CpSaturationRule()
        flow_metrics = {"cpu_utilization": 0.95, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "CP_SATURATION")

    def test_no_alert_normal_cpu(self):
        rule = CpSaturationRule()
        flow_metrics = {"cpu_utilization": 0.50, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)


class TestTopologyPoisoningRule(unittest.TestCase):
    """Test topology poisoning detection (alert-only)."""

    def test_detects_link_flaps(self):
        rule = TopologyPoisoningRule()
        flow_metrics = {"link_flap_count": 5, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.threat_type, "TOPOLOGY_POISONING")
        self.assertTrue(hasattr(rule, "alert_only"))
        self.assertTrue(rule.alert_only)

    def test_no_alert_few_flaps(self):
        rule = TopologyPoisoningRule()
        flow_metrics = {"link_flap_count": 1, "subject_id": "of:1:1"}
        verdict = rule.evaluate({}, flow_metrics, {})
        self.assertIsNone(verdict)


class TestRuleRegistry(unittest.TestCase):
    """Test rule registry completeness."""

    def test_all_8_rules_registered(self):
        self.assertEqual(len(RULES), 8)

    def test_rule_names_unique(self):
        names = [cls.name for cls in RULES]
        self.assertEqual(len(names), len(set(names)))

    def test_topology_poisoning_is_alert_only(self):
        topo_rule = next(cls for cls in RULES if cls.name == "topology_poisoning")
        self.assertTrue(topo_rule.alert_only)


if __name__ == "__main__":
    unittest.main()
