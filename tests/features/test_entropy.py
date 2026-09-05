"""Tests for features/entropy.py Shannon entropy calculations.

Uses hand-computed test cases to verify correctness.
"""

import unittest

from sentry.features.entropy import (
    compute_ip_entropy,
    compute_port_entropy,
    compute_protocol_entropy,
    shannon_entropy,
)


class TestShannonEntropy(unittest.TestCase):
    """Test Shannon entropy calculations with hand-computed cases."""

    def test_empty_distribution(self):
        """Empty distribution should return 0.0."""
        self.assertEqual(shannon_entropy({}), 0.0)

    def test_single_element(self):
        """Single element (no diversity) should return 0.0."""
        self.assertEqual(shannon_entropy({"a": 100}), 0.0)

    def test_uniform_distribution(self):
        """Perfectly uniform distribution should return 0.0 (no concentration)."""
        # 4 elements with equal frequency: entropy is maximized
        uniform = {"a": 25, "b": 25, "c": 25, "d": 25}
        result = shannon_entropy(uniform)
        self.assertAlmostEqual(result, 0.0, places=5)

    def test_perfectly_concentrated(self):
        """Perfectly concentrated distribution should return 1.0."""
        # One element dominates completely
        concentrated = {"a": 100, "b": 0, "c": 0, "d": 0}
        result = shannon_entropy(concentrated)
        self.assertAlmostEqual(result, 1.0, places=5)

    def test_hand_computed_case_1(self):
        """Hand-computed: 2 elements, 80/20 split.

        freq = {"a": 80, "b": 20}
        total = 100
        p_a = 0.8, p_b = 0.2
        H = -(0.8*log2(0.8) + 0.2*log2(0.2))
          = -(0.8*(-0.3219) + 0.2*(-2.3219))
          = -(-0.2575 + -0.4644)
          = 0.7219
        max_H = log2(2) = 1.0
        normalized_H = 0.7219 / 1.0 = 0.7219
        inverted (concentration) = 1 - 0.7219 = 0.2781
        """
        dist = {"a": 80, "b": 20}
        result = shannon_entropy(dist)
        expected = 1.0 - 0.7219  # Inverted for concentration measure
        self.assertAlmostEqual(result, expected, places=3)

    def test_hand_computed_case_2(self):
        """Hand-computed: 3 elements, skewed distribution.

        freq = {"x": 50, "y": 30, "z": 20}
        total = 100
        p_x=0.5, p_y=0.3, p_z=0.2
        H = -(0.5*log2(0.5) + 0.3*log2(0.3) + 0.2*log2(0.2))
          = -(0.5*(-1.0) + 0.3*(-1.737) + 0.2*(-2.322))
          = -(-0.5 + -0.521 + -0.464)
          = 1.485
        max_H = log2(3) = 1.585
        normalized_H = 1.485 / 1.585 = 0.937
        inverted = 1 - 0.937 = 0.063
        """
        dist = {"x": 50, "y": 30, "z": 20}
        result = shannon_entropy(dist)
        # Expect low concentration (fairly distributed)
        self.assertLess(result, 0.2)

    def test_ip_entropy_uniform(self):
        """Test IP entropy with uniform distribution."""
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        result = compute_ip_entropy(ips)
        self.assertAlmostEqual(result, 0.0, places=5)

    def test_ip_entropy_concentrated(self):
        """Test IP entropy with concentrated distribution (DDoS pattern)."""
        ips = ["10.0.0.1"] * 100 + ["10.0.0.2"] * 5
        result = compute_ip_entropy(ips)
        # Should show high concentration
        self.assertGreater(result, 0.5)

    def test_port_entropy_port_scan(self):
        """Port scan pattern: many unique ports visited."""
        # 50 unique ports each visited once = low concentration
        ports = list(range(1, 51))
        result = compute_port_entropy(ports)
        self.assertLess(result, 0.2)

    def test_port_entropy_normal_traffic(self):
        """Normal traffic: few common ports dominate."""
        # Port 80 and 443 dominate
        ports = [80] * 50 + [443] * 40 + [22, 25, 53]
        result = compute_port_entropy(ports)
        # Should show some concentration
        self.assertGreater(result, 0.3)

    def test_protocol_entropy(self):
        """Test protocol entropy."""
        # Mostly TCP with some UDP
        protocols = ["TCP"] * 90 + ["UDP"] * 10
        result = compute_protocol_entropy(protocols)
        # High concentration on TCP
        self.assertGreater(result, 0.2)


if __name__ == "__main__":
    unittest.main()
