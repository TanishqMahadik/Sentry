"""Shannon Entropy calculation for anomaly detection.

Computes normalized Shannon entropy (H) for frequency distributions.
Used to detect traffic concentration anomalies (e.g., port scans, DDoS).

Zero third-party dependencies (stdlib only, NFR-3).
"""

from __future__ import annotations

import math
from typing import Any


def shannon_entropy(frequency_dist: dict[Any, int]) -> float:
    """Calculate normalized Shannon entropy for a frequency distribution.

    Shannon entropy measures the randomness/uniformity of a distribution.
    - H = 0.0: completely uniform (all values equally likely)
    - H = 1.0: perfectly concentrated (one value dominates)

    Formula:
        H = -Σ(p_i * log2(p_i)) / log2(N)
        where p_i is the probability of element i, N is distinct elements

    Args:
        frequency_dist: Dictionary mapping values to their occurrence counts
                        e.g., {"10.0.0.1": 100, "10.0.0.2": 50}

    Returns:
        Normalized entropy [0.0, 1.0]
        Returns 0.0 for empty or single-element distributions
    """
    if not frequency_dist:
        return 0.0

    n_distinct = len(frequency_dist)
    if n_distinct == 1:
        return 0.0  # Single element = no entropy

    total = sum(frequency_dist.values())
    if total == 0:
        return 0.0

    # Calculate Shannon entropy: -Σ(p_i * log2(p_i))
    entropy = 0.0
    for count in frequency_dist.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    # Normalize by max possible entropy: log2(N)
    max_entropy = math.log2(n_distinct)
    normalized = entropy / max_entropy

    # Invert so higher value = more concentrated (anomalous)
    return 1.0 - normalized


def compute_ip_entropy(ip_addresses: list[str]) -> float:
    """Calculate entropy of IP address distribution.

    Args:
        ip_addresses: List of IP addresses (may contain duplicates)

    Returns:
        Normalized entropy score [0.0, 1.0]
    """
    freq_dist: dict[str, int] = {}
    for ip in ip_addresses:
        freq_dist[ip] = freq_dist.get(ip, 0) + 1
    return shannon_entropy(freq_dist)


def compute_port_entropy(ports: list[int]) -> float:
    """Calculate entropy of port number distribution.

    Args:
        ports: List of port numbers (may contain duplicates)

    Returns:
        Normalized entropy score [0.0, 1.0]
    """
    freq_dist: dict[int, int] = {}
    for port in ports:
        freq_dist[port] = freq_dist.get(port, 0) + 1
    return shannon_entropy(freq_dist)


def compute_protocol_entropy(protocols: list[str]) -> float:
    """Calculate entropy of protocol distribution (TCP, UDP, ICMP, etc.).

    Args:
        protocols: List of protocol names (may contain duplicates)

    Returns:
        Normalized entropy score [0.0, 1.0]
    """
    freq_dist: dict[str, int] = {}
    for proto in protocols:
        freq_dist[proto] = freq_dist.get(proto, 0) + 1
    return shannon_entropy(freq_dist)
