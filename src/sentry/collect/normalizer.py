"""Telemetry normalizer for converting monotonic counters to delta metrics.

Handles counter resets, switch reconnects, and produces per-interval rate metrics.
Critical for accurate threat detection (FR-2: Adaptive Telemetry Ingestion).
"""

from __future__ import annotations

import logging

from sentry.core.models import PortStats, TelemetrySnapshot

logger = logging.getLogger(__name__)


class TelemetryNormalizer:
    """Normalizes monotonic counters to per-interval delta metrics."""

    def __init__(self) -> None:
        """Initialize normalizer with empty state."""
        self._previous_port_stats: dict[str, PortStats] = {}
        self._previous_timestamp: int | None = None

    def _make_port_key(self, stat: PortStats) -> str:
        """Generate unique key for port stat tracking."""
        return f"{stat.device_id}:{stat.port_number}"

    def normalize_snapshot(
        self, snapshot: TelemetrySnapshot
    ) -> dict[str, dict[str, float]]:
        """Normalize telemetry snapshot to per-second rates.

        Args:
            snapshot: Raw telemetry snapshot from ONOS

        Returns:
            Dictionary mapping port_key to rate metrics:
            {
                "of:1:1": {
                    "pps_rx": 100.5,
                    "pps_tx": 95.2,
                    "bps_rx": 12800.0,
                    "bps_tx": 12160.0,
                    ...
                }
            }
        """
        normalized: dict[str, dict[str, float]] = {}

        # Calculate time delta
        if self._previous_timestamp is None:
            # First snapshot - store and return empty (no delta available)
            self._store_snapshot(snapshot)
            logger.info("First snapshot stored, no delta computed")
            return normalized

        time_delta = snapshot.timestamp - self._previous_timestamp
        if time_delta <= 0:
            logger.warning("Non-positive time delta detected, skipping normalization")
            return normalized

        # Normalize port statistics
        for current_stat in snapshot.port_stats:
            port_key = self._make_port_key(current_stat)
            previous_stat = self._previous_port_stats.get(port_key)

            if previous_stat is None:
                # New port appeared - store and skip (no baseline)
                logger.debug("New port detected", extra={"port_key": port_key})
                continue

            # Detect counter reset (current < previous)
            reset_detected = (
                current_stat.packets_received < previous_stat.packets_received
                or current_stat.packets_sent < previous_stat.packets_sent
                or current_stat.bytes_received < previous_stat.bytes_received
                or current_stat.bytes_sent < previous_stat.bytes_sent
            )

            if reset_detected:
                logger.warning(
                    "Counter reset detected",
                    extra={
                        "port_key": port_key,
                        "prev_rx": previous_stat.packets_received,
                        "curr_rx": current_stat.packets_received,
                    },
                )
                # Skip this interval - next one will have valid delta
                continue

            # Calculate deltas
            delta_packets_rx = current_stat.packets_received - previous_stat.packets_received
            delta_packets_tx = current_stat.packets_sent - previous_stat.packets_sent
            delta_bytes_rx = current_stat.bytes_received - previous_stat.bytes_received
            delta_bytes_tx = current_stat.bytes_sent - previous_stat.bytes_sent
            delta_drops_rx = current_stat.packets_rx_dropped - previous_stat.packets_rx_dropped
            delta_drops_tx = current_stat.packets_tx_dropped - previous_stat.packets_tx_dropped
            delta_errors_rx = current_stat.packets_rx_errors - previous_stat.packets_rx_errors
            delta_errors_tx = current_stat.packets_tx_errors - previous_stat.packets_tx_errors

            # Convert to per-second rates
            normalized[port_key] = {
                "pps_rx": delta_packets_rx / time_delta,
                "pps_tx": delta_packets_tx / time_delta,
                "bps_rx": delta_bytes_rx / time_delta,
                "bps_tx": delta_bytes_tx / time_delta,
                "drops_rx_rate": delta_drops_rx / time_delta,
                "drops_tx_rate": delta_drops_tx / time_delta,
                "errors_rx_rate": delta_errors_rx / time_delta,
                "errors_tx_rate": delta_errors_tx / time_delta,
            }

        # Store current snapshot for next normalization
        self._store_snapshot(snapshot)

        logger.info(
            "Snapshot normalized",
            extra={
                "ports_normalized": len(normalized),
                "time_delta": time_delta,
            },
        )

        return normalized

    def _store_snapshot(self, snapshot: TelemetrySnapshot) -> None:
        """Store snapshot state for next delta calculation."""
        self._previous_timestamp = snapshot.timestamp
        self._previous_port_stats.clear()

        for stat in snapshot.port_stats:
            port_key = self._make_port_key(stat)
            self._previous_port_stats[port_key] = stat

    def reset(self) -> None:
        """Reset normalizer state (useful for testing or reconnection handling)."""
        logger.info("Normalizer state reset")
        self._previous_port_stats.clear()
        self._previous_timestamp = None

    def get_tracked_ports(self) -> list[str]:
        """Get list of currently tracked port keys."""
        return list(self._previous_port_stats.keys())
