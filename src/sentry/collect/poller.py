"""Telemetry poller for continuous ONOS data collection.

Polls ONOS at configured intervals, handles connection failures with
exponential backoff, and emits telemetry snapshots for downstream processing.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from sentry.core.models import TelemetrySnapshot
from sentry.onos.client import OnosClient

logger = logging.getLogger(__name__)


class TelemetryPoller:
    """Polls ONOS for telemetry at regular intervals."""

    def __init__(
        self,
        client: OnosClient,
        poll_interval: float = 2.0,
        backoff_initial: float = 1.0,
        backoff_multiplier: float = 2.0,
        backoff_max: float = 30.0,
    ) -> None:
        """Initialize telemetry poller.

        Args:
            client: OnosClient instance
            poll_interval: Seconds between successful polls
            backoff_initial: Initial backoff on connection failure
            backoff_multiplier: Exponential backoff multiplier
            backoff_max: Maximum backoff duration
        """
        self.client = client
        self.poll_interval = poll_interval
        self.backoff_initial = backoff_initial
        self.backoff_multiplier = backoff_multiplier
        self.backoff_max = backoff_max

        self._running = False
        self._poll_count = 0
        self._error_count = 0

    def poll_once(self) -> TelemetrySnapshot | None:
        """Poll ONOS once and return telemetry snapshot.

        Returns:
            TelemetrySnapshot if successful, None on error
        """
        try:
            snapshot = self.client.get_telemetry_snapshot()
            self._poll_count += 1
            logger.info(
                "Telemetry poll successful",
                extra={
                    "poll_count": self._poll_count,
                    "devices": len(snapshot.devices),
                    "hosts": len(snapshot.hosts),
                    "flows": len(snapshot.flows),
                },
            )
            return snapshot

        except Exception as e:
            self._error_count += 1
            logger.error(
                "Telemetry poll failed",
                extra={"error": str(e), "error_count": self._error_count},
            )
            return None

    def start(
        self,
        on_snapshot: Callable[[TelemetrySnapshot], None],
        run_once: bool = False,
    ) -> None:
        """Start continuous polling loop.

        Args:
            on_snapshot: Callback function invoked with each snapshot
            run_once: If True, poll once and exit (for testing)
        """
        self._running = True
        backoff_delay = self.backoff_initial
        consecutive_failures = 0

        logger.info(
            "Starting telemetry poller",
            extra={"poll_interval": self.poll_interval, "run_once": run_once},
        )

        while self._running:
            snapshot = self.poll_once()

            if snapshot:
                # Successful poll - reset backoff and invoke callback
                backoff_delay = self.backoff_initial
                consecutive_failures = 0
                on_snapshot(snapshot)

                if run_once:
                    logger.info("Single poll complete, exiting")
                    break

                # Sleep until next poll interval
                time.sleep(self.poll_interval)

            else:
                # Failed poll - apply exponential backoff
                consecutive_failures += 1
                logger.warning(
                    "Poll failed, applying backoff",
                    extra={
                        "consecutive_failures": consecutive_failures,
                        "backoff_delay": backoff_delay,
                    },
                )
                time.sleep(backoff_delay)
                backoff_delay = min(backoff_delay * self.backoff_multiplier, self.backoff_max)

                if run_once:
                    logger.error("Single poll failed, exiting")
                    break

    def stop(self) -> None:
        """Stop the polling loop."""
        logger.info("Stopping telemetry poller")
        self._running = False

    def get_stats(self) -> dict[str, int]:
        """Get poller statistics.

        Returns:
            Dictionary with poll_count and error_count
        """
        return {
            "poll_count": self._poll_count,
            "error_count": self._error_count,
        }
