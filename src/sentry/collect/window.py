"""Sliding window baseline management for statistical anomaly detection.

Maintains EWMA (Exponentially Weighted Moving Average) mean and MAD (Median Absolute Deviation)
baselines per subject (host, port, device) over rolling time windows.

Implements Invariant I9: baseline updates freeze during active mitigations to prevent
oscillation loops where the attack traffic becomes the "new normal".
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sentry.core.models import BaselineWindow

logger = logging.getLogger(__name__)


class WindowManager:
    """Manages sliding time windows and baseline statistics per subject."""

    def __init__(
        self,
        window_seconds: int = 5,
        warmup_windows: int = 5,
        ewma_alpha: float = 0.3,
    ) -> None:
        """Initialize window manager.

        Args:
            window_seconds: Time window duration in seconds
            warmup_windows: Number of windows to collect before enabling alerts
            ewma_alpha: EWMA smoothing factor (0.0-1.0, higher = more weight to recent)
        """
        self.window_seconds = window_seconds
        self.warmup_windows = warmup_windows
        self.ewma_alpha = ewma_alpha

        # Subject baselines: {subject_id: {metric_name: BaselineWindow}}
        self._baselines: dict[str, dict[str, BaselineWindow]] = {}

        # Warmup tracking
        self._warmup_counts: dict[str, int] = {}

        # Invariant I9: freeze baselines during active mitigations
        self._frozen_subjects: set[str] = set()

    def update_baseline(
        self, subject_id: str, metric_name: str, value: float, timestamp: int
    ) -> BaselineWindow:
        """Update baseline statistics for a subject metric.

        Args:
            subject_id: Subject identifier (e.g., host IP, port key)
            metric_name: Metric name (e.g., "pps_rx", "bps_tx")
            value: Current metric value
            timestamp: Current timestamp

        Returns:
            Updated BaselineWindow
        """
        # Check if subject is frozen (Invariant I9)
        if subject_id in self._frozen_subjects:
            logger.debug(
                "Baseline frozen, skipping update",
                extra={"subject_id": subject_id, "metric": metric_name},
            )
            return self._get_baseline(subject_id, metric_name)

        # Initialize baseline if needed
        if subject_id not in self._baselines:
            self._baselines[subject_id] = {}
            self._warmup_counts[subject_id] = 0

        if metric_name not in self._baselines[subject_id]:
            self._baselines[subject_id][metric_name] = BaselineWindow(
                subject_id=subject_id,
                metric_name=metric_name,
                ewma_mean=value,
                mad_deviation=0.0,
                sample_count=1,
                last_updated=timestamp,
                frozen=False,
            )
            self._warmup_counts[subject_id] += 1
            return self._baselines[subject_id][metric_name]

        baseline = self._baselines[subject_id][metric_name]

        # Update EWMA mean
        new_mean = (
            self.ewma_alpha * value + (1 - self.ewma_alpha) * baseline.ewma_mean
        )

        # Update MAD (simplified incremental approximation)
        deviation = abs(value - baseline.ewma_mean)
        new_mad = (
            self.ewma_alpha * deviation + (1 - self.ewma_alpha) * baseline.mad_deviation
        )

        # Update baseline
        baseline.ewma_mean = new_mean
        baseline.mad_deviation = max(new_mad, 0.01)  # Prevent division by zero
        baseline.sample_count += 1
        baseline.last_updated = timestamp

        self._warmup_counts[subject_id] += 1

        logger.debug(
            "Baseline updated",
            extra={
                "subject": subject_id,
                "metric": metric_name,
                "mean": new_mean,
                "mad": new_mad,
                "samples": baseline.sample_count,
            },
        )

        return baseline

    def get_baseline(self, subject_id: str, metric_name: str) -> BaselineWindow | None:
        """Get baseline for a subject metric.

        Args:
            subject_id: Subject identifier
            metric_name: Metric name

        Returns:
            BaselineWindow if exists, None otherwise
        """
        return self._baselines.get(subject_id, {}).get(metric_name)

    def _get_baseline(self, subject_id: str, metric_name: str) -> BaselineWindow:
        """Internal getter that returns existing baseline (assumes it exists)."""
        return self._baselines[subject_id][metric_name]

    def is_warmup_complete(self, subject_id: str) -> bool:
        """Check if warmup period is complete for a subject.

        Args:
            subject_id: Subject identifier

        Returns:
            True if warmup complete, False otherwise
        """
        count = self._warmup_counts.get(subject_id, 0)
        return count >= self.warmup_windows

    def is_anomalous(
        self,
        subject_id: str,
        metric_name: str,
        value: float,
        mad_threshold: float = 3.0,
    ) -> tuple[bool, float]:
        """Check if a value is anomalous relative to baseline.

        Args:
            subject_id: Subject identifier
            metric_name: Metric name
            value: Current metric value
            mad_threshold: Number of MAD deviations to consider anomalous

        Returns:
            (is_anomalous, deviation_score) tuple
        """
        baseline = self.get_baseline(subject_id, metric_name)
        if baseline is None:
            return False, 0.0

        # Calculate MAD-based deviation score
        deviation = abs(value - baseline.ewma_mean)
        mad_score = deviation / baseline.mad_deviation if baseline.mad_deviation > 0 else 0.0

        is_anomalous = mad_score > mad_threshold
        return is_anomalous, mad_score

    def freeze_subject(self, subject_id: str) -> None:
        """Freeze baseline updates for a subject (Invariant I9).

        Called when a mitigation is applied to prevent attack traffic
        from becoming the new baseline.

        Args:
            subject_id: Subject identifier to freeze
        """
        self._frozen_subjects.add(subject_id)
        # Mark all baselines for this subject as frozen
        if subject_id in self._baselines:
            for baseline in self._baselines[subject_id].values():
                baseline.frozen = True
        logger.info("Subject baseline frozen", extra={"subject_id": subject_id})

    def unfreeze_subject(self, subject_id: str) -> None:
        """Unfreeze baseline updates for a subject.

        Called when a mitigation expires or is revoked.

        Args:
            subject_id: Subject identifier to unfreeze
        """
        self._frozen_subjects.discard(subject_id)
        if subject_id in self._baselines:
            for baseline in self._baselines[subject_id].values():
                baseline.frozen = False
        logger.info("Subject baseline unfrozen", extra={"subject_id": subject_id})

    def is_frozen(self, subject_id: str) -> bool:
        """Check if a subject's baselines are frozen.

        Args:
            subject_id: Subject identifier

        Returns:
            True if frozen, False otherwise
        """
        return subject_id in self._frozen_subjects

    def get_all_baselines(self) -> dict[str, dict[str, BaselineWindow]]:
        """Get all tracked baselines.

        Returns:
            Dictionary mapping subject_id -> {metric_name -> BaselineWindow}
        """
        return self._baselines

    def reset(self) -> None:
        """Reset all baselines and warmup state."""
        self._baselines.clear()
        self._warmup_counts.clear()
        self._frozen_subjects.clear()
        logger.info("Window manager reset")
