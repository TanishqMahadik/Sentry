"""Threat correlator with hysteresis and escalation stages.

Tracks per-subject threat state, implements confirmation/clearing
hysteresis (2 positive windows to confirm, 5 clean windows to clear),
and manages escalation stages through the mitigation ladder.

Topology Poisoning is alert-only per FR-1 and never escalates to mitigation.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from sentry.core.models import ThreatVerdict
from sentry.detect.rules import RULES, DetectionRule

logger = logging.getLogger(__name__)


class ThreatStage(Enum):
    """Escalation stages for threat response."""

    CLEAN = "CLEAN"
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    ESCALATING = "ESCALATING"
    MITIGATING = "MITIGATING"


class SubjectState:
    """Tracks threat state for a single subject (port, device, or host).

    Uses a sliding-window approach for escalation: the last ``window_size``
    detection results are kept as a boolean ring buffer.  Escalation checks
    the number of positive signals in that window rather than requiring strictly
    *consecutive* positives, which makes the correlator robust to intermittent
    traffic patterns common in ONOS reactive-forwarding topologies.
    """

    def __init__(
        self,
        subject_id: str,
        confirm_threshold: int = 2,
        clear_threshold: int = 5,
        window_size: int = 6,
    ) -> None:
        """Initialize subject state.

        Args:
            subject_id: Unique subject identifier
            confirm_threshold: Positive windows (within window_size) to confirm
            clear_threshold: Consecutive clean windows to clear
            window_size: Sliding window length for detection history
        """
        self.subject_id = subject_id
        self.confirm_threshold = confirm_threshold
        self.clear_threshold = clear_threshold
        self.window_size = window_size
        self.stage = ThreatStage.CLEAN
        self.threat_type: str | None = None
        self.positive_count = 0
        self.clean_count = 0
        self.total_detections = 0
        self.last_verdict: ThreatVerdict | None = None
        self._alert_only_types: set[str] = set()
        # Sliding window: True = positive detection, False = clean
        self._window: list[bool] = []

    def _window_positives(self) -> int:
        """Count positive signals in the sliding window."""
        return sum(1 for v in self._window if v)

    def update(self, verdict: ThreatVerdict | None) -> ThreatStage:
        """Update state based on detection result.

        Args:
            verdict: ThreatVerdict if detected, None if clean

        Returns:
            Current stage after update
        """
        if verdict is not None:
            self.positive_count += 1
            self.clean_count = 0
            self.total_detections += 1
            self.last_verdict = verdict
            self.threat_type = verdict.threat_type
            self._window.append(True)
            if len(self._window) > self.window_size:
                self._window.pop(0)

            positives = self._window_positives()

            # Topology poisoning stays at SUSPECTED (alert-only)
            is_alert_only: bool = verdict.threat_type in self._alert_only_types

            # Escalation: need enough positives in the sliding window
            if positives >= self.confirm_threshold:
                if self.stage == ThreatStage.CLEAN:
                    self.stage = ThreatStage.SUSPECTED
                if positives >= self.confirm_threshold + 2:
                    if not is_alert_only:
                        self.stage = ThreatStage.CONFIRMED
                    else:
                        self.stage = ThreatStage.SUSPECTED
                if positives >= self.confirm_threshold + 4:
                    if not is_alert_only:
                        self.stage = ThreatStage.ESCALATING
                    else:
                        self.stage = ThreatStage.SUSPECTED
            else:
                if self.stage == ThreatStage.CLEAN:
                    self.stage = ThreatStage.SUSPECTED

        else:
            self.clean_count += 1
            self.positive_count = 0
            self._window.append(False)
            if len(self._window) > self.window_size:
                self._window.pop(0)

            # After clear_threshold consecutive clean windows, full reset
            if self.clean_count >= self.clear_threshold:
                self.stage = ThreatStage.CLEAN
                self.threat_type = None
                self.last_verdict = None
                self._window.clear()
            elif self.clean_count >= 2 and self.stage.value in ("ESCALATING", "MITIGATING"):
                self.stage = ThreatStage.CONFIRMED

        return self.stage


class Correlator:
    """Threat correlator managing per-subject state and escalation."""

    def __init__(
        self,
        confirm_threshold: int = 2,
        clear_threshold: int = 5,
        rules: list[DetectionRule] | None = None,
    ) -> None:
        """Initialize correlator.

        Args:
            confirm_threshold: Positive windows to confirm threat
            clear_threshold: Clean windows to clear threat
            rules: Optional list of rules; defaults to all RULES
        """
        self.confirm_threshold = confirm_threshold
        self.clear_threshold = clear_threshold
        self.rules = rules or [cls() for cls in RULES]
        self._subjects: dict[str, SubjectState] = {}
        self._alert_only_types = {"TOPOLOGY_POISONING"}

    def _get_or_create_subject(self, subject_id: str) -> SubjectState:
        """Get or create state for a subject."""
        if subject_id not in self._subjects:
            state = SubjectState(
                subject_id,
                confirm_threshold=self.confirm_threshold,
                clear_threshold=self.clear_threshold,
            )
            state._alert_only_types = self._alert_only_types
            self._subjects[subject_id] = state
        return self._subjects[subject_id]

    def evaluate_cycle(
        self,
        port_metrics: dict[str, dict[str, float]],
        flow_metrics: dict[str, Any],
        baseline_metrics: dict[str, dict[str, tuple[float, float]]],
    ) -> list[ThreatVerdict]:
        """Run all rules against current metrics and update subject states.

        Args:
            port_metrics: Per-port normalized rates
            flow_metrics: Flow-level statistics
            baseline_metrics: Per-subject baseline (mean, mad) tuples

        Returns:
            List of confirmed ThreatVerdicts for this cycle
        """
        confirmed_verdicts: list[ThreatVerdict] = []
        fired_subjects: set[str] = set()

        # Run each rule
        for rule in self.rules:
            verdict = rule.evaluate(port_metrics, flow_metrics, baseline_metrics)

            if verdict is not None:
                fired_subjects.add(verdict.subject_id)
                state = self._get_or_create_subject(verdict.subject_id)
                stage = state.update(verdict)
                logger.debug(
                    f"Rule {rule.name} fired for {verdict.subject_id}",
                    extra={
                        "stage": stage.value,
                        "confidence": verdict.confidence,
                        "positive_count": state.positive_count,
                    },
                )

                # Only return verdicts for subjects at CONFIRMED or higher
                if stage in (ThreatStage.CONFIRMED, ThreatStage.ESCALATING, ThreatStage.MITIGATING):
                    confirmed_verdicts.append(verdict)

        # Update clean counts for subjects not detected this cycle
        detected_subjects = fired_subjects
        for subject_id, state in self._subjects.items():
            if subject_id not in detected_subjects and state.stage != ThreatStage.CLEAN:
                state.update(None)

        return confirmed_verdicts

    def get_subject_state(self, subject_id: str) -> SubjectState | None:
        """Get current state for a subject."""
        return self._subjects.get(subject_id)

    def get_all_states(self) -> dict[str, SubjectState]:
        """Get all subject states."""
        return dict(self._subjects)

    def get_active_threats(self) -> list[ThreatVerdict]:
        """Get all currently active (non-clean) threats."""
        threats = []
        for state in self._subjects.values():
            if state.stage != ThreatStage.CLEAN and state.last_verdict is not None:
                threats.append(state.last_verdict)
        return threats

    def reset(self) -> None:
        """Reset all subject states."""
        self._subjects.clear()
