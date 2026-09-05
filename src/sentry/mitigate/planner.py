"""Mitigation planner with 5-stage escalation ladder and safety rails.

Decides which mitigation stage to apply based on threat severity,
correlator state, and 8 sequential safety rail checks.

The planner never executes actions directly — it produces MitigationAction
requests for the Executor to carry out (or reject via safety rails).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sentry.core.models import MitigationAction, ThreatVerdict
from sentry.detect.correlator import ThreatStage
from sentry.mitigate.payloads import STAGE_TTLS, build_payload

logger = logging.getLogger(__name__)

# Severity → initial stage mapping
_SEVERITY_INITIAL_STAGE = {
    "low": 0,       # Observe only
    "medium": 1,    # Throttle
    "high": 2,      # Selective Drop
    "critical": 3,  # Quarantine
}

# Stage escalation map
_STAGE_ESCALATION = {
    0: 1,
    1: 2,
    2: 3,
    3: 4,
    4: 4,  # Already at max
}


class SafetyRailError(Exception):
    """Raised when a safety rail check fails."""

    def __init__(self, rail_name: str, reason: str) -> None:
        self.rail_name = rail_name
        self.reason = reason
        super().__init__(f"Safety rail '{rail_name}' failed: {reason}")


class SafetyRails:
    """8 sequential safety rail checks before mitigation."""

    def __init__(
        self,
        max_concurrent_mitigations: int = 10,
        min_confidence: float = 0.5,
        max_stage_for_auto: int = 3,
        allowed_threat_types: set[str] | None = None,
    ) -> None:
        """Initialize safety rails.

        Args:
            max_concurrent_mitigations: Max active mitigations system-wide
            min_confidence: Minimum confidence to allow mitigation
            max_stage_for_auto: Highest stage allowed for automated mitigation
            allowed_threat_types: Set of threat types allowed for auto-mitigation
        """
        self.max_concurrent_mitigations = max_concurrent_mitigations
        self.min_confidence = min_confidence
        self.max_stage_for_auto = max_stage_for_auto
        self.allowed_threat_types = allowed_threat_types or {
            "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD",
            "PORT_SCAN", "FLOW_TABLE_EXHAUSTION",
            "ARP_SPOOFING", "CP_SATURATION",
            # Note: TOPOLOGY_POISONING excluded (alert-only per FR-1)
        }

    def check(
        self,
        verdict: ThreatVerdict,
        proposed_stage: int,
        active_mitigations: dict[str, MitigationAction],
        current_stage: int = 0,
    ) -> list[str]:
        """Run all 8 safety rail checks.

        Returns:
            List of failure reasons (empty = all passed)
        """
        failures: list[str] = []

        # Rail 1: Confidence threshold
        if verdict.confidence < self.min_confidence:
            failures.append(
                f"Confidence {verdict.confidence:.2f} < minimum {self.min_confidence:.2f}"
            )

        # Rail 2: Threat type allowed
        if verdict.threat_type not in self.allowed_threat_types:
            failures.append(
                f"Threat type '{verdict.threat_type}' not in allowed set"
            )

        # Rail 3: Max concurrent mitigations
        if len(active_mitigations) >= self.max_concurrent_mitigations:
            failures.append(
                f"Max concurrent mitigations ({self.max_concurrent_mitigations}) reached"
            )

        # Rail 4: Max automated stage
        if proposed_stage > self.max_stage_for_auto:
            failures.append(
                f"Stage {proposed_stage} exceeds max automated stage {self.max_stage_for_auto}"
            )

        # Rail 5: Stage escalation validity (must go up by exactly 1)
        if proposed_stage > current_stage + 1:
            failures.append(
                f"Cannot skip stages: {current_stage} -> {proposed_stage}"
            )

        # Rail 6: No escalation during frozen baseline (Invariant I9)
        # Checked externally by caller — here we just validate the subject
        # isn't already being mitigated at the same or higher stage
        subject_id = verdict.subject_id
        if subject_id in active_mitigations:
            existing = active_mitigations[subject_id]
            if existing.stage >= proposed_stage:
                failures.append(
                    f"Subject {subject_id} already mitigated at stage {existing.stage}"
                )

        # Rail 7: Future timestamp sanity
        now = int(time.time())
        if verdict.timestamp > now + 300:
            failures.append(
                f"Verdict timestamp {verdict.timestamp} is more than 5 minutes in the future"
            )

        # Rail 8: Subject ID non-empty
        if not verdict.subject_id or verdict.subject_id.strip() == "":
            failures.append("Subject ID is empty")

        return failures


class Planner:
    """Mitigation planner with escalation ladder and safety rails."""

    def __init__(
        self,
        safety_rails: SafetyRails | None = None,
    ) -> None:
        """Initialize planner.

        Args:
            safety_rails: Safety rail checks instance
        """
        self.safety_rails = safety_rails or SafetyRails()
        self._action_counter = 0

    def _next_action_id(self) -> str:
        """Generate next unique action ID."""
        self._action_counter += 1
        return f"mitigation-{self._action_counter:06d}"

    def plan_action(
        self,
        verdict: ThreatVerdict,
        threat_stage: ThreatStage,
        current_stage: int,
        active_mitigations: dict[str, MitigationAction],
    ) -> MitigationAction | None:
        """Plan a mitigation action for a confirmed threat.

        Args:
            verdict: The threat verdict
            threat_stage: Current correlator stage for the subject
            current_stage: Current mitigation stage for this subject (0-4)
            active_mitigations: Map of subject_id → current MitigationAction

        Returns:
            MitigationAction if action should be taken, None if no action needed
        """
        # Determine proposed stage based on severity
        severity_stage = _SEVERITY_INITIAL_STAGE.get(verdict.severity, 0)

        # Use the higher of severity-based and current stage + 1
        proposed_stage = max(severity_stage, current_stage + 1)

        # Cap at 4
        proposed_stage = min(proposed_stage, 4)

        # Topology poisoning is alert-only — never escalate beyond observe
        if verdict.threat_type == "TOPOLOGY_POISONING":
            logger.info(
                f"Topology poisoning detected — alert-only, no mitigation",
                extra={"subject": verdict.subject_id},
            )
            return None

        # Stage 0 (observe) doesn't install any rules
        if proposed_stage == 0:
            logger.info(
                f"Observe stage for {verdict.subject_id}",
                extra={"threat_type": verdict.threat_type},
            )
            return None

        # Run safety rails
        failures = self.safety_rails.check(
            verdict, proposed_stage, active_mitigations, current_stage
        )

        if failures:
            logger.warning(
                f"Safety rails rejected mitigation for {verdict.subject_id}",
                extra={"failures": failures, "proposed_stage": proposed_stage},
            )
            return None

        # Build the OpenFlow payload
        now = int(time.time())
        ttl = STAGE_TTLS.get(proposed_stage, 60)
        payload = build_payload(
            stage=proposed_stage,
            device_id=verdict.evidence.get("device_id", "of:0000000000000001"),
            subject_id=verdict.subject_id,
            threat_type=verdict.threat_type,
        )

        action = MitigationAction(
            action_id=self._next_action_id(),
            threat_verdict=verdict,
            stage=proposed_stage,
            action_type=payload.get("action", "unknown"),
            device_id=payload.get("device_id", ""),
            payload=payload,
            applied_at=now,
            expires_at=now + ttl,
            status="pending",
        )

        logger.info(
            f"Planned mitigation: {action.action_id}",
            extra={
                "subject": verdict.subject_id,
                "stage": proposed_stage,
                "threat_type": verdict.threat_type,
                "ttl": ttl,
            },
        )

        return action
