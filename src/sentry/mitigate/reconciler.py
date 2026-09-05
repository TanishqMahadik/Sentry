"""Startup reconciler — aligns mitigation state with ONOS on boot.

On startup, the reconciler:
  1. Reads the audit ledger for all "applied" actions
  2. Checks each against ONOS (via Verifier)
  3. Removes stale rules that survived a crash
  4. Re-freezes baselines for active mitigations (Invariant I9)

This ensures consistent state after a crash or restart.
"""

from __future__ import annotations

import logging

from sentry.collect.window import WindowManager
from sentry.core.models import MitigationAction
from sentry.mitigate.executor import Executor
from sentry.mitigate.ledger import AuditLedger
from sentry.mitigate.payloads import build_payload
from sentry.mitigate.verifier import Verifier

logger = logging.getLogger(__name__)


class Reconciler:
    """Startup reconciliation of mitigation state."""

    def __init__(
        self,
        executor: Executor,
        verifier: Verifier,
        ledger: AuditLedger,
        window_manager: WindowManager,
    ) -> None:
        """Initialize reconciler.

        Args:
            executor: Mitigation executor for cleanup
            verifier: Verifier for read-back checks
            ledger: Audit ledger for historical state
            window_manager: Window manager for baseline freezing
        """
        self.executor = executor
        self.verifier = verifier
        self.ledger = ledger
        self.window_manager = window_manager

    def reconcile(self) -> dict[str, int]:
        """Run startup reconciliation.

        Returns:
            Dict with counts: {"verified": N, "revoked": N, "frozen": N}
        """
        stats = {"verified": 0, "revoked": 0, "frozen": 0}

        entries = self.ledger.get_entries()
        applied_entries = [
            e for e in entries if e.get("status") == "applied"
        ]

        logger.info(
            f"Reconciling {len(applied_entries)} active mitigations from ledger"
        )

        for entry in applied_entries:
            action_id = entry.get("action_id", "")
            device_id = entry.get("device_id", "")
            subject_id = entry.get("subject_id", "")
            stage = entry.get("stage", 0)

            # Build a minimal MitigationAction for verification
            from sentry.core.models import ThreatVerdict
            verdict = ThreatVerdict(
                threat_type=entry.get("threat_type", "unknown"),
                subject_id=subject_id,
                severity=entry.get("severity", "low"),
                confidence=entry.get("confidence", 0.0),
                timestamp=entry.get("timestamp", 0),
                evidence={"device_id": device_id},
            )
            # Reconstruct payload from stage info stored in the ledger
            threat_type = entry.get("threat_type", "unknown")
            try:
                payload = build_payload(stage, device_id, subject_id, threat_type)
            except (ValueError, KeyError):
                payload = {}

            action = MitigationAction(
                action_id=action_id,
                threat_verdict=verdict,
                stage=stage,
                action_type=entry.get("action_type", "unknown"),
                device_id=device_id,
                payload=payload,
                applied_at=entry.get("applied_at", 0),
                expires_at=entry.get("expires_at", 0),
                status="applied",
            )

            # Check if the rule still exists on the switch
            if self.verifier.verify_install(action):
                # Rule exists — check if it should have expired
                import time
                now = int(time.time())
                if now > action.expires_at:
                    # Expired but still on switch — remove it
                    logger.info(
                        f"Revoking stale rule: {action_id}",
                        extra={"device_id": device_id, "subject_id": subject_id},
                    )
                    self.executor.revoke(action)
                    stats["revoked"] += 1
                else:
                    # Rule still valid — track it and freeze baselines
                    self.executor._applied.append(action)
                    self.window_manager.freeze_subject(subject_id)
                    stats["verified"] += 1
                    stats["frozen"] += 1
            else:
                # Rule not found — already removed (crash recovery)
                logger.info(
                    f"Rule not found on switch, marking as expired: {action_id}"
                )
                stats["revoked"] += 1

        logger.info(f"Reconciliation complete: {stats}")
        return stats
