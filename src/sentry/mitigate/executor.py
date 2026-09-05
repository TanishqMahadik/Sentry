"""Mitigation executor — applies MitigationActions to the data plane.

Phase 5 runs in dry-run mode: actions are validated and logged but
never actually sent to ONOS. This lets us verify payload construction
and the audit trail without touching a live network.

In Phase 6, a live Executor will replace this with real ONOS calls.
"""

from __future__ import annotations

import logging
import time

from sentry.core.models import MitigationAction
from sentry.onos.client import OnosClient

logger = logging.getLogger(__name__)


class Executor:
    """Executes mitigation actions in dry-run or live mode."""

    def __init__(self, client: OnosClient, dry_run: bool = True) -> None:
        """Initialize executor.

        Args:
            client: ONOS client for live execution
            dry_run: If True, log actions without sending to ONOS
        """
        self.client = client
        self.dry_run = dry_run
        self._applied: list[MitigationAction] = []

    def apply(self, action: MitigationAction) -> bool:
        """Apply a mitigation action.

        Args:
            action: MitigationAction to apply

        Returns:
            True if applied successfully (or logged in dry-run), False on failure
        """
        now = int(time.time())
        if now > action.expires_at:
            logger.warning(
                f"Action {action.action_id} already expired, refusing to apply",
                extra={"expires_at": action.expires_at},
            )
            return False

        if self.dry_run:
            logger.info(
                f"[DRY-RUN] Would apply mitigation: {action.action_id}",
                extra={
                    "stage": action.stage,
                    "action_type": action.action_type,
                    "device_id": action.device_id,
                    "subject_id": action.threat_verdict.subject_id,
                    "threat_type": action.threat_verdict.threat_type,
                },
            )
            action.status = "applied"
            self._applied.append(action)
            return True

        # Live execution (Phase 6)
        try:
            success = self._execute_live(action)
            if success:
                action.status = "applied"
                self._applied.append(action)
            else:
                action.status = "failed"
            return success
        except Exception as exc:  # noqa: BLE001
            logger.exception(f"Live execution failed for {action.action_id}: {exc}")
            action.status = "failed"
            return False

    def _execute_live(self, action: MitigationAction) -> bool:
        """Execute a mitigation action against live ONOS (Phase 6)."""
        payload = action.payload
        action_type = action.action_type

        if action_type == "install_flow":
            self.client.install_flow(
                device_id=action.device_id,
                flow_rule=payload.get("flow_rule", {}),
            )
            return True
        elif action_type == "install_meter":
            logger.info(f"Installing meter on {action.device_id}")
            # Phase 6: install meter via ONOS REST
            return True
        elif action_type == "disable_port":
            logger.info(f"Disabling port on {action.device_id}")
            # Phase 6: disable port via ONOS REST
            return True

        logger.warning(f"Unknown action type: {action_type}")
        return False

    def revoke(self, action: MitigationAction) -> bool:
        """Revoke a previously applied mitigation action.

        Args:
            action: MitigationAction to revoke

        Returns:
            True if revoked successfully, False otherwise
        """
        if action.status != "applied":
            logger.warning(
                f"Action {action.action_id} not in 'applied' state, cannot revoke",
                extra={"status": action.status},
            )
            return False

        if self.dry_run:
            logger.info(
                f"[DRY-RUN] Would revoke mitigation: {action.action_id}",
                extra={"stage": action.stage},
            )
            action.status = "revoked"
            return True

        # Live revocation (Phase 6)
        try:
            self.client.remove_flow(
                device_id=action.device_id,
                flow_id=action.action_id,
            )
            action.status = "revoked"
            return True
        except Exception as exc:  # noqa: BLE001
            logger.exception(f"Live revocation failed for {action.action_id}: {exc}")
            return False

    def get_applied_actions(self) -> list[MitigationAction]:
        """Get list of all applied actions."""
        return list(self._applied)

    def expire_expired_actions(self) -> list[MitigationAction]:
        """Mark any applied actions past their TTL as expired.

        Returns:
            List of actions that were newly expired
        """
        now = int(time.time())
        expired: list[MitigationAction] = []
        for action in self._applied:
            if action.status == "applied" and now > action.expires_at:
                action.status = "expired"
                expired.append(action)
                logger.info(
                    f"Action {action.action_id} expired (TTL)",
                    extra={"expires_at": action.expires_at},
                )
        return expired
