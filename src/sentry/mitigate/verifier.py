"""Mitigation verifier — read-back validation of installed rules.

Verifies that OpenFlow rules were actually installed on the switch
by querying ONOS for the flow table and confirming the rule exists.

This closes the feedback loop: Planner → Executor → Verifier → Ledger.
"""

from __future__ import annotations

import logging

from sentry.core.models import MitigationAction
from sentry.onos.client import OnosClient

logger = logging.getLogger(__name__)


class Verifier:
    """Read-back verifier for installed mitigation rules."""

    def __init__(self, client: OnosClient) -> None:
        """Initialize verifier.

        Args:
            client: ONOS client for flow table queries
        """
        self.client = client

    def verify_install(self, action: MitigationAction) -> bool:
        """Verify that a mitigation flow rule is installed on the device.

        Args:
            action: The MitigationAction to verify

        Returns:
            True if the rule is confirmed installed, False otherwise
        """
        if action.action_type not in ("install_flow", "install_meter"):
            # Port disable and observe don't have flow rules to verify
            logger.debug(
                f"Skipping verification for action_type={action.action_type}"
            )
            return True

        try:
            flows = self.client.get_flows(action.device_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Failed to read flows from {action.device_id}: {exc}"
            )
            return False

        # Search for a matching flow by priority and IP_SRC criteria
        target_priority = action.payload.get("flow_rule", {}).get("priority", 0)
        target_ip = action.threat_verdict.subject_id

        for flow in flows:
            if flow.priority == target_priority:
                criteria = flow.selector.get("criteria", [])
                for criterion in criteria:
                    if (
                        criterion.get("type") == "IP_SRC"
                        and criterion.get("ip") == target_ip
                    ):
                        logger.info(
                            f"Verified install for {action.action_id}",
                            extra={
                                "flow_id": flow.flow_id,
                                "device_id": action.device_id,
                            },
                        )
                        return True

        logger.warning(
            f"Verification failed for {action.action_id}: rule not found",
            extra={
                "device_id": action.device_id,
                "subject_id": target_ip,
                "priority": target_priority,
            },
        )
        return False

    def verify_removal(self, action: MitigationAction) -> bool:
        """Verify that a mitigation flow rule was removed from the device.

        Args:
            action: The MitigationAction that should have been removed

        Returns:
            True if the rule is confirmed removed, False otherwise
        """
        try:
            flows = self.client.get_flows(action.device_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Failed to read flows from {action.device_id}: {exc}"
            )
            return False

        target_priority = action.payload.get("flow_rule", {}).get("priority", 0)
        target_ip = action.threat_verdict.subject_id

        for flow in flows:
            if flow.priority == target_priority:
                criteria = flow.selector.get("criteria", [])
                for criterion in criteria:
                    if (
                        criterion.get("type") == "IP_SRC"
                        and criterion.get("ip") == target_ip
                    ):
                        logger.warning(
                            f"Rule still exists after removal: {action.action_id}",
                            extra={"flow_id": flow.flow_id},
                        )
                        return False

        logger.info(f"Verified removal for {action.action_id}")
        return True
