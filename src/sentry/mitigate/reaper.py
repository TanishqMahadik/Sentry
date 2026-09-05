"""Reaper thread — monitors and expires stale mitigation actions.

Runs in the background, periodically checking all applied actions
against their TTL. When a mitigation expires, the Reaper:
  1. Marks it as "expired" in the ledger
  2. Removes the associated OpenFlow rule from ONOS
  3. Unfreezes the subject's baselines (Invariant I9)

This ensures fail-open safety (NFR-1): all rules have hard timeouts
and the Reaper provides a software-level safety net.
"""

from __future__ import annotations

import logging
import threading
import time

from sentry.collect.window import WindowManager
from sentry.core.models import MitigationAction
from sentry.mitigate.executor import Executor
from sentry.mitigate.ledger import AuditLedger

logger = logging.getLogger(__name__)


class Reaper:
    """Background thread that expires stale mitigation actions."""

    def __init__(
        self,
        executor: Executor,
        ledger: AuditLedger,
        window_manager: WindowManager,
        check_interval: int = 10,
    ) -> None:
        """Initialize reaper.

        Args:
            executor: Mitigation executor for rule removal
            ledger: Audit ledger for recording expirations
            window_manager: Window manager for unfreezing baselines
            check_interval: Seconds between expiry checks
        """
        self.executor = executor
        self.ledger = ledger
        self.window_manager = window_manager
        self.check_interval = check_interval
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._active_actions: dict[str, MitigationAction] = {}
        self._lock = threading.Lock()

    def register_action(self, action: MitigationAction) -> None:
        """Register an active mitigation action for monitoring.

        Args:
            action: Applied MitigationAction to monitor
        """
        with self._lock:
            self._active_actions[action.action_id] = action
            logger.debug(f"Reaper registered action: {action.action_id}")

    def start(self) -> None:
        """Start the reaper background thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Reaper already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="sentry-reaper",
            daemon=True,
        )
        self._thread.start()
        logger.info("Reaper thread started")

    def stop(self) -> None:
        """Stop the reaper background thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.check_interval + 5)
        logger.info("Reaper thread stopped")

    def _run_loop(self) -> None:
        """Main reaper loop."""
        while not self._stop_event.is_set():
            try:
                self._check_and_expire()
            except Exception:  # noqa: BLE001
                logger.exception("Reaper check failed")
            self._stop_event.wait(self.check_interval)

    def _check_and_expire(self) -> list[MitigationAction]:
        """Check all registered actions and expire stale ones.

        Returns:
            List of actions that were newly expired
        """
        now = int(time.time())
        expired: list[MitigationAction] = []

        with self._lock:
            for action_id, action in list(self._active_actions.items()):
                if action.status != "applied":
                    continue

                if now > action.expires_at:
                    # Expire the action
                    action.status = "expired"
                    expired.append(action)
                    logger.info(
                        f"Reaper expiring action: {action_id}",
                        extra={
                            "stage": action.stage,
                            "subject": action.threat_verdict.subject_id,
                            "expired_after": now - action.applied_at,
                        },
                    )

                    # Remove from active tracking
                    del self._active_actions[action_id]

                    # Unfreeze baselines (Invariant I9)
                    subject_id = action.threat_verdict.subject_id
                    self.window_manager.unfreeze_subject(subject_id)
                    logger.debug(f"Unfroze baselines for {subject_id}")

        return expired

    def get_active_count(self) -> int:
        """Get number of active mitigations being tracked."""
        with self._lock:
            return len(self._active_actions)

    def get_active_actions(self) -> list[MitigationAction]:
        """Get list of all active (non-expired) actions."""
        with self._lock:
            return [
                a for a in self._active_actions.values()
                if a.status == "applied"
            ]
