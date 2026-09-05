"""Tamper-evident hash-chained audit ledger (FR-5).

Append-only JSONL file with SHA-256 hash chaining. Each entry includes
the SHA-256 hash of the previous entry, making the log tamper-evident:
any modification to a past entry breaks the hash chain.

Invariants:
  - Each entry's `prev_hash` equals the SHA-256 of the complete previous entry
  - The first entry has prev_hash = "0" * 64
  - Deleting or reordering entries breaks verification
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

from sentry.core.models import MitigationAction

logger = logging.getLogger(__name__)

_ZERO_HASH = "0" * 64


def _hash_entry(entry: dict[str, Any]) -> str:
    """Compute SHA-256 hash of a ledger entry (deterministic JSON)."""
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLedger:
    """Append-only, hash-chained audit ledger."""

    def __init__(self, filepath: str = "audit_ledger.jsonl") -> None:
        """Initialize ledger.

        Args:
            filepath: Path to the JSONL ledger file
        """
        self.filepath = filepath
        self._last_hash: str | None = None
        self._entry_count = 0

        # If file exists, load the chain state
        if os.path.exists(filepath):
            self._load_chain_state()

    def _load_chain_state(self) -> None:
        """Load the last hash and entry count from existing file."""
        last_hash = _ZERO_HASH
        count = 0
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    last_hash = _hash_entry(entry)
                    count += 1
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Failed to load ledger state: {exc}")
        self._last_hash = last_hash
        self._entry_count = count

    def append_action(self, action: MitigationAction) -> str:
        """Append a mitigation action to the ledger.

        Args:
            action: MitigationAction to record

        Returns:
            SHA-256 hash of the appended entry
        """
        entry = {
            "entry_index": self._entry_count,
            "timestamp": int(time.time()),
            "action_id": action.action_id,
            "stage": action.stage,
            "action_type": action.action_type,
            "device_id": action.device_id,
            "subject_id": action.threat_verdict.subject_id,
            "threat_type": action.threat_verdict.threat_type,
            "severity": action.threat_verdict.severity,
            "confidence": action.threat_verdict.confidence,
            "applied_at": action.applied_at,
            "expires_at": action.expires_at,
            "status": action.status,
            "prev_hash": self._last_hash or _ZERO_HASH,
        }

        entry_hash = _hash_entry(entry)
        entry["hash"] = entry_hash

        # Append to file
        try:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError as exc:
            logger.error(f"Failed to write ledger entry: {exc}")
            raise

        self._last_hash = entry_hash
        self._entry_count += 1

        logger.debug(
            f"Ledger entry appended: {action.action_id}",
            extra={"entry_index": entry["entry_index"], "hash": entry_hash},
        )

        return entry_hash

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the entire hash chain.

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        if not os.path.exists(self.filepath):
            return True, []

        errors: list[str] = []
        prev_hash = _ZERO_HASH
        entry_index = 0

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as exc:
                        errors.append(f"Line {line_num}: invalid JSON: {exc}")
                        continue

                    # Check entry index continuity
                    expected_index = entry_index
                    if entry.get("entry_index") != expected_index:
                        errors.append(
                            f"Line {line_num}: expected entry_index {expected_index}, "
                            f"got {entry.get('entry_index')}"
                        )

                    # Check prev_hash chain
                    stored_prev = entry.get("prev_hash")
                    if stored_prev != prev_hash:
                        errors.append(
                            f"Line {line_num}: prev_hash mismatch. "
                            f"Expected {prev_hash}, got {stored_prev}"
                        )

                    # Verify entry hash (exclude 'hash' field for recompute)
                    stored_hash = entry.get("hash")
                    entry_for_hash = {k: v for k, v in entry.items() if k != "hash"}
                    recomputed = _hash_entry(entry_for_hash)
                    if stored_hash != recomputed:
                        errors.append(
                            f"Line {line_num}: hash mismatch. "
                            f"Expected {recomputed}, got {stored_hash}"
                        )

                    # Update chain state
                    prev_hash = stored_hash or _hash_entry(entry_for_hash)
                    entry_index += 1

        except OSError as exc:
            errors.append(f"Failed to read ledger: {exc}")

        return len(errors) == 0, errors

    def get_entries(self) -> list[dict[str, Any]]:
        """Read all ledger entries."""
        entries: list[dict[str, Any]] = []
        if not os.path.exists(self.filepath):
            return entries

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Failed to read ledger: {exc}")

        return entries

    def get_entry_count(self) -> int:
        """Get number of entries in the ledger."""
        return self._entry_count

    def clear(self) -> None:
        """Clear the ledger (for testing only)."""
        if os.path.exists(self.filepath):
            os.remove(self.filepath)
        self._last_hash = None
        self._entry_count = 0
