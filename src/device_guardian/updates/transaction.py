"""Atomic update transaction state machine and crash recovery for Device Guardian (Phase 7).

Manages multi-step update state persistence to guarantee deterministic rollback
and prevent corrupted or partial installations across process termination or crashes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.runtime.paths import ApplicationPaths

logger = get_logger("updates.transaction")


class TransactionState(str, Enum):
    """Lifecycle states of an update deployment transaction."""

    IDLE = "IDLE"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    BACKING_UP = "BACKING_UP"
    STAGING = "STAGING"
    INSTALLING = "INSTALLING"
    VALIDATING = "VALIDATING"
    COMPLETED = "COMPLETED"

    # Terminal failure states
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    BACKUP_FAILED = "BACKUP_FAILED"
    STAGING_FAILED = "STAGING_FAILED"
    INSTALL_FAILED = "INSTALL_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class UpdateTransaction:
    """Persistent state record for an update deployment transaction."""

    state: TransactionState = TransactionState.IDLE
    target_version: Optional[str] = None
    previous_version: Optional[str] = None
    release_id: Optional[str] = None
    package_path: Optional[str] = None
    backup_path: Optional[str] = None
    staging_path: Optional[str] = None
    target_executable_path: Optional[str] = None
    error_message: Optional[str] = None
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_in_progress(self) -> bool:
        """True if the transaction is in an active, non-terminal state."""
        return self.state in {
            TransactionState.VERIFYING,
            TransactionState.VERIFIED,
            TransactionState.BACKING_UP,
            TransactionState.STAGING,
            TransactionState.INSTALLING,
            TransactionState.VALIDATING,
        }

    @property
    def is_complete(self) -> bool:
        """True if the transaction successfully concluded."""
        return self.state == TransactionState.COMPLETED

    def transition_to(self, new_state: TransactionState, error_message: Optional[str] = None) -> None:
        """Transition transaction to a new state and persist atomically."""
        logger.info("Update transaction state transition: %s -> %s", self.state.value, new_state.value)
        self.state = new_state
        if error_message:
            self.error_message = error_message
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.save()

    def save(self) -> None:
        """Persist transaction record atomically to disk."""
        target_file = ApplicationPaths.get_update_transaction_file_path()
        target_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state": self.state.value,
            "target_version": self.target_version,
            "previous_version": self.previous_version,
            "release_id": self.release_id,
            "package_path": self.package_path,
            "backup_path": self.backup_path,
            "staging_path": self.staging_path,
            "target_executable_path": self.target_executable_path,
            "error_message": self.error_message,
            "updated_at": self.updated_at,
        }
        from device_guardian.recovery.persistence import AtomicPersistence
        AtomicPersistence.atomic_write_json(target_file, data, backup=True)

    @classmethod
    def load(cls) -> UpdateTransaction:
        """Load the active or most recent transaction record from disk with corruption recovery."""
        target_file = ApplicationPaths.get_update_transaction_file_path()
        from device_guardian.recovery.persistence import AtomicPersistence
        data, recovered, err = AtomicPersistence.safe_read_json(
            target_file,
            default={"state": TransactionState.IDLE.value},
            allow_backup_fallback=True,
        )
        try:
            raw_state = data.get("state", TransactionState.IDLE.value) if isinstance(data, dict) else TransactionState.IDLE.value
            state = TransactionState(raw_state)
        except ValueError:
            state = TransactionState.IDLE

        error_msg = data.get("error_message") if isinstance(data, dict) else None
        if err and not recovered:
            error_msg = f"Transaction file corruption recovered: {err}"

        return cls(
            state=state,
            target_version=data.get("target_version") if isinstance(data, dict) else None,
            previous_version=data.get("previous_version") if isinstance(data, dict) else None,
            release_id=data.get("release_id") if isinstance(data, dict) else None,
            package_path=data.get("package_path") if isinstance(data, dict) else None,
            backup_path=data.get("backup_path") if isinstance(data, dict) else None,
            staging_path=data.get("staging_path") if isinstance(data, dict) else None,
            target_executable_path=data.get("target_executable_path") if isinstance(data, dict) else None,
            error_message=error_msg,
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()) if isinstance(data, dict) else datetime.now(timezone.utc).isoformat(),
        )


def check_and_recover_interrupted_transaction() -> dict[str, Any]:
    """Inspect and safely recover from interrupted update transactions at startup.

    Returns:
        Structured recovery status dictionary with keys: 'status', 'action', 'message'.
    """
    txn = UpdateTransaction.load()
    if not txn.is_in_progress:
        return {
            "status": "clean",
            "action": "none",
            "message": "No active or interrupted transactions.",
        }

    logger.warning("Detected interrupted update transaction in state: %s", txn.state.value)
    notice = f"Notice: Detected interrupted update transaction ({txn.state.value}) from previous run."

    # If an update was interrupted during installation or validation, flag rollback requirement
    if txn.state in {TransactionState.INSTALLING, TransactionState.VALIDATING}:
        txn.transition_to(
            TransactionState.ROLLBACK_REQUIRED,
            error_message="Installation was interrupted unexpectedly before validation completed.",
        )
        return {
            "status": "interrupted",
            "action": "rollback_required",
            "message": notice + " System flagged for verification or rollback.",
        }
    else:
        # Interrupted during verification, backup, or staging -> transition to failed without modifying installed binary
        txn.transition_to(
            TransactionState.INSTALL_FAILED,
            error_message=f"Update process was interrupted during {txn.state.value} phase.",
        )
        return {
            "status": "interrupted",
            "action": "staging_aborted",
            "message": notice + " Interrupted staging was aborted. Installed binary remains unmodified.",
        }
