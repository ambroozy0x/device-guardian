"""Lifecycle models and data structures for Device Guardian (Phase 12).

Defines deterministic lifecycle states, installation metadata, and structured
records for installation, upgrade, migration, repair, and uninstallation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional
import uuid

from device_guardian.logger import get_logger
from device_guardian.recovery.persistence import AtomicPersistence
from device_guardian.runtime.paths import ApplicationPaths

logger = get_logger("lifecycle.models")


class LifecycleState(str, Enum):
    """Deterministic finite-state machine states for lifecycle operations."""

    IDLE = "IDLE"
    VERIFYING = "VERIFYING"
    BACKING_UP = "BACKING_UP"
    STAGING = "STAGING"
    INSTALLING = "INSTALLING"
    MIGRATING = "MIGRATING"
    VALIDATING = "VALIDATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"


class LifecycleOperationType(str, Enum):
    """Types of lifecycle operations supported by the installer subsystem."""

    INSTALL = "INSTALL"
    UPGRADE = "UPGRADE"
    MIGRATE = "MIGRATE"
    REPAIR = "REPAIR"
    UNINSTALL = "UNINSTALL"


@dataclass
class LifecycleRecord:
    """Atomic, persistent state record for an ongoing or completed lifecycle operation."""

    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operation_type: LifecycleOperationType = LifecycleOperationType.INSTALL
    state: LifecycleState = LifecycleState.IDLE
    previous_state: LifecycleState = LifecycleState.IDLE
    version: str = "0.1.0"
    target_version: Optional[str] = None
    backup_path: Optional[str] = None
    install_path: Optional[str] = None
    error_message: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_in_progress(self) -> bool:
        """True if the operation is in an active non-terminal state."""
        return self.state in {
            LifecycleState.VERIFYING,
            LifecycleState.BACKING_UP,
            LifecycleState.STAGING,
            LifecycleState.INSTALLING,
            LifecycleState.MIGRATING,
            LifecycleState.VALIDATING,
            LifecycleState.ROLLING_BACK,
        }

    @property
    def is_complete(self) -> bool:
        """True if the operation completed successfully."""
        return self.state == LifecycleState.COMPLETED

    def transition_to(
        self,
        new_state: LifecycleState,
        error_message: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Advance the FSM state, update timestamps, and persist atomically."""
        logger.info(
            "Lifecycle FSM transition: [%s] %s -> %s",
            self.operation_type.value,
            self.state.value,
            new_state.value,
        )
        self.previous_state = self.state
        self.state = new_state
        if error_message is not None:
            self.error_message = error_message
        if details is not None:
            self.details.update(details)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.save()

    def to_dict(self) -> dict[str, Any]:
        """Convert record to sanitized dictionary for serialization."""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type.value,
            "state": self.state.value,
            "previous_state": self.previous_state.value,
            "version": self.version,
            "target_version": self.target_version,
            "backup_path": self.backup_path,
            "install_path": self.install_path,
            "error_message": self.error_message,
            "details": self.details,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LifecycleRecord:
        """Construct record from dictionary."""
        op_type = LifecycleOperationType(data.get("operation_type", LifecycleOperationType.INSTALL.value))
        state = LifecycleState(data.get("state", LifecycleState.IDLE.value))
        prev_state = LifecycleState(data.get("previous_state", LifecycleState.IDLE.value))
        return cls(
            operation_id=data.get("operation_id", str(uuid.uuid4())),
            operation_type=op_type,
            state=state,
            previous_state=prev_state,
            version=data.get("version", "0.1.0"),
            target_version=data.get("target_version"),
            backup_path=data.get("backup_path"),
            install_path=data.get("install_path"),
            error_message=data.get("error_message"),
            details=data.get("details", {}),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )

    def save(self, target_file: Optional[Path] = None) -> bool:
        """Atomically persist record to disk."""
        target_path = target_file or ApplicationPaths.get_lifecycle_transaction_file_path()
        try:
            AtomicPersistence.atomic_write_json(target_path, self.to_dict(), backup=True)
            return True
        except Exception as exc:
            logger.error("Failed to save lifecycle record to %s: %s", target_path, exc)
            return False

    @classmethod
    def load(cls, target_file: Optional[Path] = None) -> Optional[LifecycleRecord]:
        """Load record from disk with .bak fallback on corruption."""
        target_path = target_file or ApplicationPaths.get_lifecycle_transaction_file_path()
        data, recovered, err = AtomicPersistence.safe_read_json(target_path)
        if data and isinstance(data, dict):
            try:
                return cls.from_dict(data)
            except Exception as exc:
                logger.warning("Failed to construct LifecycleRecord from data: %s", exc)
                return None
        return None


@dataclass
class InstallationMetadata:
    """Persistent metadata describing the installed application deployment."""

    version: str
    install_path: str
    user_data_path: str
    installed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_upgraded_at: Optional[str] = None
    schema_version: int = 1
    platform: str = ""
    architecture: str = ""
    is_frozen: bool = False
    executable_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata to dictionary."""
        return {
            "version": self.version,
            "install_path": self.install_path,
            "user_data_path": self.user_data_path,
            "installed_at": self.installed_at,
            "last_upgraded_at": self.last_upgraded_at,
            "schema_version": self.schema_version,
            "platform": self.platform,
            "architecture": self.architecture,
            "is_frozen": self.is_frozen,
            "executable_hash": self.executable_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InstallationMetadata:
        """Construct InstallationMetadata from dictionary."""
        return cls(
            version=data.get("version", "0.1.0"),
            install_path=data.get("install_path", ""),
            user_data_path=data.get("user_data_path", ""),
            installed_at=data.get("installed_at", datetime.now(timezone.utc).isoformat()),
            last_upgraded_at=data.get("last_upgraded_at"),
            schema_version=int(data.get("schema_version", 1)),
            platform=data.get("platform", ""),
            architecture=data.get("architecture", ""),
            is_frozen=bool(data.get("is_frozen", False)),
            executable_hash=data.get("executable_hash"),
        )

    def save(self, target_file: Optional[Path] = None) -> bool:
        """Atomically persist metadata to disk."""
        target_path = target_file or ApplicationPaths.get_install_metadata_file_path()
        try:
            AtomicPersistence.atomic_write_json(target_path, self.to_dict(), backup=True)
            return True
        except Exception as exc:
            logger.error("Failed to save installation metadata to %s: %s", target_path, exc)
            return False

    @classmethod
    def load(cls, target_file: Optional[Path] = None) -> Optional[InstallationMetadata]:
        """Load installation metadata from disk with .bak fallback."""
        target_path = target_file or ApplicationPaths.get_install_metadata_file_path()
        data, recovered, err = AtomicPersistence.safe_read_json(target_path)
        if data and isinstance(data, dict):
            try:
                return cls.from_dict(data)
            except Exception as exc:
                logger.warning("Failed to construct InstallationMetadata: %s", exc)
                return None
        return None


@dataclass
class InstallationHealth:
    """Structured assessment of installation integrity and readiness."""

    is_installed: bool
    version: str
    binary_path: str
    binary_exists: bool
    binary_valid: bool
    metadata_exists: bool
    metadata_valid: bool
    data_dir_valid: bool
    config_present: bool
    secrets_present: bool
    status: str  # HEALTHY, DEGRADED, FAILED, NOT_CONFIGURED
    message: str
    issues: list[str] = field(default_factory=list)
