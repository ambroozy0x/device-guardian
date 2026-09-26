"""Structured security event auditing for Device Guardian (Phase 9).

Provides deterministic, structured security audit events:
- Audit trail for security-relevant occurrences (validation failures, signature
  rejections, lock conflicts, path violations).
- Strictly scrubs all sensitive data (passwords, tokens, chat IDs) before recording.
- Local-only logging; absolutely NO telemetry or remote transmission.
- Never generates arbitrary risk or threat scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.security.redactor import get_redactor

logger = get_logger("security.events")


class SecurityEventType(str, Enum):
    """Categorical security event types for local auditing."""

    SECURITY_CONFIG_INVALID = "SECURITY_CONFIG_INVALID"
    SECURITY_SECRETSTORE_FAILURE = "SECURITY_SECRETSTORE_FAILURE"
    SECURITY_CONTROL_REJECTED = "SECURITY_CONTROL_REJECTED"
    SECURITY_LOCK_CONFLICT = "SECURITY_LOCK_CONFLICT"
    SECURITY_UPDATE_REJECTED = "SECURITY_UPDATE_REJECTED"
    SECURITY_UPDATE_SIGNATURE_FAILED = "SECURITY_UPDATE_SIGNATURE_FAILED"
    SECURITY_UPDATE_HASH_FAILED = "SECURITY_UPDATE_HASH_FAILED"
    SECURITY_PATH_REJECTED = "SECURITY_PATH_REJECTED"
    SECURITY_ARCHIVE_REJECTED = "SECURITY_ARCHIVE_REJECTED"
    SECURITY_RECOVERY_TRIGGERED = "SECURITY_RECOVERY_TRIGGERED"
    SECURITY_INTEGRITY_CHECK_FAILED = "SECURITY_INTEGRITY_CHECK_FAILED"

    # Phase 12 Lifecycle & Installer Events
    INSTALL_STARTED = "INSTALL_STARTED"
    INSTALL_VERIFIED = "INSTALL_VERIFIED"
    INSTALL_COMPLETED = "INSTALL_COMPLETED"
    INSTALL_FAILED = "INSTALL_FAILED"
    INSTALL_ROLLBACK = "INSTALL_ROLLBACK"
    UPGRADE_STARTED = "UPGRADE_STARTED"
    UPGRADE_COMPLETED = "UPGRADE_COMPLETED"
    UPGRADE_FAILED = "UPGRADE_FAILED"
    MIGRATION_STARTED = "MIGRATION_STARTED"
    MIGRATION_COMPLETED = "MIGRATION_COMPLETED"
    MIGRATION_FAILED = "MIGRATION_FAILED"
    REPAIR_STARTED = "REPAIR_STARTED"
    REPAIR_COMPLETED = "REPAIR_COMPLETED"
    UNINSTALL_STARTED = "UNINSTALL_STARTED"
    UNINSTALL_COMPLETED = "UNINSTALL_COMPLETED"
    USER_DATA_DELETION_CONFIRMED = "USER_DATA_DELETION_CONFIRMED"


@dataclass
class SecurityAuditEvent:
    """An immutable, sanitized security audit record."""

    event_type: SecurityEventType
    subsystem: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "WARN"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        """Sanitize message and details to ensure zero credential leakage."""
        redactor = get_redactor()
        self.message = redactor.redact(self.message)
        if self.details:
            self.details = redactor.redact_dict(self.details)

    def to_dict(self) -> dict[str, Any]:
        """Convert to sanitized dictionary."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "subsystem": self.subsystem,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }

    def to_json(self) -> str:
        """Serialize to compact JSON string."""
        return json.dumps(self.to_dict())


class SecurityAuditLogger:
    """In-memory and file-based structured security audit trail."""

    _instance: Optional[SecurityAuditLogger] = None

    def __init__(self) -> None:
        self._history: list[SecurityAuditEvent] = []
        self._max_history: int = 500

    @classmethod
    def get_instance(cls) -> SecurityAuditLogger:
        """Get the singleton audit logger instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def log_event(
        self,
        event_type: SecurityEventType,
        subsystem: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
        severity: str = "WARN",
    ) -> SecurityAuditEvent:
        """Record and log a structured security audit event.

        Args:
            event_type: Type of security occurrence.
            subsystem: Name of component raising the event.
            message: Factual, sanitized description.
            details: Optional dictionary with operational context.
            severity: Event severity ('INFO', 'WARN', 'ERROR').

        Returns:
            The created and sanitized SecurityAuditEvent.
        """
        event = SecurityAuditEvent(
            event_type=event_type,
            subsystem=subsystem,
            message=message,
            details=details or {},
            severity=severity.upper(),
        )

        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        # Log via standard logging system with security prefix
        log_msg = f"[{event.event_type.value}] ({event.subsystem}): {event.message}"
        if event.severity == "ERROR":
            logger.error(log_msg)
        elif event.severity == "INFO":
            logger.info(log_msg)
        else:
            logger.warning(log_msg)

        return event

    def get_recent_events(
        self,
        limit: int = 50,
        event_type: Optional[SecurityEventType] = None,
    ) -> list[SecurityAuditEvent]:
        """Retrieve recent security audit events."""
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def clear(self) -> None:
        """Clear recorded history (primarily for tests)."""
        self._history.clear()


def log_security_event(
    event_type: SecurityEventType,
    subsystem: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
    severity: str = "WARN",
) -> SecurityAuditEvent:
    """Convenience helper to record a structured security audit event."""
    return SecurityAuditLogger.get_instance().log_event(
        event_type=event_type,
        subsystem=subsystem,
        message=message,
        details=details,
        severity=severity,
    )
