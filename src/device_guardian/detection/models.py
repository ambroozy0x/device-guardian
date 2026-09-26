"""Normalized data models and states for Authentication Failure Detection.

Adheres strictly to Phase 3 defensive principles:
- Captures only minimal necessary context (source, type, timestamp, sanitized identifiers).
- Never captures, intercepts, or retains passwords or raw credentials.
- Uses strictly objective and factual terminology.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class DetectionStatus(str, Enum):
    """Operational readiness of an authentication monitor."""

    READY = "READY"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class MonitorState(str, Enum):
    """Lifecycle states of the detection and alert engine."""

    READY = "READY"
    THRESHOLD_REACHED = "THRESHOLD_REACHED"
    ALERT_SENT = "ALERT_SENT"
    COOLDOWN = "COOLDOWN"
    ERROR = "ERROR"


@dataclass
class AuthenticationFailureEvent:
    """Normalized representation of a single operating system authentication failure."""

    timestamp: datetime = field(default_factory=datetime.now)
    platform: str = "Unknown"
    source: str = "Unknown"
    username: str = "Unavailable"
    remote_address: str = "Unavailable"
    authentication_type: str = "Unavailable"
    event_identifier: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Sanitize identifiers and ensure fallback defaults."""
        if not self.username or self.username.strip() in {"-", ""}:
            self.username = "Unavailable"
        else:
            self.username = self.username.strip()

        if not self.remote_address or self.remote_address.strip() in {"-", "", "127.0.0.1", "::1"}:
            if self.authentication_type == "local":
                self.remote_address = "Local Console"
            else:
                self.remote_address = "Unavailable"
        else:
            self.remote_address = self.remote_address.strip()

        if not self.event_identifier:
            self.event_identifier = (
                f"{self.platform}:{self.source}:{self.timestamp.isoformat()}:{self.username}"
            )

    def format_summary(self) -> str:
        """Return an objective, factual summary line of the failure."""
        return (
            f"Authentication failure recorded on {self.platform} "
            f"(Source: {self.source}, Type: {self.authentication_type}, "
            f"User: {self.username}, Remote: {self.remote_address})"
        )
