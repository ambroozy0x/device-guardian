"""Abstract base class for operating system authentication monitors.

Provides a unified interface for polling OS-specific authentication
and logon failure events across Windows, Linux, and macOS.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from device_guardian.detection.models import AuthenticationFailureEvent


class BaseAuthenticationMonitor(ABC):
    """Abstract base class defining the contract for OS authentication monitors."""

    @abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Check if the monitor is supported and operational on the current platform.

        Returns:
            Tuple of (is_available: bool, status_message: str).
            If unavailable, status_message contains actionable diagnostic guidance.
        """
        raise NotImplementedError

    @abstractmethod
    def get_source_name(self) -> str:
        """Return the human-readable description of the log source."""
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        """Initialize and bookmark the current log position or timestamp.

        Prevents processing historical events that occurred prior to startup.
        """
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Clean up monitor resources."""
        raise NotImplementedError

    @abstractmethod
    def poll(self) -> list[AuthenticationFailureEvent]:
        """Poll for new authentication failure events since the last poll.

        Returns:
            List of newly detected normalized AuthenticationFailureEvent instances.
        """
        raise NotImplementedError
