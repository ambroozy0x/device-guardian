"""Base OS startup manager abstraction for Device Guardian (Phase 5).

Defines the contract for platform-specific startup integration:
- Safe, user-controlled, fully reversible.
- Operates under standard user privileges (no elevated admin rights).
- Transparent state inspection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import sys
from typing import Any, Optional

from device_guardian.runtime.paths import ApplicationPaths


class BaseStartupManager(ABC):
    """Abstract base class for operating system startup integration."""

    @abstractmethod
    def is_supported(self) -> bool:
        """Check if startup management is supported on this platform."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if Device Guardian is currently configured to launch at startup."""
        pass

    @abstractmethod
    def enable(self, custom_command: Optional[str] = None) -> bool:
        """Configure Device Guardian to start automatically on user login.

        Args:
            custom_command: Optional command string to override default invocation.

        Returns:
            True if startup was enabled successfully, False otherwise.
        """
        pass

    @abstractmethod
    def disable(self) -> bool:
        """Remove Device Guardian from startup configuration.

        Returns:
            True if startup was removed successfully, False otherwise.
        """
        pass

    @abstractmethod
    def get_command(self) -> Optional[str]:
        """Return the command currently registered for startup, if any."""
        pass

    @abstractmethod
    def get_details(self) -> dict[str, Any]:
        """Return diagnostic details regarding startup registration."""
        pass

    @classmethod
    def validate_startup_command(cls, command: str) -> bool:
        """Validate that startup command is safe, free of shell metacharacters, and well-formed."""
        if not command or not command.strip():
            return False
        forbidden_chars = {"&", "|", ";", ">", "<", "`", "$", "\n", "\r"}
        if any(char in command for char in forbidden_chars):
            return False

        try:
            import shlex
            try:
                parts = shlex.split(command, posix=False)
            except Exception:
                parts = shlex.split(command, posix=True)
        except Exception:
            return False

        if not parts:
            return False

        from pathlib import Path
        exe_str = parts[0].strip('"\'; ')
        exe_path = Path(exe_str)
        if exe_path.exists():
            from device_guardian.security.filesystem import is_symlink_or_reparse_point
            if is_symlink_or_reparse_point(exe_path):
                return False
        return True

    @staticmethod
    def get_default_command() -> str:
        """Construct the standard launcher command for Device Guardian."""
        if ApplicationPaths.is_frozen():
            return f'"{sys.executable}" --start'
        return f'"{sys.executable}" -m device_guardian.main --start'
