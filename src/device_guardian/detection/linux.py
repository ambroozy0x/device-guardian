"""Linux authentication log monitor.

Monitors standard Linux authentication log locations (/var/log/auth.log,
/var/log/secure) for failed authentication attempts (PAM, local login, SSH).
Adheres strictly to Phase 3 privacy guidelines:
- Extracts only usernames, remote IPs, timestamps, and service names.
- Never captures, logs, or stores credentials.
"""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import platform
import re
from typing import Optional

from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.logger import get_logger

logger = get_logger("detection.linux")

STANDARD_LOG_PATHS = [
    Path("/var/log/auth.log"),  # Debian, Ubuntu
    Path("/var/log/secure"),    # RHEL, CentOS, Fedora, Rocky, Alma
]

# Regex patterns for common Linux authentication failures
SSH_FAILED_PATTERN = re.compile(
    r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
PAM_PREFIX_PATTERN = re.compile(
    r"pam_unix\((?P<service>[^:]+):auth\):\s+authentication failure;",
    re.IGNORECASE,
)
USER_FIELD_PATTERN = re.compile(r"\buser=(?P<user>\S+)", re.IGNORECASE)
RHOST_FIELD_PATTERN = re.compile(r"\brhost=(?P<ip>\S+)", re.IGNORECASE)
SUDO_FAILURE_PATTERN = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*\d+\s+incorrect password attempt",
    re.IGNORECASE,
)


class LinuxAuthLogMonitor(BaseAuthenticationMonitor):
    """Monitors Linux authentication log files for failed authentication events."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        """Initialize the Linux authentication monitor.

        Args:
            log_path: Optional explicit log file path for custom environments or testing.
        """
        self._custom_log_path = log_path
        self._active_path: Optional[Path] = None
        self._last_position: int = 0
        self._running: bool = False

    def get_source_name(self) -> str:
        """Return human-readable description of active log source."""
        if self._active_path:
            return f"Linux Authentication Log ({self._active_path})"
        return "Linux Authentication Log (/var/log/auth.log or /var/log/secure)"

    def is_available(self) -> tuple[bool, str]:
        """Check if Linux authentication log monitoring is supported and readable.

        Returns:
            Tuple of (is_available: bool, status_message: str).
        """
        if self._custom_log_path and self._custom_log_path.exists():
            if os.access(self._custom_log_path, os.R_OK):
                return True, f"Custom log file {self._custom_log_path} is readable."
            return False, f"Permission denied reading {self._custom_log_path}."

        if platform.system() != "Linux":
            return False, f"Unsupported platform: {platform.system()} (Linux required)"

        for candidate in STANDARD_LOG_PATHS:
            if candidate.exists():
                if os.access(candidate, os.R_OK):
                    return True, f"Log file {candidate} is accessible and readable."
                return (
                    False,
                    f"Authentication log {candidate} exists but is not readable. "
                    "Ensure the current user belongs to the 'adm' or 'wheel' group, "
                    "or run Device Guardian with appropriate file read permissions.",
                )

        return (
            False,
            "No standard Linux authentication log found (/var/log/auth.log or /var/log/secure).",
        )

    def _resolve_log_path(self) -> Optional[Path]:
        """Find the active readable log path."""
        if self._custom_log_path and self._custom_log_path.exists():
            return self._custom_log_path
        for candidate in STANDARD_LOG_PATHS:
            if candidate.exists() and os.access(candidate, os.R_OK):
                return candidate
        return None

    def start(self) -> None:
        """Bookmark log file offset to avoid processing historical lines."""
        self._running = True
        self._active_path = self._resolve_log_path()

        if self._active_path and self._active_path.exists():
            try:
                # Seek to end of file to ignore past events
                self._last_position = self._active_path.stat().st_size
                logger.debug("Linux log bookmark set to offset %d in %s", self._last_position, self._active_path)
            except OSError as err:
                logger.warning("Could not set initial log position: %s", err)
                self._last_position = 0
        else:
            self._last_position = 0

        logger.info("Linux authentication log monitor started.")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.info("Linux authentication log monitor stopped.")

    def poll(self) -> list[AuthenticationFailureEvent]:
        """Poll newly appended log lines for authentication failures.

        Returns:
            List of newly detected normalized AuthenticationFailureEvent instances.
        """
        if not self._running:
            return []

        if not self._active_path or not self._active_path.exists():
            self._active_path = self._resolve_log_path()
            if not self._active_path:
                return []

        try:
            current_size = self._active_path.stat().st_size
            # Handle log rotation where file size shrank
            if current_size < self._last_position:
                self._last_position = 0

            if current_size == self._last_position:
                return []

            new_events: list[AuthenticationFailureEvent] = []
            with open(self._active_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._last_position)
                lines = f.readlines()
                self._last_position = f.tell()

            for line in lines:
                ev = self.parse_log_line(line)
                if ev:
                    new_events.append(ev)

            return new_events

        except OSError as err:
            logger.warning("Error reading Linux auth log: %s", err)
            return []

    def parse_log_line(self, line: str) -> Optional[AuthenticationFailureEvent]:
        """Parse a single Linux authentication log line into a normalized event.

        Args:
            line: Raw string line from auth.log / secure.

        Returns:
            AuthenticationFailureEvent if failure detected, None otherwise.
        """
        line_clean = line.strip()
        if not line_clean:
            return None

        # Check SSH failure
        ssh_match = SSH_FAILED_PATTERN.search(line_clean)
        if ssh_match:
            user = ssh_match.group("user") or "Unavailable"
            remote_ip = ssh_match.group("ip") or "Unavailable"
            return AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform="Linux",
                source="sshd",
                username=user,
                remote_address=remote_ip,
                authentication_type="remote",
                details={"service": "sshd", "raw_entry_truncated": line_clean[:120]},
            )

        # Check PAM failure
        pam_match = PAM_PREFIX_PATTERN.search(line_clean)
        if pam_match:
            service = pam_match.group("service") or "system"
            user_match = USER_FIELD_PATTERN.search(line_clean)
            user = user_match.group("user") if user_match else "Unavailable"
            rhost_match = RHOST_FIELD_PATTERN.search(line_clean)
            raw_ip = rhost_match.group("ip") if rhost_match else None
            remote_ip = raw_ip if raw_ip and raw_ip.strip() else "Local Console"
            auth_type = "remote" if remote_ip != "Local Console" else "local"

            return AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform="Linux",
                source=f"pam_unix({service})",
                username=user,
                remote_address=remote_ip,
                authentication_type=auth_type,
                details={"service": service, "raw_entry_truncated": line_clean[:120]},
            )

        # Check sudo failure
        sudo_match = SUDO_FAILURE_PATTERN.search(line_clean)
        if sudo_match:
            user = sudo_match.group("user") or "Unavailable"
            return AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform="Linux",
                source="sudo",
                username=user,
                remote_address="Local Console",
                authentication_type="local",
                details={"service": "sudo", "raw_entry_truncated": line_clean[:120]},
            )

        return None
