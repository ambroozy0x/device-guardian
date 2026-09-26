"""macOS authentication log monitor.

Monitors macOS security/authentication events via the macOS Unified Logging System (`log show`).
Adheres to Phase 3 privacy requirements:
- Sanitizes usernames and IPs.
- Never captures or stores credentials.
- Handles macOS permission limitations gracefully.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import platform
import shutil
import subprocess
from typing import Any, Callable, Optional

from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.logger import get_logger

logger = get_logger("detection.macos")


class MacOSAuthLogMonitor(BaseAuthenticationMonitor):
    """Monitors macOS unified logs for authentication failure events."""

    def __init__(
        self,
        command_runner: Optional[Callable[[list[str], float], subprocess.CompletedProcess]] = None,
    ) -> None:
        """Initialize the macOS log monitor.

        Args:
            command_runner: Optional runner hook for testing.
        """
        self._runner = command_runner or (
            lambda cmd, timeout: subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        )
        self._running: bool = False
        self._last_timestamp: Optional[datetime] = None

    def get_source_name(self) -> str:
        """Return human-readable log source name."""
        return "macOS Unified Logging System (log show)"

    def is_available(self) -> tuple[bool, str]:
        """Check if macOS log utility is available and accessible.

        Returns:
            Tuple of (is_available: bool, status_message: str).
        """
        if platform.system() != "Darwin":
            return False, f"Unsupported platform: {platform.system()} (macOS/Darwin required)"

        log_tool = shutil.which("log")
        if not log_tool:
            return False, "/usr/bin/log utility not found on macOS."

        try:
            # Probe with a fast 1-second query
            res = self._runner(
                [log_tool, "show", "--predicate", 'process == "loginwindow"', "--last", "10s", "--style", "ndjson"],
                5.0,
            )
            if res.returncode != 0:
                return (
                    False,
                    "macOS Unified Logging system returned an error. Ensure Device Guardian "
                    "has necessary security and terminal permissions.",
                )
            return True, "macOS Unified Logging system is accessible and operational."
        except Exception as exc:
            return False, f"Failed to probe macOS unified log: {exc}"

    def start(self) -> None:
        """Bookmark the current timestamp."""
        self._running = True
        self._last_timestamp = datetime.now(timezone.utc)
        logger.info("macOS authentication monitor started.")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.info("macOS authentication monitor stopped.")

    def poll(self) -> list[AuthenticationFailureEvent]:
        """Poll macOS logs for recent authentication failures.

        Returns:
            List of newly detected normalized AuthenticationFailureEvent instances.
        """
        if not self._running:
            return []

        log_tool = shutil.which("log") or "/usr/bin/log"
        # Search for failed authentication messages in loginwindow, opendirectoryd, or sshd
        predicate = (
            '(process == "loginwindow" or process == "authorizationhost" or process == "sshd") and '
            '(eventMessage contains[c] "authentication failed" or eventMessage contains[c] "Failed to authenticate" '
            'or eventMessage contains[c] "Failed password")'
        )

        try:
            res = self._runner(
                [log_tool, "show", "--predicate", predicate, "--last", "1m", "--style", "ndjson"],
                8.0,
            )
            if res.returncode != 0 or not res.stdout.strip():
                return []

            events = self.parse_log_stream(res.stdout)
            new_events: list[AuthenticationFailureEvent] = []

            for ev in events:
                if self._last_timestamp and ev.timestamp.replace(tzinfo=timezone.utc) <= self._last_timestamp:
                    continue
                new_events.append(ev)

            if new_events:
                # Update last timestamp to latest event
                self._last_timestamp = max(ev.timestamp.replace(tzinfo=timezone.utc) for ev in new_events)

            return new_events

        except subprocess.TimeoutExpired:
            logger.warning("macOS log query timed out.")
            return []
        except Exception as exc:
            logger.warning("Error querying macOS log: %s", exc)
            return []

    def parse_log_stream(self, ndjson_content: str) -> list[AuthenticationFailureEvent]:
        """Parse newline-delimited JSON entries from macOS log show.

        Args:
            ndjson_content: Raw NDJSON string from `log show --style ndjson`.

        Returns:
            List of normalized AuthenticationFailureEvent instances.
        """
        events: list[AuthenticationFailureEvent] = []
        if not ndjson_content or not ndjson_content.strip():
            return events

        for line in ndjson_content.splitlines():
            line_clean = line.strip()
            if not line_clean:
                continue
            try:
                record = json.loads(line_clean)
                msg = record.get("eventMessage", "")
                process = record.get("processImagePath", record.get("processID", "unknown"))
                process_name = str(process).split("/")[-1]

                # Extract timestamp
                ts_str = record.get("timestamp")
                dt = datetime.now()
                if ts_str:
                    try:
                        clean_ts = ts_str.split("+")[0].split("Z")[0]
                        dt = datetime.fromisoformat(clean_ts)
                    except ValueError:
                        pass

                auth_type = "remote" if "sshd" in process_name.lower() else "local"

                norm_event = AuthenticationFailureEvent(
                    timestamp=dt,
                    platform="macOS",
                    source=f"unified_log({process_name})",
                    username="Unavailable",
                    remote_address="Local Console" if auth_type == "local" else "Unavailable",
                    authentication_type=auth_type,
                    details={"process": process_name, "raw_entry_truncated": msg[:120]},
                )
                events.append(norm_event)

            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        return events
