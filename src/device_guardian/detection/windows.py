"""Windows Security Event Log monitor for Event ID 4625 (Logon Failure).

Uses `wevtutil.exe` to inspect the Windows Security log.
Enforces safe parsing:
- Captures only sanitized usernames, timestamps, logon types, and IP addresses.
- Never captures, logs, or stores credentials.
- Handles non-elevated user permissions gracefully with actionable diagnostics.
"""

from __future__ import annotations

from datetime import datetime, timezone
import platform
import shutil
import subprocess
from typing import Callable, Optional
import xml.etree.ElementTree as ET

from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.logger import get_logger

logger = get_logger("detection.windows")

# Windows Logon Types reference:
# 2 = Interactive (console / keyboard)
# 3 = Network (SMB, share, etc.)
# 7 = Unlock (screen unlock)
# 8 = NetworkCleartext
# 10 = RemoteInteractive (RDP / Remote Desktop)
# 11 = CachedInteractive
LOCAL_LOGON_TYPES = {"2", "7", "11"}
REMOTE_LOGON_TYPES = {"3", "8", "10"}

XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _find_child(node: ET.Element, tag: str) -> Optional[ET.Element]:
    child = node.find(f"{{{XML_NS}}}{tag}")
    if child is not None:
        return child
    return node.find(tag)


def _findall_children(node: ET.Element, tag: str) -> list[ET.Element]:
    children = node.findall(f"{{{XML_NS}}}{tag}")
    if children:
        return children
    return node.findall(tag)


class WindowsSecurityLogMonitor(BaseAuthenticationMonitor):
    """Monitors Windows Security Event Log for logon failure events (Event ID 4625)."""

    def __init__(
        self,
        command_runner: Optional[Callable[[list[str], float], subprocess.CompletedProcess]] = None,
    ) -> None:
        """Initialize the Windows Security Log monitor.

        Args:
            command_runner: Optional test hook to mock subprocess.run.
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
        self._last_record_id: Optional[int] = None
        self._start_time: Optional[datetime] = None
        self._running: bool = False
        self._seen_record_ids: set[int] = set()

    def get_source_name(self) -> str:
        """Return human-readable log source name."""
        return "Windows Security Event Log (Event 4625)"

    def is_available(self) -> tuple[bool, str]:
        """Check if Windows Security Log monitoring is available and accessible.

        Returns:
            Tuple of (is_available: bool, status_message: str).
        """
        if platform.system() != "Windows":
            return False, f"Unsupported platform: {platform.system()} (Windows required)"

        wevtutil = shutil.which("wevtutil.exe") or shutil.which("wevtutil")
        if not wevtutil:
            return False, "wevtutil.exe utility not found on PATH."

        try:
            # Probe with a fast single-record query to verify access permissions
            res = self._runner(
                [wevtutil, "qe", "Security", "/q:*[System[(EventID=4625)]]", "/c:1", "/rd:true"],
                5.0,
            )
            stderr = res.stderr.lower() if res.stderr else ""
            stdout = res.stdout.lower() if res.stdout else ""

            if res.returncode != 0 or "access is denied" in stderr or "access is denied" in stdout:
                return (
                    False,
                    "Windows Security Event Log is not accessible. Run Device Guardian with "
                    "elevated privileges ('Run as Administrator') or add the user account "
                    "to the 'Event Log Readers' group.",
                )

            return True, "Windows Security Event Log is accessible and operational."
        except Exception as exc:
            return False, f"Failed to probe Windows Security Event Log: {exc}"

    def start(self) -> None:
        """Bookmark current state to prevent alerting on historical events."""
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        self._seen_record_ids.clear()

        # Attempt to read the most recent record ID to establish baseline bookmark
        try:
            wevtutil = shutil.which("wevtutil.exe") or "wevtutil"
            res = self._runner(
                [
                    wevtutil,
                    "qe",
                    "Security",
                    "/q:*[System[(EventID=4625)]]",
                    "/f:xml",
                    "/c:1",
                    "/rd:true",
                ],
                5.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                events = self.parse_event_xml(res.stdout)
                if events and "record_id" in events[0].details:
                    self._last_record_id = int(events[0].details["record_id"])
                    self._seen_record_ids.add(self._last_record_id)
                    logger.debug("Baseline Windows event bookmark set to record ID %d", self._last_record_id)
        except Exception as exc:
            logger.debug("Could not establish initial baseline record ID: %s", exc)

        logger.info("Windows Security Event Log monitor started.")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.info("Windows Security Event Log monitor stopped.")

    def poll(self) -> list[AuthenticationFailureEvent]:
        """Poll for new logon failure events.

        Returns:
            List of newly detected normalized AuthenticationFailureEvent instances.
        """
        if not self._running:
            return []

        wevtutil = shutil.which("wevtutil.exe") or "wevtutil"
        try:
            res = self._runner(
                [
                    wevtutil,
                    "qe",
                    "Security",
                    "/q:*[System[(EventID=4625)]]",
                    "/f:xml",
                    "/c:25",
                    "/rd:true",
                ],
                8.0,
            )
            if res.returncode != 0:
                logger.warning(
                    "wevtutil returned code %d: %s",
                    res.returncode,
                    res.stderr.strip() if res.stderr else "Unknown error",
                )
                return []

            if not res.stdout.strip():
                return []

            events = self.parse_event_xml(res.stdout)
            new_events: list[AuthenticationFailureEvent] = []

            for ev in events:
                rec_id = ev.details.get("record_id")
                rec_id_int = int(rec_id) if rec_id is not None else None

                # Deduplicate seen events
                if rec_id_int is not None and rec_id_int in self._seen_record_ids:
                    continue

                # Filter events that occurred before startup baseline
                if self._last_record_id is not None and rec_id_int is not None:
                    if rec_id_int <= self._last_record_id:
                        continue
                elif self._start_time is not None:
                    if ev.timestamp.replace(tzinfo=timezone.utc) < self._start_time:
                        continue

                if rec_id_int is not None:
                    self._seen_record_ids.add(rec_id_int)
                    if self._last_record_id is None or rec_id_int > self._last_record_id:
                        self._last_record_id = rec_id_int

                new_events.append(ev)

            # Sort ascending by timestamp
            new_events.sort(key=lambda x: x.timestamp)
            return new_events

        except subprocess.TimeoutExpired:
            logger.warning("Windows event query timed out.")
            return []
        except Exception as exc:
            logger.warning("Error querying Windows Security Log: %s", exc)
            return []

    def parse_event_xml(self, xml_content: str) -> list[AuthenticationFailureEvent]:
        """Parse raw wevtutil XML output into normalized AuthenticationFailureEvent items.

        Args:
            xml_content: Concatenated <Event> elements from wevtutil.

        Returns:
            List of normalized AuthenticationFailureEvent instances.
        """
        if not xml_content or not xml_content.strip():
            return []

        # wevtutil outputs multiple root <Event> tags without an enclosing root.
        wrapped_xml = f"<Events>{xml_content}</Events>"
        parsed_events: list[AuthenticationFailureEvent] = []

        try:
            root = ET.fromstring(wrapped_xml)
        except ET.ParseError as err:
            logger.debug("Failed to parse event XML: %s", err)
            return []

        for event_node in _findall_children(root, "Event"):
            try:
                system_node = _find_child(event_node, "System")
                event_data_node = _find_child(event_node, "EventData")

                # Extract System fields
                record_id: Optional[str] = None
                iso_time: Optional[str] = None
                if system_node is not None:
                    rec_elem = _find_child(system_node, "EventRecordID")
                    if rec_elem is not None and rec_elem.text:
                        record_id = rec_elem.text.strip()

                    time_elem = _find_child(system_node, "TimeCreated")
                    if time_elem is not None:
                        iso_time = time_elem.attrib.get("SystemTime")

                # Parse timestamp
                dt = datetime.now()
                if iso_time:
                    try:
                        clean_time = iso_time.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_time)
                    except ValueError:
                        pass

                # Extract EventData fields
                data_dict: dict[str, str] = {}
                if event_data_node is not None:
                    for d in _findall_children(event_data_node, "Data"):
                        name = d.attrib.get("Name")
                        if name and d.text:
                            data_dict[name] = d.text.strip()

                username = data_dict.get("TargetUserName", "Unavailable")
                logon_type_code = data_dict.get("LogonType", "")
                remote_ip = data_dict.get("IpAddress", "Unavailable")

                # Determine authentication type
                if logon_type_code in LOCAL_LOGON_TYPES:
                    auth_type = "local"
                elif logon_type_code in REMOTE_LOGON_TYPES:
                    auth_type = "remote"
                else:
                    auth_type = "unknown"

                details = {
                    "source": "Security",
                    "event_id": 4625,
                    "logon_type": logon_type_code,
                    "status": data_dict.get("Status", "Unavailable"),
                    "sub_status": data_dict.get("SubStatus", "Unavailable"),
                    "workstation": data_dict.get("WorkstationName", "Unavailable"),
                }
                if record_id:
                    details["record_id"] = record_id

                event_id_str = f"windows:4625:{record_id or dt.isoformat()}"

                norm_event = AuthenticationFailureEvent(
                    timestamp=dt,
                    platform="Windows",
                    source="Security Event Log (4625)",
                    username=username,
                    remote_address=remote_ip,
                    authentication_type=auth_type,
                    event_identifier=event_id_str,
                    details=details,
                )
                parsed_events.append(norm_event)

            except Exception as item_err:
                logger.debug("Failed parsing individual event node: %s", item_err)
                continue

        return parsed_events
