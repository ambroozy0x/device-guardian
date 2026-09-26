"""Unit tests for WindowsSecurityLogMonitor."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from device_guardian.detection.windows import WindowsSecurityLogMonitor

SAMPLE_EVENT_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <EventRecordID>10042</EventRecordID>
        <TimeCreated SystemTime="2026-09-25T14:30:15.1234567Z" />
    </System>
    <EventData>
        <Data Name="TargetUserName">test_user</Data>
        <Data Name="TargetDomainName">WORKGROUP</Data>
        <Data Name="Status">0xc000006d</Data>
        <Data Name="SubStatus">0xc000006a</Data>
        <Data Name="LogonType">2</Data>
        <Data Name="WorkstationName">DESKTOP-TEST</Data>
        <Data Name="IpAddress">-</Data>
        <Data Name="IpPort">-</Data>
    </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <EventRecordID>10043</EventRecordID>
        <TimeCreated SystemTime="2026-09-25T14:31:00.0000000Z" />
    </System>
    <EventData>
        <Data Name="TargetUserName">remote_admin</Data>
        <Data Name="TargetDomainName">WORKGROUP</Data>
        <Data Name="Status">0xc000006d</Data>
        <Data Name="SubStatus">0xc000006a</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="WorkstationName">REMOTE-PC</Data>
        <Data Name="IpAddress">192.168.1.55</Data>
        <Data Name="IpPort">49152</Data>
    </EventData>
</Event>
"""


def test_windows_xml_parsing() -> None:
    """Verify parsing of Event 4625 XML into normalized events."""
    mon = WindowsSecurityLogMonitor()
    events = mon.parse_event_xml(SAMPLE_EVENT_XML)

    assert len(events) == 2

    # First event (LogonType 2 -> local)
    ev1 = events[0]
    assert ev1.platform == "Windows"
    assert ev1.username == "test_user"
    assert ev1.authentication_type == "local"
    assert ev1.remote_address == "Local Console"
    assert ev1.details.get("record_id") == "10042"

    # Second event (LogonType 10 -> remote RDP)
    ev2 = events[1]
    assert ev2.platform == "Windows"
    assert ev2.username == "remote_admin"
    assert ev2.authentication_type == "remote"
    assert ev2.remote_address == "192.168.1.55"
    assert ev2.details.get("record_id") == "10043"


def test_windows_xml_parsing_empty_input() -> None:
    """Verify handling of empty or invalid XML without raising errors."""
    mon = WindowsSecurityLogMonitor()
    assert mon.parse_event_xml("") == []
    assert mon.parse_event_xml("<Invalid<xml>>") == []


@patch("platform.system", return_value="Linux")
def test_windows_is_available_non_windows(mock_sys: MagicMock) -> None:
    """Verify monitor reports unavailable on non-Windows platforms."""
    mon = WindowsSecurityLogMonitor()
    ok, msg = mon.is_available()
    assert ok is False
    assert "Unsupported platform" in msg


@patch("platform.system", return_value="Windows")
@patch("shutil.which", return_value=None)
def test_windows_is_available_missing_wevtutil(mock_which: MagicMock, mock_sys: MagicMock) -> None:
    """Verify monitor reports unavailable when wevtutil is missing."""
    mon = WindowsSecurityLogMonitor()
    ok, msg = mon.is_available()
    assert ok is False
    assert "wevtutil.exe utility not found" in msg


@patch("platform.system", return_value="Windows")
@patch("shutil.which", return_value="C:\\Windows\\System32\\wevtutil.exe")
def test_windows_is_available_access_denied(mock_which: MagicMock, mock_sys: MagicMock) -> None:
    """Verify monitor handles non-elevated Access is denied with clear guidance."""
    runner = MagicMock(return_value=subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="Access is denied.\nFailed to open event query.",
    ))
    mon = WindowsSecurityLogMonitor(command_runner=runner)
    ok, msg = mon.is_available()
    assert ok is False
    assert "Run Device Guardian with elevated privileges" in msg


@patch("platform.system", return_value="Windows")
@patch("shutil.which", return_value="C:\\Windows\\System32\\wevtutil.exe")
def test_windows_is_available_success(mock_which: MagicMock, mock_sys: MagicMock) -> None:
    """Verify monitor reports ready when wevtutil succeeds."""
    runner = MagicMock(return_value=subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="<Event>...</Event>",
        stderr="",
    ))
    mon = WindowsSecurityLogMonitor(command_runner=runner)
    ok, msg = mon.is_available()
    assert ok is True
    assert "accessible and operational" in msg


def test_windows_monitor_poll_and_deduplication() -> None:
    """Verify polling filters out seen events and respects baseline record ID."""
    runner = MagicMock(return_value=subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=SAMPLE_EVENT_XML,
        stderr="",
    ))
    mon = WindowsSecurityLogMonitor(command_runner=runner)

    # Establish baseline with record_id 10042
    mon.start()
    mon._last_record_id = 10042
    mon._seen_record_ids.add(10042)

    # Polling should only return record 10043 (which is > 10042)
    new_events = mon.poll()
    assert len(new_events) == 1
    assert new_events[0].details.get("record_id") == "10043"

    # Second poll should return empty list because 10043 has now been seen
    repeat_events = mon.poll()
    assert len(repeat_events) == 0

    mon.stop()
    assert mon.poll() == []
