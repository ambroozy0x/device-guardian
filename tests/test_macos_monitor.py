"""Unit tests for MacOSAuthLogMonitor."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from device_guardian.detection.macos import MacOSAuthLogMonitor

SAMPLE_MACOS_NDJSON = """
{"timestamp": "2026-09-25 14:38:00.123456-0400", "processImagePath": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow", "eventMessage": "Failed to authenticate user 'testuser'"}
{"timestamp": "2026-09-25 14:38:05.654321-0400", "processImagePath": "/usr/sbin/sshd", "eventMessage": "Failed password for admin from 192.168.1.80 port 5022 ssh2"}
"""


def test_macos_ndjson_parsing() -> None:
    """Verify parsing macOS unified log NDJSON format."""
    mon = MacOSAuthLogMonitor()
    events = mon.parse_log_stream(SAMPLE_MACOS_NDJSON)

    assert len(events) == 2

    ev1 = events[0]
    assert ev1.platform == "macOS"
    assert ev1.authentication_type == "local"
    assert "loginwindow" in ev1.source

    ev2 = events[1]
    assert ev2.platform == "macOS"
    assert ev2.authentication_type == "remote"
    assert "sshd" in ev2.source


@patch("platform.system", return_value="Windows")
def test_macos_is_available_non_darwin(mock_sys: MagicMock) -> None:
    """Verify monitor reports unavailable on non-macOS systems."""
    mon = MacOSAuthLogMonitor()
    ok, msg = mon.is_available()
    assert ok is False
    assert "macOS/Darwin required" in msg


@patch("platform.system", return_value="Darwin")
@patch("shutil.which", return_value=None)
def test_macos_is_available_missing_tool(mock_which: MagicMock, mock_sys: MagicMock) -> None:
    """Verify monitor reports unavailable if /usr/bin/log is missing."""
    mon = MacOSAuthLogMonitor()
    ok, msg = mon.is_available()
    assert ok is False
    assert "/usr/bin/log utility not found" in msg


@patch("platform.system", return_value="Darwin")
@patch("shutil.which", return_value="/usr/bin/log")
def test_macos_is_available_success(mock_which: MagicMock, mock_sys: MagicMock) -> None:
    """Verify monitor reports ready when log show probe succeeds."""
    runner = MagicMock(return_value=subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="[]",
        stderr="",
    ))
    mon = MacOSAuthLogMonitor(command_runner=runner)
    ok, msg = mon.is_available()
    assert ok is True
    assert "accessible and operational" in msg
