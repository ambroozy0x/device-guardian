"""Unit tests for Phase 3 Detection Models and States."""

from __future__ import annotations

from datetime import datetime

from device_guardian.detection.models import (
    AuthenticationFailureEvent,
    DetectionStatus,
    MonitorState,
)


def test_authentication_failure_event_sanitization() -> None:
    """Verify username and remote address sanitization and fallbacks."""
    ev = AuthenticationFailureEvent(
        timestamp=datetime(2026, 9, 25, 12, 0, 0),
        platform="Windows",
        source="Security",
        username="  admin_user  ",
        remote_address=" 192.168.1.100 ",
        authentication_type="remote",
    )
    assert ev.username == "admin_user"
    assert ev.remote_address == "192.168.1.100"
    assert ev.platform == "Windows"
    assert ev.authentication_type == "remote"
    assert "admin_user" in ev.event_identifier


def test_authentication_failure_event_fallbacks() -> None:
    """Verify empty/dash usernames and IPs get converted to safe fallbacks."""
    ev1 = AuthenticationFailureEvent(
        username="-",
        remote_address="-",
        authentication_type="local",
    )
    assert ev1.username == "Unavailable"
    assert ev1.remote_address == "Local Console"

    ev2 = AuthenticationFailureEvent(
        username="",
        remote_address="127.0.0.1",
        authentication_type="network",
    )
    assert ev2.username == "Unavailable"
    assert ev2.remote_address == "Unavailable"


def test_authentication_failure_format_summary() -> None:
    """Verify objective, factual format_summary string."""
    ev = AuthenticationFailureEvent(
        timestamp=datetime(2026, 9, 25, 12, 0, 0),
        platform="Linux",
        source="sshd",
        username="john_doe",
        remote_address="10.0.0.5",
        authentication_type="remote",
    )
    summary = ev.format_summary()
    assert "Authentication failure recorded on Linux" in summary
    assert "Source: sshd" in summary
    assert "User: john_doe" in summary
    assert "Remote: 10.0.0.5" in summary
    # Verify objective tone without emotive or speculative language
    assert "hacker" not in summary.lower()
    assert "intruder" not in summary.lower()
    assert "attack" not in summary.lower()


def test_detection_status_and_monitor_states() -> None:
    """Verify enum members exist and match expected string values."""
    assert DetectionStatus.READY.value == "READY"
    assert DetectionStatus.UNAVAILABLE.value == "UNAVAILABLE"
    assert DetectionStatus.ERROR.value == "ERROR"

    assert MonitorState.READY.value == "READY"
    assert MonitorState.THRESHOLD_REACHED.value == "THRESHOLD_REACHED"
    assert MonitorState.ALERT_SENT.value == "ALERT_SENT"
    assert MonitorState.COOLDOWN.value == "COOLDOWN"
    assert MonitorState.ERROR.value == "ERROR"
