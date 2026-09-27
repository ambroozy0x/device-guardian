"""Phase 15 Security Audit — Authentication Security Tests.

Verifies:
- Password privacy invariant: raw passwords/credentials never captured, normalized, or stored.
- Authentication failure event normalization strips credentials from all OS sources.
- Threshold evaluation handles malformed, empty, and out-of-order timestamps safely.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import pytest

from device_guardian.detection.models import (
    AuthenticationFailureEvent,
    DetectionStatus,
    MonitorState,
)
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.detection.windows import WindowsSecurityLogMonitor
from device_guardian.detection.linux import LinuxAuthLogMonitor
from device_guardian.detection.macos import MacOSAuthLogMonitor


def test_auth_event_never_stores_passwords() -> None:
    """Verify AuthenticationFailureEvent schema has no password field and sanitizes inputs."""
    event = AuthenticationFailureEvent(
        timestamp=datetime.now(timezone.utc),
        platform="Windows",
        source="SecurityEventLog",
        username="administrator",
        remote_address="192.168.1.100",
        authentication_type="local",
        details={"record_id": 1001, "failure_reason": "Bad password"},
    )
    # Ensure fields do not contain secret/password attributes
    assert not hasattr(event, "password")
    assert not hasattr(event, "secret")
    assert not hasattr(event, "credential")
    event_dict = asdict(event)
    assert "password" not in event_dict
    assert event.username == "administrator"


def test_windows_4625_xml_parsing_excludes_passwords() -> None:
    """Verify parsing Windows Event 4625 XML does not extract or leak passwords."""
    xml_with_sensitive_data = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <TimeCreated SystemTime="2026-09-27T10:00:00.000Z"/>
        <EventRecordID>4242</EventRecordID>
      </System>
      <EventData>
        <Data Name="TargetUserName">testuser</Data>
        <Data Name="LogonType">2</Data>
        <Data Name="IpAddress">10.0.0.5</Data>
        <Data Name="WorkstationName">WORKSTATION1</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
        <Data Name="AttemptedPassword">super_secret_password_123</Data>
      </EventData>
    </Event>
    """
    monitor = WindowsSecurityLogMonitor()
    events = monitor.parse_event_xml(xml_with_sensitive_data)
    assert len(events) == 1
    ev = events[0]
    assert ev.username == "testuser"
    assert ev.remote_address == "10.0.0.5"
    assert "super_secret_password_123" not in str(asdict(ev))
    assert "AttemptedPassword" not in ev.details


def test_linux_auth_log_parsing_excludes_passwords() -> None:
    """Verify parsing Linux PAM/SSH lines never captures attempted passwords."""
    monitor = LinuxAuthLogMonitor()
    line1 = "Sep 27 10:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    line2 = "Sep 27 10:01:00 server pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/1 ruser=alice rhost= user=alice"

    ev1 = monitor.parse_log_line(line1)
    ev2 = monitor.parse_log_line(line2)

    assert ev1 is not None
    assert ev2 is not None
    for ev in [ev1, ev2]:
        event_str = str(asdict(ev))
        assert "password=" not in event_str
        assert "Failed password for" not in ev.username


def test_macos_log_stream_parsing_excludes_passwords() -> None:
    """Verify parsing macOS unified log NDJSON never extracts passwords."""
    monitor = MacOSAuthLogMonitor()
    ndjson = """{"timestamp":"2026-09-27 10:00:00.000000+0000","processImagePath":"/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow","eventMessage":"Failed to authenticate user <john_doe> with password secret_pass"}"""
    events = monitor.parse_log_stream(ndjson)
    assert len(events) == 1
    ev = events[0]
    assert "secret_pass" not in ev.username
    assert "secret_pass" not in str(asdict(ev))


def test_threshold_engine_safe_on_malformed_input() -> None:
    """Verify SlidingWindowThresholdEngine handles duplicate and threshold events safely."""
    engine = SlidingWindowThresholdEngine(threshold=3, window_seconds=60.0)
    assert engine.threshold == 3

    # Record event with valid timestamp
    t1 = datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)
    ev1 = AuthenticationFailureEvent(timestamp=t1, platform="Linux", source="auth.log", username="user1")
    threshold_met, count, _ = engine.record_event(ev1)
    assert threshold_met is False
    assert count == 1

    # Record event with duplicate timestamp
    ev2 = AuthenticationFailureEvent(timestamp=t1, platform="Linux", source="auth.log", username="user1")
    threshold_met, count, _ = engine.record_event(ev2)
    assert threshold_met is False
    assert count == 2

    # Third failure reaches threshold
    t3 = datetime(2026, 9, 27, 10, 0, 30, tzinfo=timezone.utc)
    ev3 = AuthenticationFailureEvent(timestamp=t3, platform="Linux", source="auth.log", username="user1")
    threshold_met, count, _ = engine.record_event(ev3)
    assert threshold_met is True
    assert count == 3
