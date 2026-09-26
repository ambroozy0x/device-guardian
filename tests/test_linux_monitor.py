"""Unit tests for LinuxAuthLogMonitor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from device_guardian.detection.linux import LinuxAuthLogMonitor


def test_linux_parse_ssh_failure() -> None:
    """Verify parsing of sshd authentication failure lines."""
    mon = LinuxAuthLogMonitor()
    line = "Sep 25 14:32:01 server sshd[1234]: Failed password for invalid user badguy from 198.51.100.24 port 54321 ssh2"
    ev = mon.parse_log_line(line)

    assert ev is not None
    assert ev.platform == "Linux"
    assert ev.source == "sshd"
    assert ev.username == "badguy"
    assert ev.remote_address == "198.51.100.24"
    assert ev.authentication_type == "remote"


def test_linux_parse_pam_failure() -> None:
    """Verify parsing of pam_unix authentication failure lines."""
    mon = LinuxAuthLogMonitor()
    # Local PAM failure
    line_local = "Sep 25 14:33:00 server login: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=alice"
    ev_local = mon.parse_log_line(line_local)

    assert ev_local is not None
    assert ev_local.platform == "Linux"
    assert ev_local.username == "alice"
    assert ev_local.remote_address == "Local Console"
    assert ev_local.authentication_type == "local"

    # Remote PAM failure
    line_remote = "Sep 25 14:34:00 server sshd: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=bob"
    ev_remote = mon.parse_log_line(line_remote)

    assert ev_remote is not None
    assert ev_remote.username == "bob"
    assert ev_remote.remote_address == "203.0.113.5"
    assert ev_remote.authentication_type == "remote"


def test_linux_parse_sudo_failure() -> None:
    """Verify parsing of sudo authentication failure lines."""
    mon = LinuxAuthLogMonitor()
    line = "Sep 25 14:35:00 server sudo:   charlie : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/charlie ; USER=root ; COMMAND=/bin/bash"
    ev = mon.parse_log_line(line)

    assert ev is not None
    assert ev.username == "charlie"
    assert ev.source == "sudo"
    assert ev.authentication_type == "local"


def test_linux_parse_ignores_benign_lines() -> None:
    """Verify non-failure lines return None."""
    mon = LinuxAuthLogMonitor()
    assert mon.parse_log_line("Sep 25 14:36:00 server sshd[1234]: Accepted password for alice from 192.168.1.5") is None
    assert mon.parse_log_line("") is None
    assert mon.parse_log_line("Sep 25 14:36:00 server systemd: Started Session 1 of user alice.") is None


def test_linux_polling_custom_file(tmp_path: Path) -> None:
    """Verify LinuxAuthLogMonitor tails newly appended lines from a custom log file."""
    log_file = tmp_path / "auth.log"
    # Initial existing content
    log_file.write_text("Initial log entry\n", encoding="utf-8")

    mon = LinuxAuthLogMonitor(log_path=log_file)
    mon.start()

    # Initial poll without new lines -> empty
    assert mon.poll() == []

    # Append new failure line
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("Sep 25 14:37:00 server sshd[100]: Failed password for testuser from 192.0.2.1 port 22 ssh2\n")

    events = mon.poll()
    assert len(events) == 1
    assert events[0].username == "testuser"
    assert events[0].remote_address == "192.0.2.1"

    # Polling again without new writes -> empty
    assert mon.poll() == []
    mon.stop()


@patch("platform.system", return_value="Windows")
def test_linux_is_available_non_linux(mock_sys: MagicMock) -> None:
    """Verify monitor reports unavailable on non-Linux systems."""
    mon = LinuxAuthLogMonitor()
    ok, msg = mon.is_available()
    assert ok is False
    assert "Linux required" in msg
