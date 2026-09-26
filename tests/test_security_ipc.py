"""Tests for Phase 9 Hardened Local IPC and Control Channel."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import time
import uuid
import pytest

from device_guardian.security.ipc import (
    ControlChannel,
    ControlChannelError,
    ControlCommand,
    ControlMessage,
    IPCError,
)


def test_control_command_values():
    """Verify ControlCommand only contains whitelisted local lifecycle operations."""
    allowed = {cmd.value for cmd in ControlCommand}
    assert allowed == {"START", "STOP", "RESTART"}


def test_control_message_valid_creation():
    """Verify valid ControlMessage initializes with valid timestamp and UUID."""
    msg = ControlMessage.create(command=ControlCommand.STOP)
    assert msg.command == ControlCommand.STOP
    assert msg.request_id is not None
    assert msg.sender_pid == os.getpid()

    json_str = msg.to_json()
    parsed = json.loads(json_str)
    assert parsed["command"] == "STOP"
    assert "request_id" in parsed
    assert "created_at" in parsed
    assert "expires_at" in parsed


def test_control_message_from_dict_valid():
    """Verify parsing valid dictionary into ControlMessage."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=30)
    data = {
        "command": "START",
        "request_id": str(uuid.uuid4()),
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "sender_pid": 1234,
    }
    msg = ControlMessage.from_dict(data)
    assert msg.command == ControlCommand.START
    assert msg.sender_pid == 1234


def test_control_message_rejects_unwhitelisted_command():
    """Verify foreign/arbitrary command injection strings are rejected."""
    bad_commands = ["EXEC", "SHELL", "CMD", "RUN", "POWERSHELL", "SCRIPT"]
    for bad in bad_commands:
        with pytest.raises(ControlChannelError) as exc_info:
            ControlMessage.create(bad)
        assert "forbidden" in str(exc_info.value).lower() or "unknown" in str(exc_info.value).lower()


def test_control_message_rejects_expired_ttl():
    """Verify messages older than TTL are rejected."""
    past = datetime.now(timezone.utc) - timedelta(seconds=60)
    expired = datetime.now(timezone.utc) - timedelta(seconds=10)
    data = {
        "command": "STOP",
        "request_id": str(uuid.uuid4()),
        "created_at": past.isoformat(),
        "expires_at": expired.isoformat(),
        "sender_pid": 1234,
    }
    with pytest.raises(ControlChannelError) as exc_info:
        ControlMessage.from_dict(data)
    assert "expired" in str(exc_info.value).lower()


def test_control_message_rejects_future_clock_drift():
    """Verify messages with excessive future timestamps are rejected."""
    future = datetime.now(timezone.utc) + timedelta(minutes=10)
    expires = future + timedelta(seconds=30)
    data = {
        "command": "STOP",
        "request_id": str(uuid.uuid4()),
        "created_at": future.isoformat(),
        "expires_at": expires.isoformat(),
        "sender_pid": 1234,
    }
    with pytest.raises(ControlChannelError) as exc_info:
        ControlMessage.from_dict(data)
    assert "future" in str(exc_info.value).lower() or "skew" in str(exc_info.value).lower()


def test_control_message_replay_protection(tmp_path: Path):
    """Verify replaying the same request_id within the cache window is rejected by ControlChannel."""
    ctl_file = tmp_path / "replay_test.ipc"
    ControlChannel.reset_replay_cache()

    # First send and read succeeds
    ControlChannel.send_command(ctl_file, ControlCommand.STOP)
    msg1 = ControlChannel.read_command(ctl_file)
    assert msg1 is not None

    # Now write the exact same message payload back to file to simulate replay
    ctl_file.write_text(msg1.to_json(), encoding="utf-8")
    msg2 = ControlChannel.read_command(ctl_file)
    assert msg2 is None  # Replay must be rejected


def test_control_channel_send_and_read(tmp_path: Path):
    """Verify ControlChannel sends and consumes messages safely."""
    ctl_file = tmp_path / "test_control.ipc"

    assert ControlChannel.read_command(ctl_file) is None

    # Send STOP command
    ok = ControlChannel.send_command(ctl_file, ControlCommand.STOP)
    assert ok is True
    assert ctl_file.exists()

    # Read command
    received = ControlChannel.read_command(ctl_file)
    assert received is not None
    assert received.command == ControlCommand.STOP

    # Once cleared, it should return None
    ControlChannel.clear(ctl_file)
    assert ControlChannel.read_command(ctl_file) is None


def test_control_channel_corrupted_file_handling(tmp_path: Path):
    """Verify ControlChannel handles malformed JSON files gracefully without crashing."""
    ctl_file = tmp_path / "test_control.ipc"
    ctl_file.write_text("NOT_VALID_JSON{{{", encoding="utf-8")

    # Should catch error, log security event, and return None
    cmd = ControlChannel.read_command(ctl_file)
    assert cmd is None
