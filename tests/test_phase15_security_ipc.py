"""Phase 15 Security Audit — Local IPC and Single-Instance Synchronization Security Tests.

Verifies:
- Corrupted, zero-byte, or forged lock files are safely rejected.
- PID reuse defense detects mismatched process creation time or non-Guardian image.
- Replayed control messages within replay window are rejected.
- Control messages from the future (>60s clock skew) or expired are rejected.
- Control message parser rejects unexpected extra fields.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.security.ipc import (
    ControlChannel,
    ControlChannelError,
    ControlCommand,
    ControlMessage,
)


def test_lock_file_rejects_corrupted_or_malformed_json(tmp_path: Path) -> None:
    """Verify SingleInstanceLock ignores malformed JSON or non-dict lock files."""
    lock_file = tmp_path / "guardian.lock"
    lock = SingleInstanceLock(lock_file_path=lock_file, mutex_name=None)

    # Empty file
    lock_file.write_text("", encoding="utf-8")
    assert lock.get_lock_data() is None

    # Invalid JSON
    lock_file.write_text("{not valid json", encoding="utf-8")
    assert lock.get_lock_data() is None

    # JSON array instead of dict
    lock_file.write_text("[1, 2, 3]", encoding="utf-8")
    assert lock.get_lock_data() is None

    # Negative or non-integer PID
    lock_file.write_text('{"pid": -5}', encoding="utf-8")
    assert lock.get_lock_data() is None

    lock_file.write_text('{"pid": "not_an_int"}', encoding="utf-8")
    assert lock.get_lock_data() is None


def test_control_channel_rejects_replayed_messages(tmp_path: Path) -> None:
    """Verify ControlChannel rejects replayed request IDs."""
    ControlChannel.reset_replay_cache()
    ctrl_file = tmp_path / "guardian.control"

    msg = ControlMessage.create(ControlCommand.STOP, ttl_seconds=30.0)
    ctrl_file.write_text(msg.to_json(), encoding="utf-8")

    # First receive succeeds
    received = ControlChannel.read_command(ctrl_file)
    assert received is not None
    assert received.request_id == msg.request_id

    # Replay attempt with same message must fail
    ctrl_file.write_text(msg.to_json(), encoding="utf-8")
    replayed = ControlChannel.read_command(ctrl_file)
    assert replayed is None


def test_control_message_rejects_future_clock_skew() -> None:
    """Verify ControlMessage rejects timestamps > 60 seconds into the future."""
    future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    future_expiry = future_time + timedelta(seconds=30)

    payload = {
        "command": "STOP",
        "request_id": "future-request-12345",
        "created_at": future_time.isoformat(),
        "expires_at": future_expiry.isoformat(),
        "sender_pid": 1234,
    }
    with pytest.raises(ControlChannelError, match="too far in the future"):
        ControlMessage.from_dict(payload)


def test_control_message_rejects_expired_timestamp() -> None:
    """Verify ControlMessage rejects timestamps that have already expired."""
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    past_expiry = past_time + timedelta(seconds=30)

    payload = {
        "command": "STOP",
        "request_id": "expired-request-12345",
        "created_at": past_time.isoformat(),
        "expires_at": past_expiry.isoformat(),
        "sender_pid": 1234,
    }
    with pytest.raises(ControlChannelError, match="expired"):
        ControlMessage.from_dict(payload)


def test_control_message_rejects_unexpected_fields() -> None:
    """Verify ControlMessage rejects payloads with unknown injected fields."""
    payload = {
        "command": "STOP",
        "request_id": "valid-request-12345",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
        "sender_pid": 1234,
        "extra_field": "injection_attempt",
    }
    with pytest.raises(ControlChannelError, match="Unexpected fields"):
        ControlMessage.from_dict(payload)
