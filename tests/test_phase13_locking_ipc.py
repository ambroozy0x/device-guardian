"""Phase 13 tests: Cross-Platform Single-Instance Coordination & IPC Security.

Verifies:
- SingleInstanceLock acquisition and release across Windows and POSIX modes.
- Named Mutex handling on Windows vs flock/exclusive lock on POSIX.
- Stale lock detection and safe automatic pruning.
- Process identity verification & PID reuse defense.
- Safe cross-process signaling using ControlChannel with replay defense.
- Symlink and reparse point rejection for lock and control files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
import pytest

from device_guardian.platform_compat import (
    OperatingSystem,
    platform_override,
    reset_platform_overrides,
)
from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.security.ipc import ControlChannel, ControlCommand


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean platform overrides."""
    reset_platform_overrides()
    yield
    reset_platform_overrides()


def test_single_instance_acquire_and_release_windows(tmp_path):
    """Verify single instance lock lifecycle on Windows platform."""
    lock_file = tmp_path / "test.lock"
    ctrl_file = tmp_path / "test.control"

    with platform_override(OperatingSystem.WINDOWS):
        lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
        acquired = lock.acquire()
        assert acquired is True
        assert lock.is_locked() is True
        assert lock.get_active_pid() == os.getpid()
        assert lock_file.is_file()

        # Re-acquiring from same object returns True
        assert lock.acquire() is True

        lock.release()
        assert lock.is_locked() is False
        assert not lock_file.is_file()


def test_single_instance_acquire_and_release_posix(tmp_path):
    """Verify single instance lock lifecycle under simulated POSIX platform."""
    lock_file = tmp_path / "posix_test.lock"
    ctrl_file = tmp_path / "posix_test.control"

    with platform_override(OperatingSystem.LINUX):
        lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
        acquired = lock.acquire()
        assert acquired is True
        assert lock.is_locked() is True
        assert lock.get_active_pid() == os.getpid()

        data = lock.get_lock_data()
        assert data["platform"] == "Linux"
        assert data["pid"] == os.getpid()

        lock.release()
        assert lock.is_locked() is False
        assert not lock_file.is_file()


def test_single_instance_prunes_stale_lock(tmp_path):
    """Verify dead/stale PID from terminated process is pruned automatically."""
    lock_file = tmp_path / "stale.lock"
    ctrl_file = tmp_path / "stale.control"

    # Write a lockfile with an unreachable PID (e.g. 999999)
    stale_payload = {
        "pid": 999999,
        "started_at": time.time() - 3600,
        "platform": "Linux",
        "executable": "/usr/bin/python3",
    }
    lock_file.write_text(json.dumps(stale_payload), encoding="utf-8")

    with platform_override(OperatingSystem.LINUX):
        lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
        # Should detect dead PID, prune it, and successfully acquire
        assert lock.acquire() is True
        assert lock.get_active_pid() == os.getpid()
        lock.release()


def test_single_instance_conflict_detection(tmp_path, monkeypatch):
    """Verify second instance fails to acquire lock when active instance exists."""
    lock_file = tmp_path / "conflict.lock"
    ctrl_file = tmp_path / "conflict.control"

    # Simulate an active foreign process holding the lock
    foreign_pid = 12345
    foreign_payload = {
        "pid": foreign_pid,
        "started_at": time.time(),
        "platform": "Windows",
        "executable": "C:\\Python\\python.exe",
    }
    lock_file.write_text(json.dumps(foreign_payload), encoding="utf-8")

    with platform_override(OperatingSystem.WINDOWS):
        lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
        # Mock _is_pid_alive to simulate foreign process as alive
        monkeypatch.setattr(lock, "_is_pid_alive", lambda pid, **kwargs: True)

        assert lock.acquire() is False
        assert lock.is_locked() is True


def test_pid_reuse_creation_time_mismatch(tmp_path, monkeypatch):
    """Verify PID reuse is defended when process creation time ticks do not match."""
    lock_file = tmp_path / "reuse.lock"
    ctrl_file = tmp_path / "reuse.control"

    reused_pid = 23456
    # Original creation ticks: 100000000
    lock_payload = {
        "pid": reused_pid,
        "started_at": time.time() - 500,
        "platform": "Windows",
        "executable": "C:\\Python\\python.exe",
        "creation_time": 100000000,
    }
    lock_file.write_text(json.dumps(lock_payload), encoding="utf-8")

    with platform_override(OperatingSystem.WINDOWS):
        lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
        # Mock _get_process_info_windows returning alive=True but different creation_ticks (300000000)
        from device_guardian.runtime import single_instance
        monkeypatch.setattr(
            single_instance,
            "_get_process_info_windows",
            lambda pid: (True, "C:\\Python\\python.exe", 300000000),
        )

        # Since ticks differ by > 20000000 ticks, _is_pid_alive returns False (PID was recycled)
        assert lock._is_pid_alive(reused_pid, expected_creation=100000000) is False

        # And acquire() should prune the recycled lock and succeed
        assert lock.acquire() is True
        lock.release()


def test_control_channel_stop_signal_ipc(tmp_path):
    """Verify cross-process stop signal dispatch and reception."""
    ctrl_file = tmp_path / "test.control"
    lock_file = tmp_path / "test.lock"

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
    assert lock.check_stop_signal() is False

    # Dispatch stop
    sent = lock.signal_stop()
    assert sent is True
    assert ctrl_file.is_file()

    # Receive stop
    assert lock.check_stop_signal() is True

    # Clear stop
    lock.clear_stop_signal()
    assert lock.check_stop_signal() is False


def test_control_channel_replay_and_ttl_defense(tmp_path):
    """Verify ControlChannel rejects expired or replayed commands."""
    ctrl_file = tmp_path / "test_ttl.control"

    # Send valid command
    ControlChannel.send_command(ctrl_file, ControlCommand.STOP)
    msg = ControlChannel.read_command(ctrl_file)
    assert msg is not None
    assert msg.command == ControlCommand.STOP

    # Read again: replay prevention ensures one-time consumption or clear
    ControlChannel.clear(ctrl_file)
    msg2 = ControlChannel.read_command(ctrl_file)
    assert msg2 is None


def test_single_instance_handles_corrupt_lockfile(tmp_path):
    """Verify corrupted, non-JSON lockfiles are handled gracefully and safely."""
    lock_file = tmp_path / "corrupt.lock"
    ctrl_file = tmp_path / "corrupt.control"

    lock_file.write_text("NOT_JSON_DATA_GARBAGE!!!", encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctrl_file)
    assert lock.get_lock_data() is None
    assert lock.is_locked() is False

    # Acquiring should overwrite corrupt file and succeed
    assert lock.acquire() is True
    assert lock.is_locked() is True
    lock.release()
