import json
import os
from pathlib import Path
from unittest.mock import patch
import uuid
import pytest

from device_guardian.runtime.single_instance import SingleInstanceLock


def test_lock_acquire_and_release(tmp_path):
    """Verify single instance lock can be acquired and cleanly released."""
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    m_name = f"Local\\Test_{uuid.uuid4().hex}"
    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=m_name)

    assert lock.is_locked() is False
    acquired = lock.acquire()
    assert acquired is True
    assert lock.is_locked() is True
    assert lock_file.is_file()

    # Verify written PID matches current process
    data = json.loads(lock_file.read_text(encoding="utf-8"))
    assert data["pid"] == os.getpid()

    lock.release()
    assert lock.is_locked() is False
    assert not lock_file.is_file()


def test_lock_duplicate_rejection(tmp_path):
    """Verify that a second instance cannot acquire an active lock."""
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    m_name = f"Local\\Test_{uuid.uuid4().hex}"

    lock1 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=m_name)
    assert lock1.acquire() is True

    # Simulate a second process attempting acquisition with same mutex/lockfile
    lock2 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=m_name)
    assert lock2.acquire() is False

    lock1.release()


def test_stale_lock_pruning(tmp_path):
    """Verify that a stale lock from a dead process is pruned and acquisition succeeds."""
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    m_name = f"Local\\Test_{uuid.uuid4().hex}"

    # Write a fake dead PID to lock file
    stale_payload = {"pid": 999999, "started_at": 1000.0}
    lock_file.write_text(json.dumps(stale_payload), encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=m_name)

    # When PID 999999 is dead
    with patch.object(lock, "_is_pid_alive", return_value=False):
        acquired = lock.acquire()
        assert acquired is True
        assert lock.get_active_pid() == os.getpid()

    lock.release()


def test_stop_signal_ipc(tmp_path):
    """Verify IPC stop signal dispatching, checking, and clearing."""
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file)

    assert lock.check_stop_signal() is False

    lock.signal_stop()
    assert lock.check_stop_signal() is True
    assert control_file.is_file()

    lock.clear_stop_signal()
    assert lock.check_stop_signal() is False
    assert not control_file.is_file()
