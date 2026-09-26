"""Tests for Phase 9 Single-Instance Lock Hardening and PID Verification."""

from __future__ import annotations

import json
import os
from pathlib import Path
import uuid
import pytest

from device_guardian.runtime.single_instance import SingleInstanceLock


def test_lock_acquire_and_release(tmp_path: Path):
    """Verify clean acquisition and release of SingleInstanceLock."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)

    acquired = lock.acquire()
    assert acquired is True
    assert lock.is_locked() is True
    assert lock_file.is_file()

    lock.release()
    assert lock.is_locked() is False
    assert not lock_file.exists()


def test_lock_conflict_same_process(tmp_path: Path):
    """Verify second lock cannot acquire while first lock is held."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock1 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)
    lock2 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)

    assert lock1.acquire() is True
    assert lock2.acquire() is False

    lock1.release()
    # Now lock2 should be able to acquire
    assert lock2.acquire() is True
    lock2.release()


def test_lock_malformed_json_recovery(tmp_path: Path):
    """Verify malformed JSON lock file is safely treated as stale and cleaned up."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock_file.write_text("{corrupt-json-not-closed...", encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)
    # Acquisition should succeed by recovering from the corrupted file
    assert lock.acquire() is True
    assert lock.is_locked() is True
    lock.release()


def test_lock_negative_pid_rejected(tmp_path: Path):
    """Verify lock file with negative PID is treated as invalid and recovered."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock_file.write_text(json.dumps({"pid": -9999, "created_at": "2026-09-26T00:00:00"}), encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)
    assert lock.acquire() is True
    lock.release()


def test_lock_non_integer_pid_rejected(tmp_path: Path):
    """Verify lock file with string/invalid PID type is recovered."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock_file.write_text(json.dumps({"pid": "invalid_pid_string"}), encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)
    assert lock.acquire() is True
    lock.release()


def test_lock_stale_dead_pid(tmp_path: Path):
    """Verify lock held by a dead process PID is detected as stale and recovered."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    # An extraordinarily high PID that cannot be running
    dead_pid = 9999999
    lock_file.write_text(json.dumps({"pid": dead_pid, "started_at": 1000.0}), encoding="utf-8")

    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)
    assert lock.acquire() is True
    lock.release()


def test_lock_signal_stop_via_control_channel(tmp_path: Path):
    """Verify signal_stop writes structured stop message and check_stop_signal detects it."""
    lock_file = tmp_path / "runtime.lock"
    ctl_file = tmp_path / "runtime.control"
    m_name = f"Local\\TestLock_{uuid.uuid4().hex}"
    lock = SingleInstanceLock(lock_file_path=lock_file, control_file_path=ctl_file, mutex_name=m_name)

    assert lock.check_stop_signal() is False

    # Signal stop
    assert lock.signal_stop() is True
    assert lock.check_stop_signal() is True

    # Clear stop
    lock.clear_stop_signal()
    assert lock.check_stop_signal() is False
