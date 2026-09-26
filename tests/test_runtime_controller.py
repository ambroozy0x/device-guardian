"""Tests for GuardianRuntime controller and background lifecycle (Phase 5)."""

import json
from pathlib import Path
import time
from unittest.mock import MagicMock, patch
import uuid
import pytest

from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState, RuntimeStatus
from device_guardian.runtime.single_instance import SingleInstanceLock


class DummyMonitor(BaseAuthenticationMonitor):
    def is_available(self):
        return True, "Dummy available"

    def get_source_name(self):
        return "DummyMonitor"

    def start(self):
        pass

    def stop(self):
        pass

    def poll(self):
        return []


@pytest.fixture
def test_config():
    return AppConfig(
        telegram_bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        telegram_chat_id="123456789",
        auth_failure_threshold=3,
        auto_restart_enabled=True,
        max_restart_attempts=2,
        restart_backoff_seconds=0.01,
        single_instance_enabled=True,
    )


def test_runtime_initial_state(test_config, tmp_path):
    """Verify runtime initializes in STOPPED state with zero metrics."""
    status_file = tmp_path / "status.json"
    runtime = GuardianRuntime(
        config=test_config,
        status_file_path=status_file,
    )
    assert runtime.status.state == RuntimeState.STOPPED
    assert runtime.status.is_running() is False
    assert runtime.status.uptime_seconds == 0.0


def test_runtime_start_and_stop(test_config, tmp_path):
    """Verify standard start and stop transitions."""
    status_file = tmp_path / "status.json"
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    lock = SingleInstanceLock(
        lock_file_path=lock_file,
        control_file_path=control_file,
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )

    mock_monitor = DummyMonitor()
    det_mgr = DetectionManager(config=test_config, monitor=mock_monitor)

    runtime = GuardianRuntime(
        config=test_config,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.05,
    )

    started = runtime.start(blocking=False)
    assert started is True
    assert runtime.is_running() is True
    assert status_file.is_file()

    # Verify status contents
    data = json.loads(status_file.read_text(encoding="utf-8"))
    assert data["state"] == "RUNNING"
    assert data["single_instance_active"] is True

    stopped = runtime.stop(timeout=2.0)
    assert stopped is True
    assert runtime.is_running() is False
    assert runtime.status.state == RuntimeState.STOPPED


def test_runtime_idempotent_lifecycle(test_config, tmp_path):
    """Verify repeated start and stop calls do not crash or create duplicate threads."""
    status_file = tmp_path / "status.json"
    lock_file = tmp_path / "test.lock"
    lock = SingleInstanceLock(
        lock_file_path=lock_file,
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )
    det_mgr = DetectionManager(config=test_config, monitor=DummyMonitor())

    runtime = GuardianRuntime(
        config=test_config,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.05,
    )

    assert runtime.start(blocking=False) is True
    # Duplicate start
    assert runtime.start(blocking=False) is True

    assert runtime.stop() is True
    # Duplicate stop
    assert runtime.stop() is True


def test_runtime_single_instance_block(test_config, tmp_path):
    """Verify start fails when single-instance lock is held by another process."""
    status_file = tmp_path / "status.json"
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    m_name = f"Local\\TestRuntime_{uuid.uuid4().hex}"

    # Pre-acquire lock
    holder = SingleInstanceLock(
        lock_file_path=lock_file,
        control_file_path=control_file,
        mutex_name=m_name,
    )
    holder.acquire()

    contender = SingleInstanceLock(
        lock_file_path=lock_file,
        control_file_path=control_file,
        mutex_name=m_name,
    )
    with patch.object(contender, "_is_pid_alive", return_value=True):
        runtime = GuardianRuntime(
            config=test_config,
            single_instance_lock=contender,
            status_file_path=status_file,
        )
        started = runtime.start(blocking=False)
        assert started is False
        assert runtime.status.state == RuntimeState.STOPPED
        assert "single instance" in runtime.status.last_error.lower()

    holder.release()


def test_runtime_ipc_stop_signal(test_config, tmp_path):
    """Verify IPC stop signal cleanly halts worker loop."""
    status_file = tmp_path / "status.json"
    lock_file = tmp_path / "test.lock"
    control_file = tmp_path / "test.control"
    lock = SingleInstanceLock(
        lock_file_path=lock_file,
        control_file_path=control_file,
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )

    det_mgr = DetectionManager(config=test_config, monitor=DummyMonitor())
    runtime = GuardianRuntime(
        config=test_config,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.05,
    )

    runtime.start(blocking=False)
    assert runtime.is_running() is True

    # Signal stop via IPC file
    lock.signal_stop()

    # Wait for worker loop to pick up stop signal
    for _ in range(30):
        time.sleep(0.05)
        if not runtime.is_running():
            break

    assert runtime.is_running() is False
    runtime.stop()


def test_runtime_bounded_auto_restart_recovery(test_config, tmp_path):
    """Verify worker auto-restart recovers from crash but halts at max attempts."""
    status_file = tmp_path / "status.json"
    lock_file = tmp_path / "test.lock"
    lock = SingleInstanceLock(
        lock_file_path=lock_file,
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )

    crashing_monitor = MagicMock()
    crashing_monitor.poll.side_effect = RuntimeError("Simulated crash")
    crashing_monitor.get_source_name.return_value = "CrashingMonitor"

    det_mgr = DetectionManager(config=test_config, monitor=crashing_monitor)
    runtime = GuardianRuntime(
        config=test_config,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.01,
    )

    runtime.start(blocking=False)

    # Wait for crash retries to exhaust
    for _ in range(60):
        time.sleep(0.05)
        if runtime.status.state == RuntimeState.FAILED:
            break

    assert runtime.status.state == RuntimeState.FAILED
    assert runtime.status.restart_count == test_config.max_restart_attempts
    runtime.stop()
