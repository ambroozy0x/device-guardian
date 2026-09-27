"""Resilience and crash recovery tests for background runtime (Phase 8)."""

from pathlib import Path
import threading
import time
from unittest.mock import MagicMock, patch
import uuid
import pytest

from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState, RuntimeStatus
from device_guardian.runtime.single_instance import SingleInstanceLock


class FailingMonitor(BaseAuthenticationMonitor):
    """Monitor that can be configured to raise exceptions during poll."""

    def __init__(self, failure_count: int = 1) -> None:
        self.failure_count = failure_count
        self.calls = 0

    def is_available(self) -> tuple[bool, str]:
        return True, "Mock failing monitor"

    def get_source_name(self) -> str:
        return "FailingMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list[AuthenticationFailureEvent]:
        self.calls += 1
        if self.calls <= self.failure_count:
            raise RuntimeError(f"Simulated monitor failure on poll {self.calls}")
        return []


def test_runtime_recovers_from_transient_worker_crash(tmp_path: Path):
    """Verify runtime recovers from a transient monitor crash without terminating."""
    status_file = tmp_path / "status.json"
    lock = SingleInstanceLock(
        lock_file_path=tmp_path / "test.lock",
        control_file_path=tmp_path / "test.control",
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )
    # Fails once then succeeds
    monitor = FailingMonitor(failure_count=1)
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TEST_TOKEN",
        telegram_chat_id="987654321",
        single_instance_enabled=False,
    )
    det_mgr = DetectionManager(config=cfg, monitor=monitor)

    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.05,
    )

    started = runtime.start(blocking=False)
    assert started is True
    time.sleep(0.3)

    # Runtime should still be running after recovering from transient crash
    assert runtime.is_running() is True
    assert runtime.status.state == RuntimeState.RUNNING

    runtime.stop()
    assert runtime.is_running() is False


def test_runtime_crash_loop_containment(tmp_path: Path):
    """Verify runtime enters FAILED state and halts after exceeding max restart attempts."""
    status_file = tmp_path / "status.json"
    lock = SingleInstanceLock(
        lock_file_path=tmp_path / "test.lock",
        control_file_path=tmp_path / "test.control",
        mutex_name=f"Local\\TestRuntime_{uuid.uuid4().hex}",
    )
    # Continuous failures
    monitor = FailingMonitor(failure_count=100)
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TEST_TOKEN",
        telegram_chat_id="987654321",
        single_instance_enabled=False,
        max_restart_attempts=2,
        restart_backoff_seconds=0.01,
    )
    det_mgr = DetectionManager(config=cfg, monitor=monitor)
    det_mgr.poll_once = MagicMock(side_effect=RuntimeError("Simulated monitor failure"))

    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.01,
    )

    started = runtime.start(blocking=False)
    assert started is True

    # Allow worker loop to execute consecutive failures and exhaust retries
    time.sleep(0.3)

    # Should have halted and transitioned to FAILED
    assert runtime.is_running() is False
    status = runtime.status
    assert status.state == RuntimeState.FAILED
    assert "simulated monitor failure" in str(status.last_error).lower()


def test_concurrent_runtime_start_single_instance_protection(tmp_path: Path):
    """Verify second runtime cannot start when single instance lock is held."""
    lock_file = tmp_path / "shared.lock"
    control_file = tmp_path / "shared.control"
    mutex_name = f"Local\\TestShared_{uuid.uuid4().hex}"

    lock1 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=mutex_name)
    lock2 = SingleInstanceLock(lock_file_path=lock_file, control_file_path=control_file, mutex_name=mutex_name)

    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TEST_TOKEN",
        telegram_chat_id="987654321",
        single_instance_enabled=True,
    )
    mon1 = FailingMonitor(failure_count=0)
    mon2 = FailingMonitor(failure_count=0)

    rt1 = GuardianRuntime(config=cfg, detection_manager=DetectionManager(config=cfg, monitor=mon1), single_instance_lock=lock1, status_file_path=tmp_path / "s1.json", poll_interval=0.05)
    rt2 = GuardianRuntime(config=cfg, detection_manager=DetectionManager(config=cfg, monitor=mon2), single_instance_lock=lock2, status_file_path=tmp_path / "s2.json", poll_interval=0.05)

    assert rt1.start(blocking=False) is True
    assert rt1.is_running() is True

    # Second instance must fail to start
    assert rt2.start(blocking=False) is False
    assert rt2.is_running() is False

    rt1.stop()
    assert rt1.is_running() is False
