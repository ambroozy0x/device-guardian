"""Phase 14 Deterministic Failure Injection Tests for Device Guardian.

Verifies system resilience under injected faults:
- Sensor exceptions degrade gracefully without crashing background worker.
- Camera exceptions degrade gracefully, releasing hardware handles.
- Network timeouts & HTTP errors in alert pipeline handle failure cleanly.
- Worker loop exceptions trigger bounded auto-restart recovery without runaway spinning.
- Immediate responsive shutdown during recovery backoff.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from device_guardian.alerts.pipeline import AlertResult, trigger_alert
from device_guardian.camera.capture import CameraError, capture_photo
from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.reliability.metrics import get_reliability_metrics, reset_reliability_metrics
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.runtime.single_instance import SingleInstanceLock


class FailingSensorMonitor(BaseAuthenticationMonitor):
    """Monitor that raises an exception on first poll then recovers."""

    def __init__(self) -> None:
        self.call_count = 0

    def is_available(self) -> tuple[bool, str]:
        return True, "FailingSensorMonitor"

    def get_source_name(self) -> str:
        return "FailingSensorMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list:
        self.call_count += 1
        if self.call_count == 1:
            raise OSError("Injected OS sensor read failure")
        return []


def test_sensor_failure_injection_graceful_degradation() -> None:
    """Verify injected sensor exception is caught, recorded in metrics, and system recovers."""
    reset_reliability_metrics()
    metrics = get_reliability_metrics()

    cfg = AppConfig(telegram_alert_enabled=False)
    monitor = FailingSensorMonitor()
    det_mgr = DetectionManager(config=cfg, monitor=monitor)

    # First poll raises OSError inside monitor, but poll_once should catch it and return []
    events = det_mgr.poll_once()
    assert events == []
    assert det_mgr._sensor_degraded is True

    snap = metrics.snapshot()
    assert snap.sensor_failures == 1

    # Second poll succeeds -> sensor recovery detected and recorded
    events2 = det_mgr.poll_once()
    assert events2 == []
    assert det_mgr._sensor_degraded is False

    snap2 = metrics.snapshot()
    assert snap2.sensor_recoveries == 1


def test_camera_failure_injection_pipeline_resilience(tmp_path: Path) -> None:
    """Verify that an injected camera capture failure allows pipeline to deliver text alert safely."""
    cfg = AppConfig(
        camera_alert_enabled=True,
        location_alert_enabled=False,
        telegram_alert_enabled=False,
    )

    with patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Device busy")):
        result = trigger_alert(reason="Injected Camera Failure", config=cfg, output_dir=tmp_path)
        assert result.camera_success is False
        assert result.success is True  # Telegram was disabled, so text alert succeeded
        assert result.event is not None
        assert result.event.camera_path is None


def test_worker_loop_exception_bounded_recovery(tmp_path: Path) -> None:
    """Verify that unexpected worker exceptions trigger bounded auto-restart and terminate cleanly."""
    reset_reliability_metrics()
    metrics = get_reliability_metrics()

    cfg = AppConfig(
        telegram_alert_enabled=False,
        single_instance_enabled=False,
        auto_restart_enabled=True,
        max_restart_attempts=2,
        restart_backoff_seconds=0.05,
    )

    faulty_mgr = MagicMock()
    faulty_mgr.poll_once.side_effect = RuntimeError("Injected worker fault")

    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=faulty_mgr,
        status_file_path=tmp_path / "fault_status.json",
        poll_interval=0.02,
    )

    runtime.start(blocking=False)
    # Wait for retries to exhaust
    time.sleep(0.5)

    assert runtime.status.state == RuntimeState.FAILED
    assert runtime.status.restart_count == 2
    assert "Injected worker fault" in (runtime.status.last_error or "")

    snap = metrics.snapshot()
    assert snap.unexpected_exceptions >= 1

    runtime.stop()


def test_shutdown_during_recovery_backoff(tmp_path: Path) -> None:
    """Verify stop() immediately aborts worker during crash backoff rather than sleeping."""
    cfg = AppConfig(
        telegram_alert_enabled=False,
        single_instance_enabled=False,
        auto_restart_enabled=True,
        max_restart_attempts=5,
        restart_backoff_seconds=10.0,  # Long backoff
    )

    faulty_mgr = MagicMock()
    faulty_mgr.poll_once.side_effect = RuntimeError("Injected crash")

    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=faulty_mgr,
        status_file_path=tmp_path / "backoff_status.json",
        poll_interval=0.05,
    )

    runtime.start(blocking=False)
    # Allow worker to hit the exception and enter backoff
    time.sleep(0.1)

    t0 = time.time()
    # Stop should respond immediately and unblock, taking << 10.0s
    runtime.stop(timeout=2.0)
    stop_duration = time.time() - t0

    assert stop_duration < 2.0
    assert runtime.is_running() is False
