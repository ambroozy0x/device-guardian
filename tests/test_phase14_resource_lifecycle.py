"""Phase 14 Resource Lifecycle & Leak Defense Tests for Device Guardian.

Verifies:
- Repeated startup/shutdown cycles do not leak threads or locks.
- Idempotent start and stop behavior.
- Clean resource reclamation on shutdown.
- Bounded memory consumption for duplicate log filters under churn.
"""

from __future__ import annotations

import logging
from pathlib import Path
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from device_guardian.camera.capture import CameraError, capture_photo
from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.logger import DuplicateLogFilter
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.single_instance import SingleInstanceLock


class DummyMonitor(BaseAuthenticationMonitor):
    def is_available(self) -> tuple[bool, str]:
        return True, "Available"

    def get_source_name(self) -> str:
        return "DummyMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list:
        return []


def test_repeated_runtime_lifecycle_no_thread_leak(tmp_path: Path) -> None:
    """Verify that repeated start/stop cycles do not accumulate background worker threads."""
    initial_threads = threading.active_count()

    status_file = tmp_path / "runtime_status.json"
    lock_file = tmp_path / "runtime.lock"
    cfg = AppConfig(
        telegram_alert_enabled=False,
        camera_alert_enabled=False,
        location_alert_enabled=False,
        single_instance_enabled=True,
    )

    det_mgr = DetectionManager(config=cfg, monitor=DummyMonitor())
    lock = SingleInstanceLock(lock_file_path=lock_file)
    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=det_mgr,
        single_instance_lock=lock,
        status_file_path=status_file,
        poll_interval=0.1,
    )

    # Perform 5 start/stop cycles
    for cycle in range(5):
        assert runtime.start(blocking=False) is True
        assert runtime.is_running() is True
        time.sleep(0.05)
        assert runtime.stop(timeout=2.0) is True
        assert runtime.is_running() is False
        assert not lock.is_locked()

    # Allow tiny grace period for OS thread cleanup
    time.sleep(0.1)
    current_threads = threading.active_count()
    assert current_threads <= initial_threads + 1


def test_runtime_idempotent_operations(tmp_path: Path) -> None:
    """Verify that start() and stop() are completely idempotent."""
    cfg = AppConfig(
        telegram_alert_enabled=False,
        single_instance_enabled=False,
    )
    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=DetectionManager(config=cfg, monitor=DummyMonitor()),
        status_file_path=tmp_path / "idempotent_status.json",
        poll_interval=0.1,
    )

    # Multiple stops when already stopped
    assert runtime.stop() is True
    assert runtime.stop() is True

    # Start
    assert runtime.start(blocking=False) is True
    # Start again while running should return True without duplicate workers
    assert runtime.start(blocking=False) is True

    # Stop once
    assert runtime.stop() is True
    # Stop again
    assert runtime.stop() is True
    assert runtime.is_running() is False


def test_duplicate_log_filter_cache_bounding() -> None:
    """Verify that DuplicateLogFilter cache is strictly bounded and cannot grow indefinitely."""
    max_size = 50
    f = DuplicateLogFilter(max_repeats=3, window_seconds=10.0, max_cache_size=max_size)

    # Inject 200 distinct log messages
    for i in range(200):
        rec = logging.LogRecord(
            name=f"test.logger.{i}",
            level=logging.WARNING,
            pathname="test.py",
            lineno=i,
            msg=f"Distinct log message number {i}",
            args=(),
            exc_info=None,
        )
        f.filter(rec)

    # Cache should never exceed max_cache_size
    assert len(f._cache) <= max_size


def test_camera_resource_release_on_error(tmp_path: Path) -> None:
    """Verify camera capture releases OpenCV resources when an error occurs."""
    with patch("cv2.VideoCapture") as mock_cap_cls:
        mock_cap = MagicMock()
        mock_cap.isOpened.return_value = False
        mock_cap_cls.return_value = mock_cap

        with pytest.raises(CameraError):
            capture_photo(camera_index=99, output_dir=tmp_path)

        # Release must have been called despite failure to open
        assert mock_cap.release.called
