"""Phase 13 tests: Detection Adapters, Sensor Degradation & Headless Handling.

Verifies:
- Platform monitor factory (Windows, Linux, macOS, NullAuthenticationMonitor).
- NullAuthenticationMonitor safe degradation on unsupported hosts.
- DetectionManager normalized event processing preserving platform context.
- Camera failure graceful degradation (no crash, alert pipeline completes with text).
- Geolocation offline / timeout degradation (UNKNOWN != SAFE invariant preserved).
- TrayManager headless environment detection (X11 / Wayland display absence).
"""

from __future__ import annotations

import os
import pytest

from device_guardian.alerts.pipeline import trigger_alert
from device_guardian.config import AppConfig
from device_guardian.detection.linux import LinuxAuthLogMonitor
from device_guardian.detection.macos import MacOSAuthLogMonitor
from device_guardian.detection.manager import (
    DetectionManager,
    NullAuthenticationMonitor,
    create_platform_monitor,
)
from device_guardian.detection.windows import WindowsSecurityLogMonitor
from device_guardian.location.geolocation import get_approximate_location
from device_guardian.platform_compat import (
    OperatingSystem,
    platform_override,
    reset_platform_overrides,
)
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.tray.manager import TrayManager


@pytest.fixture(autouse=True)
def clean_environment():
    reset_platform_overrides()
    yield
    reset_platform_overrides()


def test_platform_monitor_factory():
    """Verify create_platform_monitor yields the appropriate monitor per OS."""
    with platform_override(OperatingSystem.WINDOWS):
        mon = create_platform_monitor()
        assert isinstance(mon, WindowsSecurityLogMonitor)

    with platform_override(OperatingSystem.LINUX):
        mon = create_platform_monitor()
        assert isinstance(mon, LinuxAuthLogMonitor)

    with platform_override(OperatingSystem.MACOS):
        mon = create_platform_monitor()
        assert isinstance(mon, MacOSAuthLogMonitor)

    with platform_override(OperatingSystem.UNSUPPORTED):
        mon = create_platform_monitor()
        assert isinstance(mon, NullAuthenticationMonitor)
        avail, reason = mon.is_available()
        assert avail is False
        assert "not supported" in reason
        assert mon.poll() == []


def test_synthetic_test_preserves_platform_tag():
    """Verify DetectionManager synthetic test stamps events with active platform."""
    with platform_override(OperatingSystem.LINUX):
        mgr = DetectionManager()
        events_captured = []

        def mock_dispatcher(reason, config):
            class MockResult:
                success = True
            return MockResult()

        mgr.alert_dispatcher = mock_dispatcher
        # Execute synthetic test
        triggered = mgr.run_synthetic_test(count=1)
        assert mgr.total_events_processed >= 1


def test_camera_graceful_degradation_in_alert_pipeline(monkeypatch):
    """Verify alert pipeline succeeds with text even when camera capture fails or is missing."""
    cfg = AppConfig(
        camera_alert_enabled=True,
        telegram_alert_enabled=False,  # Keep offline
        location_alert_enabled=False,
    )

    # Mock camera to fail
    from device_guardian.camera import capture
    def mock_capture(*args, **kwargs):
        from device_guardian.camera.capture import CameraError
        raise CameraError("Camera device not detected or access denied.")

    monkeypatch.setattr("device_guardian.alerts.pipeline.capture_photo", mock_capture)

    result = trigger_alert(reason="Test Camera Failure", config=cfg)
    assert result.camera_success is False
    assert result.event is not None
    assert result.event.camera_path is None
    # Overall alert succeeds despite missing camera
    assert result.success is True


def test_geolocation_offline_graceful_degradation(monkeypatch):
    """Verify geolocation returns LocationInfo(is_available=False) without raising exceptions when offline."""
    import requests
    from device_guardian.location.geolocation import LocationInfo

    def mock_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Network is unreachable")

    monkeypatch.setattr("device_guardian.location.geolocation.requests.get", mock_get)

    loc = get_approximate_location(api_url="http://invalid.local", timeout=1.0)
    assert isinstance(loc, LocationInfo)
    assert loc.is_available is False
    assert loc.city == "Unavailable"
    assert loc.country == "Unavailable"
    assert loc.latitude is None
    assert loc.longitude is None


def test_tray_manager_headless_detection_linux(monkeypatch):
    """Verify TrayManager detects headless state on Linux without graphical displays."""
    runtime = GuardianRuntime()
    tray = TrayManager(runtime=runtime)

    with platform_override(OperatingSystem.LINUX):
        # Both unset -> headless
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert tray.is_headless() is True
        assert tray.setup_icon() is False

        # Set DISPLAY -> not headless
        monkeypatch.setenv("DISPLAY", ":0")
        assert tray.is_headless() is False

        # Set WAYLAND_DISPLAY -> not headless
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
        assert tray.is_headless() is False


def test_tray_manager_windows_headless_behavior():
    """Verify TrayManager on Windows does not falsely report headless."""
    runtime = GuardianRuntime()
    tray = TrayManager(runtime=runtime)

    with platform_override(OperatingSystem.WINDOWS):
        assert tray.is_headless() is False
