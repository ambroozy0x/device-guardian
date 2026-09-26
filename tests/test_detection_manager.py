"""Unit tests for DetectionManager."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

from device_guardian.alerts.pipeline import AlertResult
from device_guardian.config import AppConfig
from device_guardian.detection.cooldown import AlertCooldownManager
from device_guardian.detection.manager import DetectionManager, NullAuthenticationMonitor
from device_guardian.detection.models import (
    AuthenticationFailureEvent,
    DetectionStatus,
    MonitorState,
)
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.detection.voice import OfflineVoiceWarning


def _make_test_config() -> AppConfig:
    return AppConfig(
        telegram_bot_token="123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567",
        telegram_chat_id="987654321",
        auth_failure_threshold=3,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        voice_warning_enabled=True,
        voice_warning_cooldown_seconds=60.0,
    )


def test_detection_manager_initialization() -> None:
    """Verify default initialization and configuration wiring."""
    cfg = _make_test_config()
    mgr = DetectionManager(config=cfg)

    assert mgr.threshold_engine.threshold == 3
    assert mgr.threshold_engine.window_seconds == 60.0
    assert mgr.cooldown_manager.cooldown_seconds == 300.0
    assert mgr.voice_warning.enabled is True
    assert mgr.state == MonitorState.READY


def test_detection_manager_status_delegation() -> None:
    """Verify get_monitor_status delegates to underlying monitor."""
    cfg = _make_test_config()
    mock_mon = MagicMock()
    mock_mon.is_available.return_value = (True, "System log is operational.")

    mgr = DetectionManager(config=cfg, monitor=mock_mon)
    status, msg = mgr.get_monitor_status()
    assert status == DetectionStatus.READY
    assert "operational" in msg

    mock_mon.is_available.return_value = (False, "Permission denied.")
    status2, msg2 = mgr.get_monitor_status()
    assert status2 == DetectionStatus.UNAVAILABLE
    assert "Permission denied" in msg2


def test_detection_manager_below_threshold_does_not_alert() -> None:
    """Verify single event below threshold does not dispatch alert."""
    cfg = _make_test_config()
    mock_dispatcher = MagicMock()
    mock_voice = MagicMock()

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    ev = AuthenticationFailureEvent(username="user1")
    result = mgr.process_event(ev)

    assert result is False
    assert mgr.total_events_processed == 1
    assert mgr.alerts_triggered == 0
    mock_dispatcher.assert_not_called()
    mock_voice.speak.assert_not_called()


def test_detection_manager_threshold_reached_triggers_alert_and_voice() -> None:
    """Verify reaching threshold triggers voice warning and alert pipeline."""
    cfg = _make_test_config()
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_voice = MagicMock()
    mock_voice.enabled = True
    mock_voice.can_speak.return_value = True

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    # Process events up to threshold (3)
    ev1 = AuthenticationFailureEvent(username="u1")
    ev2 = AuthenticationFailureEvent(username="u1")
    ev3 = AuthenticationFailureEvent(username="u1")

    assert mgr.process_event(ev1) is False
    assert mgr.process_event(ev2) is False
    assert mgr.process_event(ev3) is True

    assert mgr.alerts_triggered == 1
    mock_voice.speak.assert_called_once()
    mock_dispatcher.assert_called_once()
    call_kwargs = mock_dispatcher.call_args[1]
    assert "Repeated authentication failures detected" in call_kwargs["reason"]
    # Cooldown should now be active
    assert mgr.cooldown_manager.is_in_cooldown() is True


def test_detection_manager_cooldown_suppression() -> None:
    """Verify subsequent bursts during cooldown are suppressed."""
    cfg = _make_test_config()
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_voice = MagicMock()
    mock_voice.enabled = False

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    # First burst of 3
    for _ in range(3):
        mgr.process_event(AuthenticationFailureEvent(username="u1"))
    assert mgr.alerts_triggered == 1
    assert mock_dispatcher.call_count == 1

    # Second burst of 3 during cooldown
    for _ in range(3):
        mgr.process_event(AuthenticationFailureEvent(username="u1"))

    # Still only 1 alert dispatched, 1 burst suppressed
    assert mgr.alerts_triggered == 1
    assert mgr.alerts_suppressed_by_cooldown == 1
    assert mock_dispatcher.call_count == 1


def test_detection_manager_synthetic_test() -> None:
    """Verify synthetic test triggers pipeline with mock events."""
    cfg = _make_test_config()
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_voice = MagicMock()
    mock_voice.enabled = False

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    success = mgr.run_synthetic_test(count=3)
    assert success is True
    assert mgr.alerts_triggered == 1
    mock_dispatcher.assert_called_once()


def test_detection_manager_monitoring_loop_clean_exit() -> None:
    """Verify monitoring loop runs and stops cleanly using stop_event."""
    cfg = _make_test_config()
    mock_mon = MagicMock()
    mock_mon.poll.return_value = []
    mock_mon.get_source_name.return_value = "MockMonitor"

    mgr = DetectionManager(config=cfg, monitor=mock_mon)

    stop_event = threading.Event()
    # Trigger stop immediately after starting
    stop_event.set()

    mgr.run_monitoring_loop(sleep_interval=0.01, stop_event=stop_event)

    mock_mon.start.assert_called_once()
    mock_mon.stop.assert_called_once()


def test_null_authentication_monitor() -> None:
    """Verify NullAuthenticationMonitor behavior."""
    null_mon = NullAuthenticationMonitor()
    ok, msg = null_mon.is_available()
    assert ok is False
    assert "not supported" in msg
    assert null_mon.poll() == []
    null_mon.start()
    null_mon.stop()
