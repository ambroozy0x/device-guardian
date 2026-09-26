"""Integration tests for Phase 4 Smart Filtering, Environmental Triggers, and DetectionManager."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from device_guardian.alerts.pipeline import AlertResult, trigger_alert
from device_guardian.config import AppConfig
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.detector import EnvironmentalDetector
from device_guardian.environment.models import (
    DeviceState,
    EnvironmentalContext,
    NetworkContext,
    NetworkState,
)
from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.location.geolocation import LocationInfo


def _make_phase4_config(
    trusted_users: list[str] = None,
    trusted_networks: list[str] = None,
    trusted_auth_types: list[str] = None,
    smart_filtering_enabled: bool = True,
    camera_alert_enabled: bool = True,
    location_alert_enabled: bool = True,
    telegram_alert_enabled: bool = True,
    require_context_for_alert: bool = False,
) -> AppConfig:
    return AppConfig(
        telegram_bot_token="123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567",
        telegram_chat_id="987654321",
        auth_failure_threshold=3,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        voice_warning_enabled=True,
        smart_filtering_enabled=smart_filtering_enabled,
        trusted_users=trusted_users or [],
        trusted_networks=trusted_networks or [],
        trusted_auth_types=trusted_auth_types or [],
        camera_alert_enabled=camera_alert_enabled,
        location_alert_enabled=location_alert_enabled,
        telegram_alert_enabled=telegram_alert_enabled,
        require_context_for_alert=require_context_for_alert,
    )


def test_detection_manager_suppresses_trusted_user_burst() -> None:
    """Verify bursts by configured trusted users are suppressed by the smart filter."""
    cfg = _make_phase4_config(trusted_users=["alice"])
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_voice = MagicMock()
    mock_voice.enabled = True
    mock_voice.can_speak.return_value = True

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    # Inject 3 events for trusted user "alice"
    for _ in range(3):
        res = mgr.process_event(AuthenticationFailureEvent(username="alice"))
        assert res is False

    assert mgr.alerts_triggered == 0
    assert mgr.alerts_suppressed_by_filter == 1
    mock_dispatcher.assert_not_called()
    mock_voice.speak.assert_not_called()


def test_detection_manager_dispatches_untrusted_burst() -> None:
    """Verify bursts by untrusted users trigger alert and voice warning."""
    cfg = _make_phase4_config(trusted_users=["alice"])
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_voice = MagicMock()
    mock_voice.enabled = True
    mock_voice.can_speak.return_value = True

    mgr = DetectionManager(
        config=cfg,
        voice_warning=mock_voice,
        alert_dispatcher=mock_dispatcher,
    )

    # Events 1 and 2 below threshold
    assert mgr.process_event(AuthenticationFailureEvent(username="unknown_user")) is False
    assert mgr.process_event(AuthenticationFailureEvent(username="unknown_user")) is False

    # Event 3 reaches threshold and qualifies
    assert mgr.process_event(AuthenticationFailureEvent(username="unknown_user")) is True

    assert mgr.alerts_triggered == 1
    assert mgr.alerts_suppressed_by_filter == 0
    mock_dispatcher.assert_called_once()
    mock_voice.speak.assert_called_once()


def test_safety_gates_in_alert_pipeline() -> None:
    """Verify camera, location, and telegram safety gates can be individually disabled."""
    cfg = _make_phase4_config(
        camera_alert_enabled=False,
        location_alert_enabled=False,
        telegram_alert_enabled=False,
    )

    result = trigger_alert(reason="Test Safety Gate Alert", config=cfg)

    # All three actions should report as skipped/bypassed without error
    assert result.camera_success is False
    assert result.location_success is False
    assert result.telegram_success is True
    assert result.success is True


def test_detection_manager_require_context_filter_unknown_state() -> None:
    """Verify require_context_for_alert filters bursts when context is completely UNKNOWN."""
    cfg = _make_phase4_config()
    cfg.require_context_for_alert = True

    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_env_detector = MagicMock()
    mock_env_detector.collect_context.return_value = EnvironmentalContext(
        device_state=DeviceState.UNKNOWN,
        network_context=NetworkContext(state=NetworkState.UNKNOWN),
    )

    mgr = DetectionManager(
        config=cfg,
        alert_dispatcher=mock_dispatcher,
        environmental_detector=mock_env_detector,
    )

    for _ in range(3):
        res = mgr.process_event(AuthenticationFailureEvent(username="intruder_sim"))
        assert res is False

    assert mgr.alerts_triggered == 0
    assert mgr.alerts_suppressed_by_filter == 1
    mock_dispatcher.assert_not_called()


def test_detection_manager_synthetic_test_with_filtering_enabled() -> None:
    """Verify run_synthetic_test completes through the smart filtering layer."""
    cfg = _make_phase4_config(smart_filtering_enabled=True)
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


def test_detection_manager_trusted_network_suppression() -> None:
    """Verify bursts originating from explicitly trusted networks are filtered."""
    cfg = _make_phase4_config()
    cfg.trusted_networks = ["net_192.168.1.0/24"]

    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_env_detector = MagicMock()
    mock_env_detector.collect_context.return_value = EnvironmentalContext(
        network_context=NetworkContext(
            connected=True,
            state=NetworkState.CONNECTED,
            network_identifier="net_192.168.1.0/24",
        )
    )

    mgr = DetectionManager(
        config=cfg,
        alert_dispatcher=mock_dispatcher,
        environmental_detector=mock_env_detector,
    )

    for _ in range(3):
        res = mgr.process_event(AuthenticationFailureEvent(username="guest"))
        assert res is False

    assert mgr.alerts_triggered == 0
    assert mgr.alerts_suppressed_by_filter == 1
    mock_dispatcher.assert_not_called()


def test_synthetic_test_isolation_cannot_bypass_production() -> None:
    """Verify production events with synthetic-looking strings cannot bypass trusted filtering."""
    cfg = _make_phase4_config(trusted_users=["alice"])

    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mgr = DetectionManager(
        config=cfg,
        alert_dispatcher=mock_dispatcher,
    )

    # A real event that happens to have source="SyntheticTestMonitor" or username="alice"
    # must NOT bypass the trusted context rule when is_synthetic is False
    crafted_event = AuthenticationFailureEvent(
        username="alice",  # Trusted user
        source="SyntheticTestMonitor",  # Crafting test monitor name
        details={},
    )

    for _ in range(3):
        res = mgr.process_event(crafted_event, is_synthetic=False)
        assert res is False

    # Trusted user rule must still have filtered the event
    assert mgr.alerts_triggered == 0
    assert mgr.alerts_suppressed_by_filter == 1
    mock_dispatcher.assert_not_called()


def test_safety_gates_individual_controls() -> None:
    """Verify each safety gate (camera, location, telegram) can be operated independently."""
    # 1. Camera disabled only
    cfg_no_cam = _make_phase4_config(camera_alert_enabled=False, location_alert_enabled=True, telegram_alert_enabled=True)
    with patch("device_guardian.alerts.pipeline.capture_photo") as mock_cam, \
         patch("device_guardian.alerts.pipeline.get_approximate_location") as mock_loc, \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls:

        mock_loc.return_value = LocationInfo(
            is_available=True,
            city="SampleCity",
            region="SampleRegion",
            country="SampleCountry",
            latitude=12.345678,
            longitude=98.765432,
        )
        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = MagicMock(success=True, error_message=None)
        mock_tg_cls.return_value = mock_tg_instance

        res = trigger_alert(reason="Test No Cam", config=cfg_no_cam)
        mock_cam.assert_not_called()
        mock_loc.assert_called_once()
        assert res.camera_success is False
        assert res.location_success is True

    # 2. Location disabled only
    cfg_no_loc = _make_phase4_config(camera_alert_enabled=True, location_alert_enabled=False, telegram_alert_enabled=True)
    with patch("device_guardian.alerts.pipeline.capture_photo") as mock_cam, \
         patch("device_guardian.alerts.pipeline.get_approximate_location") as mock_loc, \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls:

        mock_cam.return_value = None
        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = MagicMock(success=True, error_message=None)
        mock_tg_cls.return_value = mock_tg_instance

        res = trigger_alert(reason="Test No Loc", config=cfg_no_loc)
        mock_loc.assert_not_called()
        assert res.location_success is False

    # 3. Telegram disabled only
    cfg_no_tg = _make_phase4_config(camera_alert_enabled=True, location_alert_enabled=True, telegram_alert_enabled=False)
    with patch("device_guardian.alerts.pipeline.capture_photo") as mock_cam, \
         patch("device_guardian.alerts.pipeline.get_approximate_location") as mock_loc, \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls:

        mock_cam.return_value = None
        mock_loc.return_value = LocationInfo(is_available=False)

        res = trigger_alert(reason="Test No TG", config=cfg_no_tg)
        mock_tg_cls.return_value.send_message.assert_not_called()
        mock_tg_cls.return_value.send_photo.assert_not_called()
        assert res.success is True


def test_unknown_context_with_require_context_false_dispatches_alert() -> None:
    """Verify UNKNOWN context does not suppress real alerts when require_context_for_alert=False."""
    cfg = _make_phase4_config(require_context_for_alert=False)

    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))
    mock_env_detector = MagicMock()
    mock_env_detector.collect_context.return_value = EnvironmentalContext(
        device_state=DeviceState.UNKNOWN,
        network_context=NetworkContext(state=NetworkState.UNKNOWN),
    )

    mgr = DetectionManager(
        config=cfg,
        alert_dispatcher=mock_dispatcher,
        environmental_detector=mock_env_detector,
    )

    for _ in range(3):
        res = mgr.process_event(AuthenticationFailureEvent(username="unknown_attacker"))

    # When require_context_for_alert is False, UNKNOWN != THREAT does not suppress real alerts!
    assert res is True
    assert mgr.alerts_triggered == 1
    mock_dispatcher.assert_called_once()


def test_detection_manager_records_auth_context_change_trigger() -> None:
    """Verify transitions in environmental state across auth failures record trigger events."""
    cfg = _make_phase4_config()
    mock_dispatcher = MagicMock(return_value=AlertResult(success=True, reason="Test"))

    # Create detector that returns ACTIVE on first call, LOCKED on second
    mock_dev = MagicMock()
    mock_dev.detect_device_state.side_effect = [DeviceState.ACTIVE, DeviceState.LOCKED]
    env_detector = EnvironmentalDetector(
        device_detector=mock_dev,
        network_context_enabled=False,
    )

    mgr = DetectionManager(
        config=cfg,
        alert_dispatcher=mock_dispatcher,
        environmental_detector=env_detector,
    )

    ev1 = AuthenticationFailureEvent(username="user1")
    mgr.process_event(ev1)

    ev2 = AuthenticationFailureEvent(username="user2")
    mgr.process_event(ev2)

    events = env_detector.get_recent_events()
    auth_change_events = [e for e in events if e.event_type == "AUTH_FAILURE_CONTEXT_CHANGE"]
    assert len(auth_change_events) >= 1
    assert "Device [ACTIVE -> LOCKED]" in auth_change_events[0].description


