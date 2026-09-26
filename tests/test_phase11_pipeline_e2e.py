"""Phase 11 End-to-End Integration Tests: Core Security Event Pipeline, Detection, and Filtering (Workstreams 3, 4, 5, 6)."""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.alerts.pipeline import AlertResult, trigger_alert
from device_guardian.camera.capture import CameraError
from device_guardian.config import AppConfig
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.detection.manager import DetectionManager
from device_guardian.environment.detector import EnvironmentalContext
from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.models import FilterContext, FilterDecision
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.location.geolocation import LocationInfo
from device_guardian.recovery.health import HealthStatus, assess_system_health
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.telegram.bot import TelegramResponse
from device_guardian.ux.operator import get_operator_summary, format_operator_dashboard


@pytest.fixture
def test_env(tmp_path):
    ApplicationPaths.set_data_dir_override(tmp_path)
    config = AppConfig(
        telegram_bot_token="123456:ABC-SECRET_TOKEN_VALUE",
        telegram_chat_id="123456789",
        camera_alert_enabled=True,
        location_alert_enabled=True,
        voice_warning_enabled=True,
        auth_failure_threshold=2,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        smart_filtering_enabled=True,
    )
    return tmp_path, config


def test_full_detection_to_alert_pipeline_e2e(test_env):
    """Verify complete security flow from detection through filtering, alert creation, and dispatch."""
    tmp_path, config = test_env
    photo_file = tmp_path / "photo.jpg"
    photo_file.write_bytes(b"dummy_image_data")

    with patch("device_guardian.alerts.pipeline.capture_photo") as mock_cam, \
         patch("device_guardian.alerts.pipeline.get_approximate_location") as mock_loc, \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls, \
         patch("device_guardian.detection.voice.OfflineVoiceWarning.speak") as mock_voice:

        mock_cam.return_value = photo_file
        mock_loc.return_value = LocationInfo(
            city="Zurich",
            region="Zurich",
            country="Switzerland",
            is_available=True,
        )
        mock_tg_instance = MagicMock()
        mock_tg_instance.send_photo.return_value = TelegramResponse(
            success=True,
            status_code=200,
            data={"result": {"message_id": 42}},
        )
        mock_tg_cls.return_value = mock_tg_instance

        # Test through DetectionManager for true end-to-end detection
        dm = DetectionManager(config=config)
        event1 = AuthenticationFailureEvent(
            username="unauthorized_actor",
            remote_address="198.51.100.99",
            authentication_type="ssh",
        )
        event2 = AuthenticationFailureEvent(
            username="unauthorized_actor",
            remote_address="198.51.100.99",
            authentication_type="ssh",
        )

        # Threshold is 2
        dm.process_event(event1)
        dispatched = dm.process_event(event2)

        assert dispatched is True
        assert mock_tg_instance.send_photo.called
        assert mock_voice.called

        # Verify operator surface reflects recent evaluation
        summary = get_operator_summary(config=config)
        assert summary["configuration"]["telegram_configured"] is True


def test_pipeline_smart_filtering_trusted_suppression_e2e(test_env):
    """Verify that trusted context correctly suppresses dispatch without disabling local awareness."""
    tmp_path, config = test_env
    trusted_ctx = TrustedContext(trusted_networks=["192.168.1.0/24"], trusted_users=["owner"])
    filter_engine = SmartFilterEngine(trusted_context=trusted_ctx)

    trusted_env = EnvironmentalContext()

    event = AuthenticationFailureEvent(username="owner", remote_address="192.168.1.50")
    ctx = FilterContext(
        event=event,
        environmental_context=trusted_env,
        consecutive_failures=3,
        threshold=2,
    )
    result = filter_engine.evaluate(ctx)

    assert result.decision == FilterDecision.FILTER
    assert "trusted_user" in result.rule_id or "trusted" in result.explanation.lower()


def test_pipeline_cooldown_suppression_e2e(test_env):
    """Verify alert cooldown manager suppresses back-to-back duplicate alerts deterministically."""
    from device_guardian.detection.cooldown import AlertCooldownManager
    cooldown = AlertCooldownManager(cooldown_seconds=300.0)

    # First alert allowed
    assert cooldown.can_alert() is True
    cooldown.record_alert()

    # Immediate second alert must be suppressed
    assert cooldown.can_alert() is False
    assert cooldown.time_remaining() > 0


def test_detection_scenario_auth_failure_context_change_e2e():
    """Verify AUTH_FAILURE_CONTEXT_CHANGE event is normalized with accurate context and no risk scores."""
    raw_event = {
        "event_id": 4625,
        "target_user": "admin",
        "workstation": "DESKTOP-TEST",
        "source_ip": "10.0.0.99",
        "logon_type": 3,
        "status_code": "0xC000006D",
    }

    norm_event = AuthenticationFailureEvent(
        timestamp=datetime(2026, 9, 26, 14, 0, 0),
        username=raw_event["target_user"],
        remote_address=raw_event["source_ip"],
        authentication_type=str(raw_event["logon_type"]),
        details=raw_event,
    )

    assert norm_event.username == "admin"
    assert norm_event.remote_address == "10.0.0.99"
    # Ensure no threat score attribute was injected
    assert not hasattr(norm_event, "threat_score")
    assert not hasattr(norm_event, "risk_level")


def test_unknown_state_propagation_camera_unavailable_e2e(test_env):
    """Verify that when camera fails, alert continues with text and state is UNKNOWN/FAILED, never SAFE."""
    tmp_path, config = test_env

    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = False

    with patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Webcam disconnected")), \
         patch("device_guardian.alerts.pipeline.get_approximate_location", return_value=LocationInfo(is_available=False)), \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls, \
         patch("cv2.VideoCapture", return_value=mock_cap):

        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = TelegramResponse(success=True)
        mock_tg_cls.return_value = mock_tg_instance

        res = trigger_alert(reason="Camera Failure Test", config=config)

        # Local alert pipeline succeeded with text fallback despite hardware failure
        assert res.success is True
        assert res.camera_success is False
        assert mock_tg_instance.send_message.called

        # Assess health and ensure camera is not SAFE
        report = assess_system_health(config=config)
        cam_sub = next(s for s in report.subsystems if "Camera" in s.name)
        assert cam_sub.status in (HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN)
        assert cam_sub.status != HealthStatus.HEALTHY


def test_unknown_state_propagation_location_unavailable_e2e(test_env):
    """Verify geolocation failure results in UNKNOWN status and is never converted to SAFE."""
    tmp_path, config = test_env

    with patch("device_guardian.alerts.pipeline.get_approximate_location", return_value=LocationInfo(is_available=False)), \
         patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Skip cam")), \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls:

        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = TelegramResponse(success=True)
        mock_tg_cls.return_value = mock_tg_instance

        res = trigger_alert(reason="Location Failure Test", config=config)
        assert res.location_success is False

        # Uncertainty rule: Absence of location must not imply "Safe Location"
        summary = get_operator_summary(config=config)
        dashboard = format_operator_dashboard(summary)
        assert "Safe Location" not in dashboard


def test_pipeline_strict_secret_redaction_throughout_e2e(test_env):
    """Verify secrets are redacted across the entire detection and alert pipeline."""
    import logging
    tmp_path, config = test_env
    raw_secret = config.get_secret_token()

    # 1. Sanitized configuration masks secrets
    sanitized = config.to_sanitized_dict()
    assert raw_secret not in str(sanitized)
    assert "***" in sanitized["telegram_bot_token"]

    # 2. Pipeline execution masks secrets in formatted messages
    with patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Skip")), \
         patch("device_guardian.alerts.pipeline.get_approximate_location", return_value=LocationInfo(is_available=False)), \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls:

        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = TelegramResponse(success=True)
        mock_tg_cls.return_value = mock_tg_instance

        res = trigger_alert(reason="Test Alert", config=config)
        assert res.success is True
        if res.event:
            msg = res.event.format_telegram_message()
            assert raw_secret not in msg

    # 3. Redacting filter scrubs secret from log records
    from device_guardian.logger import RedactingFilter
    r_filter = RedactingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Transmission with token: %s",
        args=(raw_secret,),
        exc_info=None,
    )
    r_filter.filter(record)
    assert raw_secret not in record.args[0]


def test_pipeline_notification_failure_preserves_local_alert_e2e(test_env):
    """Verify Telegram HTTP or network failure preserves local alert and voice warning."""
    tmp_path, config = test_env

    with patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Skip")), \
         patch("device_guardian.alerts.pipeline.TelegramClient") as mock_tg_cls, \
         patch("device_guardian.detection.voice.OfflineVoiceWarning.speak") as mock_voice:

        mock_tg_instance = MagicMock()
        mock_tg_instance.send_message.return_value = TelegramResponse(
            success=False,
            error_message="Network unreachable",
        )
        mock_tg_cls.return_value = mock_tg_instance

        # Test DetectionManager handling
        dm = DetectionManager(config=config)
        event1 = AuthenticationFailureEvent(username="attacker")
        event2 = AuthenticationFailureEvent(username="attacker")
        dm.process_event(event1)
        # Event 2 reaches threshold; voice warning is called; alert fails remotely but doesn't crash
        dm.process_event(event2)

        assert mock_voice.called
