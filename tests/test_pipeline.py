"""Unit tests for the Core Alert Pipeline."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.alerts.models import AlertEvent
from device_guardian.alerts.pipeline import AlertResult, trigger_alert
from device_guardian.camera.capture import CameraError
from device_guardian.config import AppConfig
from device_guardian.location.geolocation import LocationInfo
from device_guardian.telegram.bot import TelegramResponse


@pytest.fixture
def mock_config():
    """Return a valid AppConfig fixture for tests."""
    return AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_123456",
        telegram_chat_id="987654321",
        location_api_url="https://ipapi.co/json/",
        camera_index=0,
        request_timeout_seconds=5.0,
    )


def test_alert_event_message_formatting_objective():
    """Verify AlertEvent produces strictly objective text conforming to safety guidelines."""
    loc = LocationInfo(
        ip="198.51.100.1",
        city="Oslo",
        region="Oslo",
        country="Norway",
        latitude=59.9139,
        longitude=10.7522,
        is_available=True,
    )
    event = AlertEvent(
        reason="Repeated failed login",
        location=loc,
        image_path=Path("/tmp/capture_test.jpg"),
    )
    msg = event.format_telegram_message()

    assert "🚨 DEVICE GUARDIAN ALERT" in msg
    assert "Reason: Repeated failed login" in msg
    assert "City: Oslo" in msg
    assert "Country: Norway" in msg
    assert "59.913900, 10.752200" in msg
    assert "https://maps.google.com/?q=59.913900,10.752200" in msg

    # Safety checks: ensure inflammatory/judgmental terms are NOT present
    for prohibited in ["hacker", "attacker", "criminal", "intruder", "thief"]:
        assert prohibited not in msg.lower()


@patch("device_guardian.alerts.pipeline.get_approximate_location")
@patch("device_guardian.alerts.pipeline.capture_photo")
@patch("device_guardian.alerts.pipeline.TelegramClient")
def test_trigger_alert_full_success_cleans_up_photo(
    mock_telegram_cls,
    mock_capture_photo,
    mock_get_location,
    mock_config,
    tmp_path: Path,
):
    """Verify full end-to-end alert pipeline deletes temp photo on success."""
    temp_img = tmp_path / "capture_2026-09-25_215100.jpg"
    temp_img.write_bytes(b"dummy image data")
    assert temp_img.exists()

    mock_capture_photo.return_value = temp_img

    mock_get_location.return_value = LocationInfo(
        ip="203.0.113.1",
        city="Kochi",
        region="Kerala",
        country="India",
        latitude=9.9312,
        longitude=76.2673,
        is_available=True,
    )

    mock_tg_instance = MagicMock()
    mock_tg_instance.send_photo.return_value = TelegramResponse(success=True, status_code=200)
    mock_telegram_cls.return_value = mock_tg_instance

    result = trigger_alert(
        reason="Manual Test Alert",
        config=mock_config,
        cleanup_image_on_success=True,
    )

    assert result.success is True
    assert result.camera_success is True
    assert result.location_success is True
    assert result.telegram_success is True
    # Verify temporary image was cleaned up
    assert not temp_img.exists()


@patch("device_guardian.alerts.pipeline.get_approximate_location")
@patch("device_guardian.alerts.pipeline.capture_photo")
@patch("device_guardian.alerts.pipeline.TelegramClient")
def test_trigger_alert_camera_failure_fallback_to_text(
    mock_telegram_cls,
    mock_capture_photo,
    mock_get_location,
    mock_config,
):
    """Verify that when camera fails, alert continues with text message fallback."""
    mock_capture_photo.side_effect = CameraError("Camera device is busy")

    mock_get_location.return_value = LocationInfo(
        ip="203.0.113.1",
        city="Seattle",
        region="Washington",
        country="United States",
        latitude=47.6062,
        longitude=-122.3321,
        is_available=True,
    )

    mock_tg_instance = MagicMock()
    mock_tg_instance.send_message.return_value = TelegramResponse(success=True, status_code=200)
    mock_telegram_cls.return_value = mock_tg_instance

    result = trigger_alert(
        reason="Manual Test Alert",
        config=mock_config,
    )

    assert result.success is True
    assert result.camera_success is False
    assert result.location_success is True
    assert result.telegram_success is True
    mock_tg_instance.send_message.assert_called_once()
    assert "Photograph unavailable" in mock_tg_instance.send_message.call_args[1]["text"]


@patch("device_guardian.alerts.pipeline.get_approximate_location")
@patch("device_guardian.alerts.pipeline.capture_photo")
@patch("device_guardian.alerts.pipeline.TelegramClient")
def test_trigger_alert_location_failure_continues_alert(
    mock_telegram_cls,
    mock_capture_photo,
    mock_get_location,
    mock_config,
    tmp_path: Path,
):
    """Verify that when geolocation fails, alert is still delivered."""
    temp_img = tmp_path / "capture_test.jpg"
    temp_img.write_bytes(b"dummy image data")
    mock_capture_photo.return_value = temp_img

    # Geolocation returns unavailable
    mock_get_location.return_value = LocationInfo(is_available=False)

    mock_tg_instance = MagicMock()
    mock_tg_instance.send_photo.return_value = TelegramResponse(success=True, status_code=200)
    mock_telegram_cls.return_value = mock_tg_instance

    result = trigger_alert(
        reason="Manual Test Alert",
        config=mock_config,
        cleanup_image_on_success=True,
    )

    assert result.success is True
    assert result.camera_success is True
    assert result.location_success is False
    assert result.telegram_success is True


@patch("device_guardian.alerts.pipeline.get_approximate_location")
@patch("device_guardian.alerts.pipeline.capture_photo")
@patch("device_guardian.alerts.pipeline.TelegramClient")
def test_trigger_alert_telegram_failure_retains_photo(
    mock_telegram_cls,
    mock_capture_photo,
    mock_get_location,
    mock_config,
    tmp_path: Path,
):
    """Verify that when Telegram dispatch fails, temporary photo is kept for diagnosis."""
    temp_img = tmp_path / "capture_diagnostic.jpg"
    temp_img.write_bytes(b"dummy image data")
    mock_capture_photo.return_value = temp_img

    mock_get_location.return_value = LocationInfo(is_available=True)

    mock_tg_instance = MagicMock()
    mock_tg_instance.send_photo.return_value = TelegramResponse(
        success=False, error_message="Network connection failed"
    )
    mock_tg_instance.send_message.return_value = TelegramResponse(
        success=False, error_message="Network connection failed"
    )
    mock_telegram_cls.return_value = mock_tg_instance

    result = trigger_alert(
        reason="Manual Test Alert",
        config=mock_config,
    )

    assert result.success is False
    assert result.telegram_success is False
    assert "Network connection failed" in result.error_message
    # Photo should NOT be deleted if delivery failed
    assert temp_img.exists()
