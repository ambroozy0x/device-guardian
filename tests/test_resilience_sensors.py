"""Unit tests for sensor resilience and graceful degradation under hardware faults (Phase 8)."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.alerts.pipeline import trigger_alert
from device_guardian.camera.capture import CameraError
from device_guardian.config import AppConfig
from device_guardian.environment.detector import EnvironmentalDetector
from device_guardian.environment.models import NetworkState
from device_guardian.location.geolocation import LocationInfo
from device_guardian.telegram.bot import TelegramClient, TelegramResponse


def test_pipeline_camera_hardware_failure_degrades_to_text_alert():
    """Verify alert pipeline delivers text-only alert when camera capture raises CameraError."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN",
        telegram_chat_id="987654321",
    )

    with patch("device_guardian.alerts.pipeline.capture_photo", side_effect=CameraError("Camera device busy")):
        with patch("device_guardian.alerts.pipeline.get_approximate_location", return_value=LocationInfo(is_available=False)):
            with patch.object(TelegramClient, "send_message", return_value=TelegramResponse(success=True)) as mock_send_msg:
                with patch.object(TelegramClient, "send_photo") as mock_send_photo:
                    result = trigger_alert(reason="Test Camera Failure", config=cfg)

                    assert result.success is True
                    assert result.camera_success is False
                    assert result.telegram_success is True
                    # Photo was NOT attempted; text message was dispatched instead
                    mock_send_photo.assert_not_called()
                    mock_send_msg.assert_called_once()
                    assert "Photograph unavailable" in mock_send_msg.call_args[1]["text"]


def test_pipeline_location_service_failure_degrades_gracefully(tmp_path: Path):
    """Verify alert pipeline succeeds when IP geolocation times out or returns unavailable."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN",
        telegram_chat_id="987654321",
    )

    real_photo = tmp_path / "test_photo.jpg"
    real_photo.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF")

    with patch("device_guardian.alerts.pipeline.capture_photo", return_value=real_photo):
        with patch("device_guardian.alerts.pipeline.get_approximate_location", return_value=LocationInfo(is_available=False)):
            with patch.object(TelegramClient, "send_photo", return_value=TelegramResponse(success=True)) as mock_send_photo:
                result = trigger_alert(reason="Test Location Failure", config=cfg, cleanup_image_on_success=False)

                assert result.success is True
                assert result.location_success is False
                assert result.telegram_success is True
                mock_send_photo.assert_called_once()
                caption = mock_send_photo.call_args[1]["caption"]
                assert "Location: Unavailable" in caption or "Unavailable" in caption


def test_environmental_detector_network_failure_fallback():
    """Verify EnvironmentalDetector handles network hook exceptions gracefully."""
    from device_guardian.environment.network import NetworkDetector

    def failing_hook():
        raise OSError("Network socket query failed")

    net_det = NetworkDetector(connectivity_hook=failing_hook, resolver_hook=failing_hook)
    detector = EnvironmentalDetector(network_detector=net_det, network_context_enabled=True)

    ctx = detector.collect_context()
    assert ctx.network_context is not None
    assert ctx.network_context.connected is False
    assert ctx.network_context.state == NetworkState.UNKNOWN
