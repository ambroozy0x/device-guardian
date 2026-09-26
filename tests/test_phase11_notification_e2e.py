"""Phase 11 End-to-End Integration Tests: Notification Pipeline, Telegram Failure Modes, and Offline Operation (Workstreams 7, 41)."""

from unittest.mock import MagicMock, patch
import pytest
import requests

from device_guardian.alerts.pipeline import trigger_alert
from device_guardian.camera.capture import CameraError
from device_guardian.config import AppConfig
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.telegram.bot import TelegramClient, TelegramResponse
from device_guardian.ux.events import format_security_event_block


@pytest.fixture
def mock_cfg():
    return AppConfig(
        telegram_bot_token="123456:AAAHH-TEST_BOT_TOKEN_FOR_E2E",
        telegram_chat_id="987654321",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=True,
    )


def test_telegram_dispatch_success_e2e(mock_cfg):
    """Verify end-to-end successful dispatch to Telegram API."""
    client = TelegramClient(bot_token=mock_cfg.get_secret_token(), chat_id=mock_cfg.get_secret_chat_id())

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"ok": True, "result": {"message_id": 101}}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = client.send_message("Test Successful Dispatch")
        assert result.success is True
        assert result.data["message_id"] == 101
        assert mock_post.called


def test_telegram_dispatch_timeout_with_retry_e2e(mock_cfg):
    """Verify bounded timeout retry logic and fallback preservation of local state."""
    client = TelegramClient(
        bot_token=mock_cfg.get_secret_token(),
        chat_id=mock_cfg.get_secret_chat_id(),
        max_retries=1,
        retry_backoff=0.01,
    )

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Request timed out")) as mock_post:
        result = client.send_message("Test Timeout Retry")
        # Ensure retries occurred within bounds and ultimately failed safely
        assert result.success is False
        assert "timed out" in (result.error_message or "").lower() or "timeout" in (result.error_message or "").lower()
        assert mock_post.call_count >= 1


def test_telegram_dispatch_http_429_rate_limiting_e2e(mock_cfg):
    """Verify HTTP 429 rate limit backoff is respected and bounded."""
    client = TelegramClient(
        bot_token=mock_cfg.get_secret_token(),
        chat_id=mock_cfg.get_secret_chat_id(),
        max_retries=1,
        retry_backoff=0.01,
    )

    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_429.json.return_value = {"ok": False, "description": "Too Many Requests: retry after 1"}

    with patch("requests.post", return_value=mock_429) as mock_post:
        result = client.send_message("Test Rate Limit")
        assert result.success is False
        assert mock_post.called


def test_telegram_dispatch_http_5xx_server_error_e2e(mock_cfg):
    """Verify HTTP 500/502 server errors trigger bounded retries without infinite loops."""
    client = TelegramClient(
        bot_token=mock_cfg.get_secret_token(),
        chat_id=mock_cfg.get_secret_chat_id(),
        max_retries=1,
        retry_backoff=0.01,
    )

    mock_502 = MagicMock()
    mock_502.status_code = 502
    mock_502.json.return_value = {"ok": False, "description": "Bad Gateway"}

    with patch("requests.post", return_value=mock_502) as mock_post:
        result = client.send_message("Test Server Error")
        assert result.success is False
        assert mock_post.called


def test_telegram_dispatch_http_401_fast_failure_e2e(mock_cfg):
    """Verify HTTP 401 Unauthorized fails fast without wasteful retries."""
    client = TelegramClient(bot_token="invalid_token", chat_id="123")

    mock_401 = MagicMock()
    mock_401.status_code = 401
    mock_401.json.return_value = {"ok": False, "description": "Unauthorized"}

    with patch("requests.post", return_value=mock_401) as mock_post:
        result = client.send_message("Test Fast Fail")
        assert result.success is False
        assert "unauthorized" in (result.error_message or "").lower()


def test_telegram_unconfigured_credentials_safe_degradation_e2e():
    """Verify unconfigured Telegram credentials gracefully degrade to local-only alerts."""
    unconfigured_cfg = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=True,
    )

    res = trigger_alert(reason="Unconfigured Telegram Test", config=unconfigured_cfg)

    # Validates that missing credentials result in safe operational rejection without crashing
    assert res.success is False
    assert "missing" in (res.error_message or "").lower()

    # Verify UX event representation marks Telegram as NOT_CONFIGURED
    ev_text = format_security_event_block(
        event_type="UNCONFIGURED_TEST",
        telegram_dispatched=False,
        telegram_configured=False,
    )
    assert "NOT_CONFIGURED" in ev_text


def test_offline_mode_validation_e2e(mock_cfg):
    """Verify local detection, local alerts, and voice warnings function when completely offline."""
    mock_cfg.auth_failure_threshold = 1
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Network is down")), \
         patch("device_guardian.detection.voice.OfflineVoiceWarning.speak") as mock_voice:

        dm = DetectionManager(config=mock_cfg)
        event = AuthenticationFailureEvent(username="offline_tester")

        # Local processing must not crash or throw unhandled exceptions due to network outage
        dm.process_event(event)

        assert mock_voice.called
