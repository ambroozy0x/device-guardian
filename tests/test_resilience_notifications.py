"""Unit tests for Phase 8 notification delivery resilience and alert storm prevention."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import requests

from device_guardian.alerts.pipeline import AlertResult
from device_guardian.config import AppConfig
from device_guardian.detection.cooldown import AlertCooldownManager
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent, MonitorState
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.telegram.bot import TelegramClient


def test_telegram_retry_on_transient_http_500():
    """Verify TelegramClient retries on HTTP 500 and succeeds on subsequent attempt."""
    client = TelegramClient(
        bot_token="123456789:ABC_TOKEN",
        chat_id="987654321",
        timeout=1.0,
        max_retries=2,
        retry_backoff=0.01,
    )

    resp_fail = MagicMock(status_code=500, json=lambda: {"ok": False, "description": "Internal server error"})
    resp_success = MagicMock(status_code=200, json=lambda: {"ok": True, "result": {"message_id": 101}})

    with patch("requests.post", side_effect=[resp_fail, resp_success]) as mock_post:
        result = client.send_message("Test retry message")
        assert result.success is True
        assert result.data == {"message_id": 101}
        assert mock_post.call_count == 2


def test_telegram_no_retry_on_permanent_http_401():
    """Verify TelegramClient fails immediately on HTTP 401 without retrying."""
    client = TelegramClient(
        bot_token="invalid_token",
        chat_id="987654321",
        timeout=1.0,
        max_retries=2,
        retry_backoff=0.01,
    )

    resp_401 = MagicMock(status_code=401, json=lambda: {"ok": False, "description": "Unauthorized"})

    with patch("requests.post", return_value=resp_401) as mock_post:
        result = client.send_message("Test message")
        assert result.success is False
        assert result.status_code == 401
        assert "Invalid Telegram Bot Token" in result.error_message
        # Must only call once (no retry on 401)
        mock_post.assert_called_once()


def test_telegram_no_retry_on_permanent_http_400():
    """Verify TelegramClient fails immediately on HTTP 400 without retrying."""
    client = TelegramClient(
        bot_token="123456:valid_token",
        chat_id="bad_chat_id",
        timeout=1.0,
        max_retries=2,
        retry_backoff=0.01,
    )

    resp_400 = MagicMock(status_code=400, json=lambda: {"ok": False, "description": "Chat not found"})

    with patch("requests.post", return_value=resp_400) as mock_post:
        result = client.send_message("Test message")
        assert result.success is False
        assert result.status_code == 400
        mock_post.assert_called_once()


def test_telegram_exhausted_timeout_retries():
    """Verify TelegramClient retries up to max_retries before returning structured failure."""
    client = TelegramClient(
        bot_token="123456:token",
        chat_id="987654321",
        timeout=1.0,
        max_retries=2,
        retry_backoff=0.01,
    )

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timeout")) as mock_post:
        result = client.send_message("Test timeout")
        assert result.success is False
        assert "timed out" in result.error_message.lower()
        # 1 initial attempt + 2 retries = 3 calls
        assert mock_post.call_count == 3


def test_detection_delivery_failure_prevents_alert_storm():
    """Verify when Telegram delivery fails, cooldown and threshold reset to prevent alert storms."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN",
        telegram_chat_id="987654321",
        auth_failure_threshold=3,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        voice_warning_enabled=False,
    )

    mock_dispatcher = MagicMock(return_value=AlertResult(reason="Repeated failures", success=False, error_message="Network dropped"))
    cooldown = AlertCooldownManager(cooldown_seconds=300.0)
    thresh = SlidingWindowThresholdEngine(threshold=3, window_seconds=60.0)

    mgr = DetectionManager(
        config=cfg,
        threshold_engine=thresh,
        cooldown_manager=cooldown,
        alert_dispatcher=mock_dispatcher,
    )

    # Trigger 3 failures to reach threshold
    mgr.process_event(AuthenticationFailureEvent(username="u1"))
    mgr.process_event(AuthenticationFailureEvent(username="u1"))
    res = mgr.process_event(AuthenticationFailureEvent(username="u1"))

    # Alert delivery failed
    assert res is False
    assert mock_dispatcher.call_count == 1

    # But cooldown MUST be active and threshold MUST be reset
    assert cooldown.is_in_cooldown() is True
    assert len(thresh.current_events()) == 0

    # Next event 2 seconds later should NOT re-trigger alert pipeline
    res_next = mgr.process_event(AuthenticationFailureEvent(username="u1"))
    assert res_next is False
    # Dispatcher was NOT called again
    assert mock_dispatcher.call_count == 1
    assert mgr.alerts_suppressed_by_cooldown == 0  # not met threshold (only 1 event)


def test_detection_dispatcher_exception_prevents_alert_storm():
    """Verify when alert dispatcher raises an unexpected exception, cooldown is recorded."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN",
        telegram_chat_id="987654321",
        auth_failure_threshold=2,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        voice_warning_enabled=False,
    )

    mock_dispatcher = MagicMock(side_effect=RuntimeError("Unexpected pipeline crash"))
    cooldown = AlertCooldownManager(cooldown_seconds=300.0)
    thresh = SlidingWindowThresholdEngine(threshold=2, window_seconds=60.0)

    mgr = DetectionManager(
        config=cfg,
        threshold_engine=thresh,
        cooldown_manager=cooldown,
        alert_dispatcher=mock_dispatcher,
    )

    mgr.process_event(AuthenticationFailureEvent(username="u1"))
    res = mgr.process_event(AuthenticationFailureEvent(username="u1"))

    assert res is False
    assert mgr.state == MonitorState.ERROR
    # Cooldown MUST still be activated to prevent infinite exception loop
    assert cooldown.is_in_cooldown() is True
    assert len(thresh.current_events()) == 0


def test_telegram_secret_token_redaction_in_exceptions():
    """Verify raw token is scrubbed and never exposed in error responses."""
    secret_token = "SECRET_BOT_TOKEN_1234567890"
    client = TelegramClient(
        bot_token=secret_token,
        chat_id="987654321",
        timeout=1.0,
        max_retries=0,
    )

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError(f"Failed to connect to api.telegram.org/bot{secret_token}")):
        result = client.send_message("Test")
        assert result.success is False
        assert secret_token not in result.error_message
        assert "[REDACTED" in result.error_message
