"""Unit tests for Telegram Bot API client."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import requests

from device_guardian.telegram.bot import TelegramClient, TelegramResponse


def test_telegram_client_init_validation():
    """Verify initialization checks for empty token or chat id."""
    with pytest.raises(ValueError):
        TelegramClient("", "123456789")

    with pytest.raises(ValueError):
        TelegramClient("bot_token_123", "")


def test_telegram_client_token_sanitization():
    """Verify that error messages sanitize the raw token."""
    token = "123456789:ABC_SECRET_KEY_987654"
    client = TelegramClient(bot_token=token, chat_id="999999")

    error_with_token = f"Error connecting to https://api.telegram.org/bot{token}/sendMessage"
    sanitized = client._sanitize(error_with_token)

    assert token not in sanitized
    assert "[REDACTED_TOKEN]" in sanitized


@patch("requests.post")
def test_send_message_success(mock_post):
    """Verify sending a message returns successful TelegramResponse."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"ok": True, "result": {"message_id": 42}}
    mock_post.return_value = mock_resp

    client = TelegramClient("test_token_123", "999999", timeout=5.0)
    result = client.send_message("Test Alert Message")

    assert result.success is True
    assert result.status_code == 200
    assert result.data == {"message_id": 42}
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["json"]["chat_id"] == "999999"
    assert mock_post.call_args[1]["json"]["text"] == "Test Alert Message"


@patch("requests.post")
def test_send_photo_success(mock_post, tmp_path: Path):
    """Verify sending a photo reads file and returns success."""
    photo_file = tmp_path / "test.jpg"
    photo_file.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"ok": True, "result": {"message_id": 43}}
    mock_post.return_value = mock_resp

    client = TelegramClient("test_token_123", "999999", timeout=5.0)
    result = client.send_photo(photo_path=photo_file, caption="Photo caption")

    assert result.success is True
    assert result.status_code == 200
    mock_post.assert_called_once()


def test_send_photo_missing_file_fails_gracefully(tmp_path: Path):
    """Verify nonexistent file returns failure without crash."""
    nonexistent = tmp_path / "missing.jpg"
    client = TelegramClient("test_token_123", "999999")
    result = client.send_photo(nonexistent)

    assert result.success is False
    assert "not found" in result.error_message


@patch("requests.post")
def test_send_message_unauthorized_401(mock_post):
    """Verify HTTP 401 returns clear invalid token message."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"ok": False, "description": "Unauthorized"}
    mock_post.return_value = mock_resp

    client = TelegramClient("invalid_token", "999999")
    result = client.send_message("Alert")

    assert result.success is False
    assert result.status_code == 401
    assert "Invalid Telegram Bot Token" in result.error_message


@patch("requests.post")
def test_send_message_bad_request_400(mock_post):
    """Verify HTTP 400 returns clear bad request message."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"ok": False, "description": "chat not found"}
    mock_post.return_value = mock_resp

    client = TelegramClient("valid_token", "invalid_chat")
    result = client.send_message("Alert")

    assert result.success is False
    assert result.status_code == 400
    assert "Bad Request (400)" in result.error_message


@patch("requests.post")
def test_send_message_timeout(mock_post):
    """Verify network timeout returns structured failure without crashing."""
    mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

    client = TelegramClient("token", "chat", timeout=2.0)
    result = client.send_message("Alert")

    assert result.success is False
    assert "timed out" in result.error_message


@patch("requests.get")
def test_verify_credentials_success(mock_get):
    """Verify getMe success response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ok": True,
        "result": {"id": 12345, "is_bot": True, "username": "GuardianBot"},
    }
    mock_get.return_value = mock_resp

    client = TelegramClient("test_token", "123")
    result = client.verify_credentials()

    assert result.success is True
    assert result.data["username"] == "GuardianBot"
