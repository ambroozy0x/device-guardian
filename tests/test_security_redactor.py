"""Tests for SecretRedactor pattern scrubbing, dict masking, and log integration (Phase 6)."""

import logging
from device_guardian.logger import get_logger
from device_guardian.security.redactor import SecretRedactor, get_redactor, redact_string


def test_redactor_telegram_token_regex():
    """Verify Telegram bot token pattern is recognized and redacted."""
    redactor = SecretRedactor()
    raw_token = "123456789:ABCdefGHI_jkl1234567890abcdefABC"
    text = f"Connecting to Telegram with token {raw_token} for alert dispatch."

    redacted = redactor.redact(text)
    assert raw_token not in redacted
    assert "[REDACTED_TOKEN]" in redacted


def test_redactor_telegram_api_url():
    """Verify Telegram API endpoints containing tokens are sanitized."""
    redactor = SecretRedactor()
    token = "123456789:ABCdefGHI_jkl1234567890abcdefABC"
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    redacted = redactor.redact(f"Request sent to {url}")
    assert token not in redacted
    assert "https://api.telegram.org/bot[REDACTED_TOKEN]/sendMessage" in redacted


def test_redactor_bearer_token():
    """Verify Bearer authentication headers are redacted."""
    redactor = SecretRedactor()
    header = "Authorization: Bearer secret_bearer_token_value_xyz"

    redacted = redactor.redact(header)
    assert "secret_bearer_token_value_xyz" not in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted


def test_redactor_custom_registered_secret():
    """Verify dynamically registered secrets are redacted from output."""
    redactor = SecretRedactor()
    custom_chat_id = "987654321987654"
    redactor.register_secret(custom_chat_id)

    msg = f"Delivering alert packet to user chat_id={custom_chat_id}."
    redacted = redactor.redact(msg)

    assert custom_chat_id not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_redactor_dict_redaction():
    """Verify recursive dictionary scrubbing handles sensitive keys and values."""
    redactor = SecretRedactor()
    data = {
        "status": "active",
        "telegram_bot_token": "secret_token_1234",
        "api_key": "secret_api_key_5678",
        "nested": {
            "password": "super_secret_pwd",
            "normal_field": "public_data",
        },
        "item_list": [
            "normal",
            {"secret": "nested_secret_in_list"},
        ],
    }

    redacted_data = redactor.redact_dict(data)

    assert redacted_data["status"] == "active"
    assert redacted_data["telegram_bot_token"] == "[REDACTED_SECRET]"
    assert redacted_data["api_key"] == "[REDACTED_SECRET]"
    assert redacted_data["nested"]["password"] == "[REDACTED_SECRET]"
    assert redacted_data["nested"]["normal_field"] == "public_data"
    assert redacted_data["item_list"][1]["secret"] == "[REDACTED_SECRET]"


def test_redactor_exception_scrubbing():
    """Verify exceptions containing sensitive tokens have their messages scrubbed."""
    redactor = SecretRedactor()
    token = "123456789:ABCdefGHI_jkl1234567890abcdefABC"
    exc = ValueError(f"HTTP 401 Unauthorized for bot {token}")

    scrubbed_msg = redactor.redact_exception(exc)
    assert token not in scrubbed_msg
    assert "[REDACTED_TOKEN]" in scrubbed_msg


def test_redact_string_helper():
    """Verify global redact_string helper function."""
    token = "987654321:ABCdefGHI_jkl1234567890abcdefABC"
    result = redact_string(f"Error sending to {token}")
    assert token not in result
    assert "[REDACTED_TOKEN]" in result
