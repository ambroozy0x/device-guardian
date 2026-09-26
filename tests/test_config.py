"""Unit tests for configuration validation and loading."""

import os
from pathlib import Path
import pytest

from device_guardian.config import (
    AppConfig,
    ConfigurationError,
    load_config,
    mask_token,
)


def test_mask_token_various_inputs():
    """Verify sensitive tokens are masked properly."""
    assert mask_token(None) == "***EMPTY***"
    assert mask_token("") == "***EMPTY***"
    assert mask_token("   ") == "***EMPTY***"
    assert mask_token("1234567") == "***REDACTED***"
    assert mask_token("123456789:ABCdefGHI_jkl123") == "1234***l123"


def test_app_config_repr_does_not_leak_token():
    """Verify that printing AppConfig does not expose the raw bot token."""
    secret = "987654321:SECRET_TOKEN_XYZ_12345"
    config = AppConfig(
        telegram_bot_token=secret,
        telegram_chat_id="12345678",
    )
    repr_str = repr(config)
    assert secret not in repr_str
    assert "9876***2345" in repr_str


def test_valid_config_validation():
    """Verify valid configuration passes validation."""
    config = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_123456",
        telegram_chat_id="123456789",
        location_api_url="https://ipapi.co/json/",
        camera_index=0,
        request_timeout_seconds=10.0,
    )
    # Should not raise
    config.validate()


def test_missing_token_raises_configuration_error():
    """Verify missing bot token raises ConfigurationError."""
    config = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="123456789",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        config.validate()
    assert "TELEGRAM_BOT_TOKEN is missing" in str(exc_info.value)


def test_placeholder_token_raises_configuration_error():
    """Verify placeholder token raises ConfigurationError."""
    config = AppConfig(
        telegram_bot_token="your_telegram_bot_token_here",
        telegram_chat_id="123456789",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        config.validate()
    assert "placeholder value" in str(exc_info.value)


def test_missing_chat_id_raises_configuration_error():
    """Verify missing chat ID raises ConfigurationError."""
    config = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_123456",
        telegram_chat_id="",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        config.validate()
    assert "TELEGRAM_CHAT_ID is missing" in str(exc_info.value)


def test_invalid_camera_index_raises_configuration_error():
    """Verify negative camera index raises ConfigurationError."""
    config = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_123456",
        telegram_chat_id="123456789",
        camera_index=-1,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        config.validate()
    assert "CAMERA_INDEX must be a non-negative integer" in str(exc_info.value)


def test_invalid_timeout_raises_configuration_error():
    """Verify non-positive timeout raises ConfigurationError."""
    config = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_123456",
        telegram_chat_id="123456789",
        request_timeout_seconds=0,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        config.validate()
    assert "REQUEST_TIMEOUT_SECONDS must be positive" in str(exc_info.value)


def test_load_config_from_explicit_env_file(tmp_path: Path):
    """Verify loading settings from an explicit .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=test_token_123456789\n"
        "TELEGRAM_CHAT_ID=987654321\n"
        "CAMERA_INDEX=1\n"
        "REQUEST_TIMEOUT_SECONDS=15.5\n"
        "LOCATION_API_URL=https://example.com/geo\n"
    )

    config = load_config(env_path=env_file)
    assert config.telegram_bot_token == "test_token_123456789"
    assert config.telegram_chat_id == "987654321"
    assert config.camera_index == 1
    assert config.request_timeout_seconds == 15.5
    assert config.location_api_url == "https://example.com/geo"
