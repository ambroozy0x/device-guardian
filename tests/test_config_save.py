"""Unit tests for configuration persistence, safe save, and rollback."""

from pathlib import Path
from unittest.mock import patch
import pytest

from device_guardian.config import AppConfig, ConfigurationError, load_config
from device_guardian.setup.storage import format_env_file, safe_save_config


def test_format_env_file_structure():
    """Verify format_env_file generates expected key-value pairs."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN_XYZ",
        telegram_chat_id="987654321",
        location_api_url="https://ipapi.co/json/",
        camera_index=1,
        request_timeout_seconds=12.5,
        log_level="DEBUG",
    )
    formatted = format_env_file(cfg)
    assert "TELEGRAM_BOT_TOKEN=123456789:ABC_TOKEN_XYZ" in formatted
    assert "TELEGRAM_CHAT_ID=987654321" in formatted
    assert "CAMERA_INDEX=1" in formatted
    assert "REQUEST_TIMEOUT_SECONDS=12.5" in formatted
    assert "LOG_LEVEL=DEBUG" in formatted


def test_safe_save_config_creates_valid_file(tmp_path: Path):
    """Verify safe_save_config writes a file that loads back cleanly."""
    target_env = tmp_path / ".env"
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN_XYZ",
        telegram_chat_id="987654321",
        camera_index=0,
    )

    saved_path = safe_save_config(cfg, target_path=target_env)
    assert saved_path.is_file()

    reloaded = load_config(env_path=saved_path)
    assert reloaded.telegram_bot_token == "123456789:ABC_TOKEN_XYZ"
    assert reloaded.telegram_chat_id == "987654321"
    assert reloaded.camera_index == 0


def test_safe_save_config_rejects_invalid_configuration(tmp_path: Path):
    """Verify saving invalid config raises ConfigurationError and creates no file."""
    target_env = tmp_path / ".env"
    invalid_cfg = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="987654321",
    )

    with pytest.raises(ConfigurationError):
        safe_save_config(invalid_cfg, target_path=target_env)

    assert not target_env.exists()


def test_safe_save_preserves_old_configuration_on_failure(tmp_path: Path):
    """Verify rollback: if write/validation fails, existing .env is preserved."""
    target_env = tmp_path / ".env"
    original_content = (
        "TELEGRAM_BOT_TOKEN=original_token_1234\n"
        "TELEGRAM_CHAT_ID=original_chat_5678\n"
        "CAMERA_INDEX=0\n"
        "REQUEST_TIMEOUT_SECONDS=10\n"
        "LOCATION_API_URL=https://ipapi.co/json/\n"
    )
    target_env.write_text(original_content, encoding="utf-8")

    candidate_cfg = AppConfig(
        telegram_bot_token="new_valid_token_567890",
        telegram_chat_id="new_chat_123456",
    )

    # Force failure during atomic replace step
    with patch("os.replace", side_effect=OSError("Disk write error")):
        with pytest.raises(ConfigurationError):
            safe_save_config(candidate_cfg, target_path=target_env)

    # Verify original file content is intact
    assert target_env.is_file()
    assert target_env.read_text(encoding="utf-8") == original_content
    # Temporary files should be cleaned up
    tmp_file = tmp_path / ".env.tmp"
    assert not tmp_file.exists()
