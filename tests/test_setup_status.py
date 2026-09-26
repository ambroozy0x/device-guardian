"""Unit tests for setup status determination."""

from pathlib import Path
import pytest

from device_guardian.config import AppConfig
from device_guardian.setup.status import SetupStatus, determine_setup_status


def test_status_not_configured_when_no_config_and_no_file(tmp_path: Path):
    """Verify NOT_CONFIGURED when configuration does not exist."""
    missing_file = tmp_path / "nonexistent.env"
    status = determine_setup_status(env_path=missing_file)
    assert status == SetupStatus.NOT_CONFIGURED


def test_status_not_configured_when_placeholders_present():
    """Verify NOT_CONFIGURED when config has default placeholder strings."""
    cfg = AppConfig(
        telegram_bot_token="your_telegram_bot_token_here",
        telegram_chat_id="your_telegram_chat_id_here",
    )
    status = determine_setup_status(config=cfg)
    assert status == SetupStatus.NOT_CONFIGURED


def test_status_partially_configured_when_missing_chat_id():
    """Verify PARTIALLY_CONFIGURED when bot token is provided but chat ID is missing."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN_XYZ",
        telegram_chat_id="",
    )
    status = determine_setup_status(config=cfg)
    assert status == SetupStatus.PARTIALLY_CONFIGURED


def test_status_partially_configured_when_missing_token():
    """Verify PARTIALLY_CONFIGURED when chat ID is provided but bot token is missing."""
    cfg = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="987654321",
    )
    status = determine_setup_status(config=cfg)
    assert status == SetupStatus.PARTIALLY_CONFIGURED


def test_status_partially_configured_when_invalid_timeout():
    """Verify PARTIALLY_CONFIGURED when settings fail validation (e.g. invalid timeout)."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN_XYZ",
        telegram_chat_id="987654321",
        request_timeout_seconds=-1.0,
    )
    status = determine_setup_status(config=cfg)
    assert status == SetupStatus.PARTIALLY_CONFIGURED


def test_status_configured_when_all_valid():
    """Verify CONFIGURED when all required settings are valid."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_TOKEN_XYZ",
        telegram_chat_id="987654321",
        camera_index=0,
        location_api_url="https://ipapi.co/json/",
        request_timeout_seconds=10.0,
    )
    status = determine_setup_status(config=cfg)
    assert status == SetupStatus.CONFIGURED
