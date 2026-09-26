"""Tests for Phase 6 secure configuration and secrets CLI commands."""

from io import StringIO
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig
from device_guardian.main import main
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.telegram.bot import TelegramResponse


@pytest.fixture
def mock_valid_config():
    return AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TEST_TOKEN_123456",
        telegram_chat_id="987654321",
    )


@pytest.fixture
def mock_unconfigured_config():
    return AppConfig(
        telegram_bot_token="",
        telegram_chat_id="",
    )


def test_cli_config_check_success(mock_valid_config, tmp_path):
    """Verify --config-check exits with code 0 on ready configuration."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_valid_config):
        code = main(["--config-check"])
        assert code == 0

    output = captured.getvalue()
    assert "CONFIGURATION READINESS AUDIT" in output
    assert "Overall Status: READY" in output


def test_cli_config_check_failure(mock_unconfigured_config, tmp_path):
    """Verify --config-check exits with code 1 and actionable advice when unconfigured."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_unconfigured_config):
        code = main(["--config-check"])
        assert code == 1

    output = captured.getvalue()
    assert "Overall Status: NOT READY" in output
    assert "--setup" in output


def test_cli_config_show(mock_valid_config, tmp_path):
    """Verify --config-show displays masked configuration values."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_valid_config):
        code = main(["--config-show"])
        assert code == 0

    output = captured.getvalue()
    assert "SANITIZED CONFIGURATION OVERVIEW" in output
    # Ensure sensitive credentials are masked
    assert "123456789:ABC_VALID_TEST_TOKEN_123456" not in output
    assert "1234***3456" in output
    assert "*****4321" in output


def test_cli_config_path(tmp_path):
    """Verify --config-path outputs resolved directory and storage paths."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured):
        code = main(["--config-path"])
        assert code == 0

    output = captured.getvalue()
    assert "RESOLVED SYSTEM & STORAGE PATHS" in output
    assert "User Data Directory:" in output
    assert "Secrets Backend:" in output


def test_cli_credentials_status_configured(mock_valid_config, tmp_path):
    """Verify --credentials-status returns code 0 when credentials valid."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_valid_config):
        code = main(["--credentials-status"])
        assert code == 0

    output = captured.getvalue()
    assert "CREDENTIALS & SECRETS STATUS" in output
    assert "CONFIGURED" in output
    assert "123456789:ABC_VALID_TEST_TOKEN_123456" not in output


def test_cli_credentials_status_unconfigured(mock_unconfigured_config, tmp_path):
    """Verify --credentials-status returns code 1 when credentials missing."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_unconfigured_config):
        code = main(["--credentials-status"])
        assert code == 1

    output = captured.getvalue()
    assert "NOT CONFIGURED" in output


def test_cli_test_notification_success(mock_valid_config, tmp_path):
    """Verify --test-notification sends test notification successfully."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    mock_resp = TelegramResponse(success=True, status_code=200)

    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_valid_config):
        with patch("device_guardian.telegram.bot.TelegramClient.send_test_notification", return_value=mock_resp):
            code = main(["--test-notification"])
            assert code == 0

    output = captured.getvalue()
    assert "Test notification delivered successfully" in output


def test_cli_test_notification_failure(mock_valid_config, tmp_path):
    """Verify --test-notification handles failure gracefully."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    mock_resp = TelegramResponse(success=False, status_code=401, error_message="Unauthorized")

    with patch("sys.stdout", captured), patch("device_guardian.main.load_config", return_value=mock_valid_config):
        with patch("device_guardian.telegram.bot.TelegramClient.send_test_notification", return_value=mock_resp):
            code = main(["--test-notification"])
            assert code == 1

    output = captured.getvalue()
    assert "delivery failed" in output
