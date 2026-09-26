"""Tests for Phase 5 system diagnostics and status CLI handlers."""

from io import StringIO
import sys
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig
from device_guardian.main import main, run_system_diagnostics, show_runtime_status
from device_guardian.runtime.paths import ApplicationPaths


@pytest.fixture
def mock_config():
    return AppConfig(
        telegram_bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        telegram_chat_id="123456789",
    )


def test_show_runtime_status(tmp_path):
    """Verify show_runtime_status outputs formatted status without exceptions."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured):
        code = show_runtime_status()
        assert code == 0

    output = captured.getvalue()
    assert "Device Guardian Runtime Status" in output
    assert "Runtime State:" in output


def test_run_system_diagnostics(mock_config, tmp_path):
    """Verify run_system_diagnostics executes each subsystem check cleanly."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    captured = StringIO()
    with patch("sys.stdout", captured):
        # Mock telegram verify to avoid live network query during unit test
        with patch("device_guardian.telegram.bot.TelegramClient.verify_credentials") as mock_tg:
            mock_tg.return_value = MagicMock(success=True, data={"username": "TestBot"})
            code = run_system_diagnostics(config=mock_config)

    output = captured.getvalue()
    assert "DEVICE GUARDIAN - COMPREHENSIVE SYSTEM DIAGNOSTICS" in output
    assert "Environment & Packaging:" in output
    assert "Configuration & Privacy Validation:" in output
    assert "Single Instance & Process Coordination:" in output
    assert "DIAGNOSTICS SUMMARY:" in output


def test_cli_diagnostics_argument(mock_config, tmp_path):
    """Verify CLI --diagnostics flag works end to end."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    with patch("sys.stdout", StringIO()), patch("device_guardian.main.load_config", return_value=mock_config):
        with patch("device_guardian.telegram.bot.TelegramClient.verify_credentials") as mock_tg:
            mock_tg.return_value = MagicMock(success=True, data={"username": "TestBot"})
            exit_code = main(["--diagnostics"])
            assert exit_code in {0, 1}
