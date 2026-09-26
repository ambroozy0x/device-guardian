"""Unit tests for the First-Run Setup Wizard workflow and security."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.alerts.pipeline import AlertResult
from device_guardian.config import AppConfig, load_config
from device_guardian.location.geolocation import LocationInfo
from device_guardian.setup.chat_detector import DetectedChat
from device_guardian.setup.status import SetupStatus
from device_guardian.setup.wizard import SetupWizard
from device_guardian.telegram.bot import TelegramResponse


class MockIO:
    """Helper to simulate scripted user inputs and record prints."""

    def __init__(self, inputs: list[str]) -> None:
        self.inputs = list(inputs)
        self.outputs: list[str] = []

    def input(self, prompt: str = "") -> str:
        if not self.inputs:
            raise EOFError("No more scripted inputs available.")
        val = self.inputs.pop(0)
        self.outputs.append(f"{prompt}{val}")
        return val

    def print(self, *args, **kwargs) -> None:
        msg = " ".join(str(a) for a in args)
        self.outputs.append(msg)

    def output_text(self) -> str:
        return "\n".join(self.outputs)


def test_wizard_cancels_on_privacy_notice_rejection(tmp_path: Path):
    """Verify setup terminates cleanly when user declines privacy terms."""
    io = MockIO(inputs=[
        "",     # Welcome ENTER
        "n",    # Decline privacy notice
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=tmp_path / ".env",
    )
    result = wizard.run()

    assert result is False
    assert "Setup cancelled" in io.output_text()
    assert not (tmp_path / ".env").exists()


def test_wizard_reconfiguration_prompt_declined(tmp_path: Path):
    """Verify that declining reconfiguration preserves existing setup."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=123456789:ABC_TOKEN_XYZ\n"
        "TELEGRAM_CHAT_ID=987654321\n"
        "CAMERA_INDEX=0\n"
        "REQUEST_TIMEOUT_SECONDS=10\n"
        "LOCATION_API_URL=https://ipapi.co/json/\n",
        encoding="utf-8",
    )

    io = MockIO(inputs=[
        "n",  # Decline reconfigure
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=env_file,
    )
    result = wizard.run()

    assert result is False
    assert "Existing configuration preserved" in io.output_text()


@patch("device_guardian.setup.wizard.trigger_alert")
@patch("device_guardian.setup.wizard.get_approximate_location")
@patch("device_guardian.setup.wizard.verify_camera_lifecycle")
@patch("device_guardian.setup.wizard.detect_available_cameras")
@patch("device_guardian.setup.wizard.poll_for_chat_id")
@patch("device_guardian.setup.wizard.TelegramClient")
def test_wizard_complete_success_flow(
    mock_telegram_cls,
    mock_poll_chats,
    mock_detect_cams,
    mock_test_cam,
    mock_get_loc,
    mock_trigger_alert,
    tmp_path: Path,
):
    """Verify full end-to-end wizard flow through all steps to completion."""
    env_file = tmp_path / ".env"

    # Mock Telegram token validation
    mock_tg = MagicMock()
    mock_tg.verify_credentials.return_value = TelegramResponse(
        success=True,
        data={"username": "TestGuardianBot"},
    )
    mock_telegram_cls.return_value = mock_tg

    # Mock Chat detection
    mock_poll_chats.return_value = [
        DetectedChat(chat_id="987654321", display_name="@testuser")
    ]

    # Mock Camera
    mock_detect_cams.return_value = [0]
    mock_test_cam.return_value = (True, ["Camera opened", "Frame captured"], None)

    # Mock Location
    mock_get_loc.return_value = LocationInfo(
        city="Kochi", region="Kerala", country="India", is_available=True
    )

    # Mock Final Alert
    mock_trigger_alert.return_value = AlertResult(
        success=True,
        reason="Setup Complete",
        camera_success=True,
        location_success=True,
        telegram_success=True,
    )

    io = MockIO(inputs=[
        "",                              # Welcome ENTER
        "y",                             # Accept privacy
        "123456789:ABC_SECRET_TOKEN",    # Token entry
        "",                              # Press ENTER for auto chat detection
        "y",                             # Confirm detected chat
        "y",                             # Test camera
        "y",                             # Save configuration
        "y",                             # Send final test alert
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=env_file,
    )
    success = wizard.run()

    assert success is True
    assert env_file.is_file()

    # Verify saved settings
    loaded = load_config(env_path=env_file)
    assert loaded.telegram_bot_token == "123456789:ABC_SECRET_TOKEN"
    assert loaded.telegram_chat_id == "987654321"
    assert loaded.camera_index == 0

    # Security verification: raw bot token must NOT appear in output!
    out = io.output_text()
    assert "SETUP COMPLETE" in out
    # Raw token was typed, but wizard should never print the full token itself
    assert "Verified (@TestGuardianBot)" in out


@patch("device_guardian.setup.wizard.poll_for_chat_id")
@patch("device_guardian.setup.wizard.detect_available_cameras")
@patch("device_guardian.setup.wizard.get_approximate_location")
@patch("device_guardian.setup.wizard.TelegramClient")
def test_wizard_multiple_chats_selection(
    mock_telegram_cls,
    mock_get_loc,
    mock_detect_cams,
    mock_poll_chats,
    tmp_path: Path,
):
    """Verify handling when multiple chats are detected and user chooses one."""
    env_file = tmp_path / ".env"

    mock_tg = MagicMock()
    mock_tg.verify_credentials.return_value = TelegramResponse(
        success=True,
        data={"username": "Bot"},
    )
    mock_telegram_cls.return_value = mock_tg

    # Two distinct chats detected
    mock_poll_chats.return_value = [
        DetectedChat(chat_id="111111", display_name="@user_one"),
        DetectedChat(chat_id="222222", display_name="@user_two"),
    ]
    mock_detect_cams.return_value = []
    mock_get_loc.return_value = LocationInfo(is_available=False)

    io = MockIO(inputs=[
        "",                           # Welcome
        "y",                          # Privacy
        "123456789:ABC_SECRET_KEY",   # Token
        "",                           # Auto detect chat
        "2",                          # Select second chat (222222)
        "2",                          # No camera detected, continue without camera
        "y",                          # Save configuration
        "n",                          # Skip final test alert
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=env_file,
    )
    success = wizard.run()

    assert success is True
    loaded = load_config(env_path=env_file)
    assert loaded.telegram_chat_id == "222222"


@patch("device_guardian.setup.wizard.get_approximate_location")
@patch("device_guardian.setup.wizard.detect_available_cameras")
@patch("device_guardian.setup.wizard.TelegramClient")
def test_wizard_manual_chat_id_entry(
    mock_telegram_cls,
    mock_detect_cams,
    mock_get_loc,
    tmp_path: Path,
):
    """Verify fallback to manual Chat ID entry."""
    env_file = tmp_path / ".env"

    mock_tg = MagicMock()
    mock_tg.verify_credentials.return_value = TelegramResponse(
        success=True,
        data={"username": "Bot"},
    )
    mock_telegram_cls.return_value = mock_tg
    mock_detect_cams.return_value = []
    mock_get_loc.return_value = LocationInfo(is_available=False)

    io = MockIO(inputs=[
        "",                          # Welcome
        "y",                         # Privacy
        "123456789:ABC_SECRET_KEY",  # Token
        "m",                         # Choose manual chat ID entry
        "99887766",                  # Manual Chat ID
        "2",                         # Continue without camera
        "y",                         # Save configuration
        "n",                         # Skip final test alert
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=env_file,
    )
    success = wizard.run()

    assert success is True
    loaded = load_config(env_path=env_file)
    assert loaded.telegram_chat_id == "99887766"


@patch("device_guardian.setup.wizard.TelegramClient")
def test_wizard_token_validation_failure_and_exit(mock_telegram_cls, tmp_path: Path):
    """Verify token validation failure handles retry rejection cleanly."""
    mock_tg = MagicMock()
    mock_tg.verify_credentials.return_value = TelegramResponse(
        success=False,
        error_message="Unauthorized (401)",
    )
    mock_telegram_cls.return_value = mock_tg

    io = MockIO(inputs=[
        "",                # Welcome
        "y",               # Privacy
        "invalid_token",   # Bad token
        "n",               # Do not retry
    ])

    wizard = SetupWizard(
        input_fn=io.input,
        print_fn=io.print,
        env_path=tmp_path / ".env",
    )
    success = wizard.run()

    assert success is False
    assert "Setup cancelled" in io.output_text()
    assert not (tmp_path / ".env").exists()
