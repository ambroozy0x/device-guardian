"""Unit tests for OfflineVoiceWarning."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from device_guardian.detection.voice import DEFAULT_WARNING_TEXT, OfflineVoiceWarning


def test_voice_warning_initialization() -> None:
    """Verify default properties and custom configurations."""
    vw = OfflineVoiceWarning()
    assert vw.enabled is True
    assert vw.warning_text == DEFAULT_WARNING_TEXT

    custom = OfflineVoiceWarning(
        enabled=False,
        warning_text="Custom warning message",
        cooldown_seconds=60.0,
    )
    assert custom.enabled is False
    assert custom.warning_text == "Custom warning message"


def test_voice_warning_can_speak_cooldown() -> None:
    """Verify voice cooldown behavior."""
    vw = OfflineVoiceWarning(enabled=True, cooldown_seconds=60.0)

    # Initial state
    assert vw.can_speak(current_time=100.0) is True

    # After speaking at t=100
    vw._last_spoken_time = 100.0

    # Within cooldown at t=130
    assert vw.can_speak(current_time=130.0) is False

    # After cooldown at t=161
    assert vw.can_speak(current_time=161.0) is True


def test_voice_warning_disabled_suppresses_speech() -> None:
    """Verify disabled voice warning returns False immediately."""
    vw = OfflineVoiceWarning(enabled=False)
    assert vw.speak() is False


@patch("subprocess.run")
def test_voice_warning_windows_dispatch(mock_run: MagicMock) -> None:
    """Verify Windows speech synthesizer command dispatch."""
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    vw = OfflineVoiceWarning(enabled=True, warning_text="Test alert")
    success = vw._synthesize_speech("Windows", "Test alert", timeout=5.0)

    assert success is True
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    cmd_list = args[0]
    # Check powershell invocation
    assert any("powershell" in c.lower() for c in cmd_list)
    assert any("System.Speech" in c for c in cmd_list)


@patch("subprocess.run")
def test_voice_warning_macos_dispatch(mock_run: MagicMock) -> None:
    """Verify macOS 'say' command dispatch."""
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    vw = OfflineVoiceWarning(enabled=True, warning_text="Test alert")
    success = vw._synthesize_speech("Darwin", "Test alert", timeout=5.0)

    assert success is True
    mock_run.assert_called_once()
    args, _ = mock_run.call_args
    assert "say" in args[0][0]


@patch("shutil.which")
@patch("subprocess.run")
def test_voice_warning_linux_dispatch(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Verify Linux TTS dispatch using available command."""
    mock_which.side_effect = lambda cmd: "/usr/bin/spd-say" if cmd == "spd-say" else None
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    vw = OfflineVoiceWarning(enabled=True, warning_text="Test alert")
    success = vw._synthesize_speech("Linux", "Test alert", timeout=5.0)

    assert success is True
    mock_run.assert_called_once()


@patch("subprocess.run")
def test_voice_warning_graceful_failure_on_exception(mock_run: MagicMock) -> None:
    """Verify that subprocess errors or timeouts fail gracefully without raising."""
    mock_run.side_effect = OSError("Speech device unavailable")

    vw = OfflineVoiceWarning(enabled=True)
    success = vw.speak()
    assert success is False
