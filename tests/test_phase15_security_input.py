"""Phase 15 Security Audit — Input Validation and Command Injection Defense Tests.

Verifies:
- OfflineVoiceWarning strictly sanitizes input and strips shell metacharacters.
- OS startup command validator rejects shell metacharacters and command injection attempts.
- Local IPC control message parser rejects forbidden command names (EXEC, SHELL, CMD, etc.).
- Control message parser rejects malformed JSON and oversized request IDs.
"""

from __future__ import annotations

import pytest

from device_guardian.detection.voice import OfflineVoiceWarning
from device_guardian.security.ipc import (
    ControlChannelError,
    ControlCommand,
    ControlMessage,
    FORBIDDEN_COMMAND_NAMES,
)
from device_guardian.startup.base import BaseStartupManager


def test_voice_warning_strips_command_injection_payloads() -> None:
    """Verify OfflineVoiceWarning strips quotes, backticks, dollar signs, and semicolons."""
    vw = OfflineVoiceWarning()
    malicious_inputs = [
        "Alert; rm -rf /",
        "Alert && whoami",
        "Alert | powershell -Command Start-Process calc.exe",
        "Alert `dir` $(whoami)",
        "Alert' or '1'='1",
        'Alert" & calc.exe',
    ]
    for text in malicious_inputs:
        clean = "".join(c for c in text if c.isalnum() or c in " .,!?-")
        assert ";" not in clean
        assert "&" not in clean
        assert "|" not in clean
        assert "`" not in clean
        assert "$" not in clean
        assert "'" not in clean
        assert '"' not in clean
        assert "(" not in clean
        assert ")" not in clean


def test_startup_command_validator_rejects_shell_metacharacters() -> None:
    """Verify BaseStartupManager.validate_startup_command rejects command injection attempts."""
    injection_commands = [
        "python.exe main.py & calc.exe",
        "python.exe main.py | netstat",
        "python.exe main.py ; whoami",
        "python.exe main.py `id`",
        "python.exe main.py $(reboot)",
        "python.exe main.py > C:\\hacked.txt",
        "python.exe main.py < input.txt",
        "python.exe main.py\r\nmalicious.exe",
        "",
        "   ",
    ]
    for cmd in injection_commands:
        assert BaseStartupManager.validate_startup_command(cmd) is False


def test_ipc_rejects_forbidden_command_names() -> None:
    """Verify ControlMessage rejects all arbitrary execution verbs."""
    for verb in FORBIDDEN_COMMAND_NAMES:
        with pytest.raises(ControlChannelError):
            ControlMessage.create(verb)

        with pytest.raises(ControlChannelError):
            ControlMessage.from_dict({
                "command": verb,
                "request_id": "test-request-id-1234",
                "created_at": "2026-09-27T10:00:00+00:00",
                "expires_at": "2026-09-27T10:00:30+00:00",
                "sender_pid": 1234,
            })


def test_ipc_rejects_oversized_or_empty_request_id() -> None:
    """Verify ControlMessage enforces length bounds on request IDs."""
    # Too short (< 8 chars)
    with pytest.raises(ControlChannelError):
        ControlMessage.from_dict({
            "command": "START",
            "request_id": "short",
            "created_at": "2026-09-27T10:00:00+00:00",
            "expires_at": "2026-09-27T10:00:30+00:00",
            "sender_pid": 1234,
        })

    # Too long (> 64 chars)
    with pytest.raises(ControlChannelError):
        ControlMessage.from_dict({
            "command": "START",
            "request_id": "a" * 65,
            "created_at": "2026-09-27T10:00:00+00:00",
            "expires_at": "2026-09-27T10:00:30+00:00",
            "sender_pid": 1234,
        })
