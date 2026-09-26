"""Tests for Phase 10 destructive action confirmation workflows."""

import pytest

from device_guardian.ux.confirmations import (
    confirm_action,
    confirm_remove_startup,
    confirm_repair_state,
    confirm_rollback,
)


def test_confirm_action_structure_and_cancellation(capsys):
    """Verify confirmation displays Action, Effect, Preserved, Changed, and defaults to Cancel."""
    # Test default cancellation with Enter ('')
    result = confirm_action(
        action_name="Reset Application Configuration",
        effect="Resets all custom settings to factory defaults.",
        preserved=["Encrypted credentials in SecretStore", "Audit logs"],
        changed=["device_guardian.json configuration file"],
        assume_yes=False,
        input_fn=lambda prompt: "",
    )
    assert result is False

    captured = capsys.readouterr().out
    assert "DESTRUCTIVE ACTION CONFIRMATION" in captured
    assert "Action:    Reset Application Configuration" in captured
    assert "Effect:    Resets all custom settings" in captured
    assert "Preserved (Will NOT be deleted or modified):" in captured
    assert "[✓] Encrypted credentials" in captured
    assert "What May Change:" in captured
    assert "[!] device_guardian.json" in captured
    assert "Cancel Option: Press [N] or Enter to cancel safely" in captured
    assert "[CANCELLED]" in captured


def test_confirm_action_explicit_yes():
    """Verify confirmation succeeds when operator enters 'y' or 'yes'."""
    assert confirm_action(
        action_name="Test Action",
        effect="Test Effect",
        preserved=["Nothing"],
        changed=["State"],
        input_fn=lambda prompt: "y",
    ) is True

    assert confirm_action(
        action_name="Test Action",
        effect="Test Effect",
        preserved=["Nothing"],
        changed=["State"],
        input_fn=lambda prompt: "YES",
    ) is True


def test_confirm_action_handles_input_interrupts(capsys):
    """Verify confirm_action handles EOFError and KeyboardInterrupt gracefully."""
    def raise_eof(p):
        raise EOFError()

    assert confirm_action(
        action_name="Interrupt Action",
        effect="Effect",
        preserved=[],
        changed=[],
        input_fn=raise_eof,
    ) is False

    def raise_kb(p):
        raise KeyboardInterrupt()

    assert confirm_action(
        action_name="Interrupt Action",
        effect="Effect",
        preserved=[],
        changed=[],
        input_fn=raise_kb,
    ) is False


def test_confirm_action_assume_yes_bypasses_prompt(capsys):
    """Verify assume_yes=True bypasses input prompt immediately."""
    result = confirm_action(
        action_name="Automated Action",
        effect="Auto Effect",
        preserved=[],
        changed=[],
        assume_yes=True,
    )
    assert result is True
    # Verify no interactive prompt output was generated
    captured = capsys.readouterr().out
    assert "DESTRUCTIVE ACTION CONFIRMATION" not in captured


def test_specific_confirmation_wrappers():
    """Verify specific confirmation helpers invoke confirm_action with appropriate profiles."""
    assert confirm_rollback(target_version="0.0.9", assume_yes=True) is True
    assert confirm_repair_state(assume_yes=True) is True
    assert confirm_remove_startup(assume_yes=True) is True
