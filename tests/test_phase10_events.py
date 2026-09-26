"""Tests for Phase 10 human-readable security events and alert explanations."""

import pytest

from device_guardian.ux.events import (
    HumanReadableEvent,
    format_alert_explanation,
    format_empty_event_state,
    format_security_event_block,
)


def test_human_readable_event_structure():
    """Verify HumanReadableEvent includes all required factual fields."""
    ev = HumanReadableEvent(
        what="Authentication context changed",
        when="2026-09-26 14:00:00",
        why="3 failed authentication attempts detected within 60s sliding window",
        source="Windows Security Event Log",
        state="TRIGGERED",
        action="Review Windows Security Event Log (Event ID 4625).",
        dispatch="Local alert recorded; remote notification dispatched to Telegram",
    )
    formatted = ev.format_event()

    assert "Security Event: Authentication context changed" in formatted
    assert "Time:     2026-09-26 14:00:00" in formatted
    assert "Why:      3 failed authentication attempts" in formatted
    assert "Source:   Windows Security Event Log" in formatted
    assert "State:    TRIGGERED" in formatted
    assert "Dispatch: Local alert recorded; remote notification dispatched" in formatted
    assert "Action:   Review Windows Security Event Log" in formatted


def test_anti_sensationalism_guard():
    """Verify sensationalist or predictive terminology raises ValueError."""
    forbidden_terms = [
        "Attacker detected on host",
        "Criminal detected attempting logon",
        "Intruder identified at console",
        "Device compromised by adversary",
        "Threat score evaluated at 95%",
        "Danger level critical",
    ]

    for term in forbidden_terms:
        with pytest.raises(ValueError, match="Sensationalist terminology violation"):
            HumanReadableEvent(
                what=term,
                when="2026-09-26 14:00:00",
                why="Unknown heuristic",
                source="Monitor",
                state="TRIGGERED",
                action="Panic",
                dispatch="Dispatched",
            )


def test_local_alert_vs_remote_dispatch_distinction():
    """Verify distinction between local alert recording and remote Telegram dispatch."""
    # Dispatched successfully
    out_dispatched = format_security_event_block(
        event_type="Authentication context changed",
        telegram_dispatched=True,
    )
    assert "Local alert recorded; remote notification dispatched to Telegram" in out_dispatched

    # Telegram unconfigured (offline / local only)
    out_unconfigured = format_security_event_block(
        event_type="Authentication context changed",
        telegram_dispatched=False,
        telegram_configured=False,
    )
    assert "Local alert recorded; remote notification NOT_CONFIGURED" in out_unconfigured

    # Telegram configured but dispatch failed (network error)
    out_failed = format_security_event_block(
        event_type="Authentication context changed",
        telegram_dispatched=False,
        telegram_configured=True,
    )
    assert "Local alert recorded; remote dispatch FAILED" in out_failed


def test_format_alert_explanation():
    """Verify deterministic alert explanation output."""
    explanation = format_alert_explanation(
        trigger_name="AUTH_FAILURE_THRESHOLD",
        condition_met=True,
        notification_status="Telegram dispatch attempted",
        detection_time="14:22:31",
    )
    assert "Why am I seeing this alert?" in explanation
    assert "Trigger:            AUTH_FAILURE_THRESHOLD" in explanation
    assert "Condition Met:      Yes" in explanation
    assert "Evaluation Time:    14:22:31" in explanation

    # Suppressed explanation
    suppressed = format_alert_explanation(
        trigger_name="AUTH_FAILURE_THRESHOLD",
        condition_met=True,
        notification_status="Suppressed",
        suppression_reason="Trusted network context active",
    )
    assert "Suppression Reason: Trusted network context active" in suppressed
    assert "Alert suppressed" in suppressed


def test_format_empty_event_state():
    """Verify empty event state message is informative."""
    empty_msg = format_empty_event_state()
    assert "No security events recorded (system operating normally)." in empty_msg
