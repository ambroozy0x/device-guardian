"""Factual, human-readable security event representation for Device Guardian (Phase 10).

Adheres strictly to Phase 10 UX standards:
- Clear breakdown answering: WHAT, WHEN, WHY, SOURCE, STATE, ACTION, DISPATCH.
- Zero sensationalism: No speculative terms like 'Attacker detected' or 'Device compromised'.
- Zero predictive threat scores or danger percentages.
- Distinguishes local alert generation from remote dispatch.
- Meaningful empty states for event logs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


FORBIDDEN_SENSATIONAL_TERMS = [
    "ATTACKER DETECTED",
    "CRIMINAL DETECTED",
    "INTRUDER IDENTIFIED",
    "DEVICE COMPROMISED",
    "THREAT SCORE",
    "DANGER LEVEL",
]


@dataclass
class HumanReadableEvent:
    """Structured, factual breakdown of a security or operational event."""

    what: str
    when: str
    why: str
    source: str
    state: str
    action: str
    dispatch: str

    def __post_init__(self) -> None:
        """Validate that no sensationalized terms or risk scores were injected."""
        full_text = f"{self.what} {self.why} {self.action}".upper()
        for forbidden in FORBIDDEN_SENSATIONAL_TERMS:
            if forbidden in full_text:
                raise ValueError(
                    f"Sensationalist terminology violation: '{forbidden}' is prohibited in event presentation."
                )

    def format_event(self) -> str:
        """Render event as clean, structured, readable text block."""
        lines = [
            f"Security Event: {self.what}",
            f"  Time:     {self.when}",
            f"  Why:      {self.why}",
            f"  Source:   {self.source}",
            f"  State:    {self.state}",
            f"  Dispatch: {self.dispatch}",
            f"  Action:   {self.action}",
        ]
        return "\n".join(lines)


def format_security_event_block(
    event_type: str,
    timestamp: Optional[str] = None,
    reason: str = "",
    source: str = "Authentication Monitor",
    state: str = "TRIGGERED",
    recommended_action: str = "Review system logs for event details.",
    telegram_dispatched: Optional[bool] = None,
    telegram_configured: bool = True,
) -> str:
    """Format an event with standardized factual fields and dispatch status."""
    time_str = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Determine dispatch statement
    if telegram_dispatched is True:
        dispatch_str = "Local alert recorded; remote notification dispatched to Telegram"
    elif telegram_dispatched is False:
        if not telegram_configured:
            dispatch_str = "Local alert recorded; remote notification NOT_CONFIGURED"
        else:
            dispatch_str = "Local alert recorded; remote dispatch FAILED (network offline or provider error)"
    else:
        dispatch_str = "Local alert recorded only (no remote dispatch requested)"

    ev = HumanReadableEvent(
        what=event_type,
        when=time_str,
        why=reason or "Configured security threshold condition met",
        source=source,
        state=state,
        action=recommended_action,
        dispatch=dispatch_str,
    )
    return ev.format_event()


def format_alert_explanation(
    trigger_name: str,
    condition_met: bool,
    notification_status: str,
    detection_time: Optional[str] = None,
    suppression_reason: Optional[str] = None,
) -> str:
    """Explain deterministically why an alert was triggered or suppressed.

    Args:
        trigger_name: Name of the security trigger (e.g. AUTH_FAILURE_THRESHOLD).
        condition_met: Whether detection condition was met.
        notification_status: Status of notification channel.
        detection_time: Optional timestamp string.
        suppression_reason: Reason for suppression if suppressed by filter/cooldown.

    Returns:
        Structured explanation block.
    """
    time_str = detection_time or datetime.now().strftime("%H:%M:%S")
    lines = [
        "Why am I seeing this alert?",
        "---------------------------",
        f"Trigger:            {trigger_name}",
        f"Evaluation Time:    {time_str}",
        f"Condition Met:      {'Yes' if condition_met else 'No'}",
    ]

    if suppression_reason:
        lines.append(f"Suppression Reason: {suppression_reason}")
        lines.append(f"Result:             Alert suppressed (no notification dispatched)")
    else:
        lines.append(f"Notification:       {notification_status}")
        lines.append(f"Result:             Security alert processed deterministically")

    return "\n".join(lines)


def format_empty_event_state() -> str:
    """Provide helpful, clear empty state when no events exist."""
    return "No security events recorded (system operating normally)."
