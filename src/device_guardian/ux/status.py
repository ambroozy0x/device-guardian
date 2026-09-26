"""Deterministic status visualization and uncertainty model enforcement for Device Guardian (Phase 10).

Adheres strictly to Phase 10 UX standards:
- Color-independent state communication combining geometric glyphs, brackets, and uppercase labels.
- Strict uncertainty rules: UNKNOWN is never SAFE; NOT_CONFIGURED is never PROTECTED.
- Non-predictive: Absence of evidence is never represented as absence of risk.
"""

from __future__ import annotations

from enum import Enum
from typing import Union

from device_guardian.recovery.health import HealthStatus
from device_guardian.runtime.models import RuntimeState


class UXGlyph(str, Enum):
    """Accessible, color-independent geometric glyphs for terminal and UI surfaces."""

    # Subsystem Health Glyphs
    HEALTHY = "●"
    DEGRADED = "▲"
    FAILED = "■"
    UNKNOWN = "?"
    NOT_CONFIGURED = "-"

    # Runtime State Glyphs
    RUNNING = "▶"
    STOPPED = "■"
    STARTING = "⟳"
    STOPPING = "⏏"


# Mapping from status names to glyphs
GLYPH_MAP: dict[str, str] = {
    "HEALTHY": UXGlyph.HEALTHY.value,
    "DEGRADED": UXGlyph.DEGRADED.value,
    "FAILED": UXGlyph.FAILED.value,
    "UNKNOWN": UXGlyph.UNKNOWN.value,
    "NOT_CONFIGURED": UXGlyph.NOT_CONFIGURED.value,
    "RUNNING": UXGlyph.RUNNING.value,
    "STOPPED": UXGlyph.STOPPED.value,
    "STARTING": UXGlyph.STARTING.value,
    "STOPPING": UXGlyph.STOPPING.value,
}

# Standard descriptions for health and runtime states
STATE_DESCRIPTIONS: dict[str, str] = {
    "HEALTHY": "Subsystem operational and behaving within expected parameters",
    "DEGRADED": "Subsystem operational with degraded capabilities or fallback active",
    "FAILED": "Subsystem unavailable, corrupted, or experiencing operational faults",
    "UNKNOWN": "Subsystem status cannot be determined deterministically",
    "NOT_CONFIGURED": "Subsystem has not been configured by operator",
    "RUNNING": "Background monitoring service active and running",
    "STOPPED": "Background monitoring service halted",
    "STARTING": "Background monitoring service initializing subsystems",
    "STOPPING": "Background monitoring service terminating gracefully",
}


def normalize_state(state: Union[str, HealthStatus, RuntimeState]) -> str:
    """Normalize input state to standard uppercase string representation."""
    if hasattr(state, "value"):
        return str(state.value).upper()
    return str(state).strip().upper()


def get_state_glyph(state: Union[str, HealthStatus, RuntimeState]) -> str:
    """Retrieve color-independent geometric glyph for a given state."""
    norm = normalize_state(state)
    return GLYPH_MAP.get(norm, "?")


def format_status_badge(
    state: Union[str, HealthStatus, RuntimeState],
    width: int = 14,
    include_glyph: bool = True,
) -> str:
    """Format a consistent, color-independent text badge for any state.

    Examples:
        format_status_badge("HEALTHY") -> "[● HEALTHY     ]"
        format_status_badge("DEGRADED") -> "[▲ DEGRADED    ]"
        format_status_badge("UNKNOWN")  -> "[? UNKNOWN     ]"

    Args:
        state: State identifier (HealthStatus, RuntimeState, or string).
        width: Minimum label width inside brackets.
        include_glyph: Whether to prepend the geometric glyph.

    Returns:
        Formatted badge string.
    """
    norm = normalize_state(state)
    glyph = get_state_glyph(norm)

    if include_glyph:
        content = f"{glyph} {norm}"
    else:
        content = norm

    return f"[{content:<{width}}]"


def format_state_with_description(
    state: Union[str, HealthStatus, RuntimeState],
    custom_description: str = "",
) -> str:
    """Format full line containing badge, label, and explanation.

    Args:
        state: State identifier.
        custom_description: Optional specific explanation; defaults to standard text.

    Returns:
        Human-readable line combining badge and description.
    """
    norm = normalize_state(state)
    badge = format_status_badge(norm)
    desc = custom_description or STATE_DESCRIPTIONS.get(norm, "No description available")
    return f"{badge} {desc}"


def assert_uncertainty_invariants(state: str, representation: str) -> None:
    """Enforce strict Phase 10 uncertainty rules.

    Rules:
    1. UNKNOWN must NEVER be represented as SAFE, SECURE, or HEALTHY.
    2. NOT_CONFIGURED must NEVER be represented as PROTECTED or OPERATIONAL.
    3. Absence of evidence must NEVER imply absence of risk.

    Raises:
        ValueError: If an illegal semantic conversion is detected.
    """
    state_norm = normalize_state(state)
    rep_norm = representation.strip().upper()

    if state_norm == "UNKNOWN":
        forbidden_safe = {"SAFE", "SECURE", "PROTECTED", "HEALTHY", "CLEAN", "NO_THREAT"}
        for word in forbidden_safe:
            if word in rep_norm:
                raise ValueError(
                    f"Uncertainty violation: State 'UNKNOWN' cannot be represented as '{word}'."
                )

    if state_norm == "NOT_CONFIGURED":
        forbidden_prot = {"PROTECTED", "ACTIVE", "OPERATIONAL", "ENFORCED", "HEALTHY"}
        for word in forbidden_prot:
            if word in rep_norm:
                raise ValueError(
                    f"Uncertainty violation: State 'NOT_CONFIGURED' cannot be represented as '{word}'."
                )


def is_deterministic_healthy(state: Union[str, HealthStatus, RuntimeState]) -> bool:
    """Check if state is explicitly and deterministically HEALTHY.

    Returns:
        True ONLY for HEALTHY. Returns False for UNKNOWN, DEGRADED, FAILED, NOT_CONFIGURED.
    """
    norm = normalize_state(state)
    return norm == "HEALTHY"
