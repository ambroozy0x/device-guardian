"""Tests for Phase 10 status visualization and uncertainty invariants."""

import pytest

from device_guardian.recovery.health import HealthStatus
from device_guardian.runtime.models import RuntimeState
from device_guardian.ux.status import (
    GLYPH_MAP,
    STATE_DESCRIPTIONS,
    UXGlyph,
    assert_uncertainty_invariants,
    format_state_with_description,
    format_status_badge,
    get_state_glyph,
    is_deterministic_healthy,
    normalize_state,
)


def test_glyph_mapping_completeness():
    """Verify all health and runtime states have defined accessible geometric glyphs."""
    expected_states = [
        "HEALTHY",
        "DEGRADED",
        "FAILED",
        "UNKNOWN",
        "NOT_CONFIGURED",
        "RUNNING",
        "STOPPED",
        "STARTING",
        "STOPPING",
    ]
    for state in expected_states:
        glyph = get_state_glyph(state)
        if state != "UNKNOWN":
            assert glyph != "?", f"State {state} missing specific glyph mapping"
        else:
            assert glyph == "?"
        assert glyph in GLYPH_MAP.values()


def test_format_status_badge_combines_glyph_and_label():
    """Verify badge formatting is color-independent and combines glyph with uppercase label."""
    badge_healthy = format_status_badge("HEALTHY", width=12)
    assert "[● HEALTHY   ]" in badge_healthy

    badge_degraded = format_status_badge(HealthStatus.DEGRADED, width=12)
    assert "[▲ DEGRADED  ]" in badge_degraded

    badge_unknown = format_status_badge(HealthStatus.UNKNOWN, width=12)
    assert "[? UNKNOWN   ]" in badge_unknown

    badge_not_conf = format_status_badge(HealthStatus.NOT_CONFIGURED, width=16)
    assert "[- NOT_CONFIGURED]" in badge_not_conf

    badge_running = format_status_badge(RuntimeState.RUNNING, width=12)
    assert "[▶ RUNNING   ]" in badge_running

    badge_stopped = format_status_badge(RuntimeState.STOPPED, width=12)
    assert "[■ STOPPED   ]" in badge_stopped


def test_format_state_with_description():
    """Verify format_state_with_description produces full line with badge and explanation."""
    line = format_state_with_description("HEALTHY")
    assert "[● HEALTHY" in line
    assert "operational" in line.lower()

    custom_line = format_state_with_description("DEGRADED", "Custom fallback active")
    assert "[▲ DEGRADED" in custom_line
    assert "Custom fallback active" in custom_line


def test_uncertainty_invariant_unknown_never_safe():
    """Verify that UNKNOWN can never be represented as SAFE, SECURE, or HEALTHY."""
    # Valid representation
    assert_uncertainty_invariants("UNKNOWN", "Subsystem status UNKNOWN")
    assert_uncertainty_invariants("UNKNOWN", "[? UNKNOWN] Verification incomplete")

    # Forbidden mappings
    for forbidden in ["SAFE", "SECURE", "PROTECTED", "HEALTHY", "CLEAN", "NO_THREAT"]:
        with pytest.raises(ValueError, match="Uncertainty violation"):
            assert_uncertainty_invariants("UNKNOWN", f"Device is {forbidden}")


def test_uncertainty_invariant_not_configured_never_protected():
    """Verify that NOT_CONFIGURED can never be represented as PROTECTED or OPERATIONAL."""
    # Valid representation
    assert_uncertainty_invariants("NOT_CONFIGURED", "Telegram channel NOT_CONFIGURED")

    # Forbidden mappings
    for forbidden in ["PROTECTED", "ACTIVE", "OPERATIONAL", "ENFORCED", "HEALTHY"]:
        with pytest.raises(ValueError, match="Uncertainty violation"):
            assert_uncertainty_invariants("NOT_CONFIGURED", f"Subsystem is {forbidden}")


def test_deterministic_healthy_check():
    """Verify is_deterministic_healthy returns True ONLY for HEALTHY."""
    assert is_deterministic_healthy("HEALTHY") is True
    assert is_deterministic_healthy(HealthStatus.HEALTHY) is True

    # None of these are deterministically healthy
    assert is_deterministic_healthy("UNKNOWN") is False
    assert is_deterministic_healthy("DEGRADED") is False
    assert is_deterministic_healthy("FAILED") is False
    assert is_deterministic_healthy("NOT_CONFIGURED") is False
    assert is_deterministic_healthy("SAFE") is False
