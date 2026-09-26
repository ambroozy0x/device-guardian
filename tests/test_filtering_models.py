"""Unit tests for Smart Filtering models."""

from __future__ import annotations

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.models import EnvironmentalContext
from device_guardian.filtering.models import (
    FilterContext,
    FilterDecision,
    FilterResult,
)


def test_filter_decision_enum() -> None:
    """Verify FilterDecision enum members."""
    assert FilterDecision.ALLOW.value == "allow"
    assert FilterDecision.FILTER.value == "filter"
    assert FilterDecision.ALERT_ELIGIBLE.value == "alert_eligible"


def test_filter_result_properties() -> None:
    """Verify FilterResult helper predicates."""
    res_alert = FilterResult(
        decision=FilterDecision.ALERT_ELIGIBLE,
        rule_id="RULE_TEST",
        explanation="Threshold exceeded",
    )
    assert res_alert.is_alert_eligible() is True
    assert res_alert.is_filtered() is False

    res_filter = FilterResult(
        decision=FilterDecision.FILTER,
        rule_id="RULE_TEST",
        explanation="Trusted user matched",
    )
    assert res_filter.is_alert_eligible() is False
    assert res_filter.is_filtered() is True


def test_filter_context_initialization() -> None:
    """Verify FilterContext wiring."""
    ev = AuthenticationFailureEvent(username="bob")
    env = EnvironmentalContext()
    ctx = FilterContext(
        event=ev,
        environmental_context=env,
        consecutive_failures=3,
        threshold=3,
        window_seconds=60.0,
        is_synthetic=True,
    )
    assert ctx.event.username == "bob"
    assert ctx.consecutive_failures == 3
    assert ctx.is_synthetic is True
