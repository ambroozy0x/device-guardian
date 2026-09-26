"""Unit tests for deterministic Smart Filtering rules."""

from __future__ import annotations

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.models import (
    DeviceState,
    EnvironmentalContext,
    NetworkContext,
    NetworkState,
)
from device_guardian.filtering.models import (
    FilterContext,
    FilterDecision,
)
from device_guardian.filtering.rules import (
    DEFAULT_RULES,
    AlertEligibilityRule,
    DisabledFilteringRule,
    EnvironmentalContextRule,
    ExplicitTrustedContextRule,
    SyntheticTestRule,
    ThresholdEvaluationRule,
)
from device_guardian.filtering.trusted import TrustedContext


def test_rule_priority_order() -> None:
    """Verify DEFAULT_RULES are in strictly ascending priority order."""
    priorities = [rule.priority for rule in DEFAULT_RULES]
    assert priorities == sorted(priorities)
    assert len(priorities) == len(set(priorities)), "Priorities must be strictly distinct"


def test_disabled_filtering_rule() -> None:
    """Verify DisabledFilteringRule returns ALERT_ELIGIBLE when filtering is disabled."""
    rule = DisabledFilteringRule()
    ctx = FilterContext(
        event=AuthenticationFailureEvent(username="user1"),
        environmental_context=EnvironmentalContext(),
    )
    trusted = TrustedContext()

    res = rule.evaluate(ctx, trusted, filtering_enabled=False)
    assert res is not None
    assert res.decision == FilterDecision.ALERT_ELIGIBLE
    assert res.rule_id == "RULE_FILTERING_DISABLED"

    # When enabled, passes through (returns None)
    assert rule.evaluate(ctx, trusted, filtering_enabled=True) is None


def test_synthetic_test_rule() -> None:
    """Verify SyntheticTestRule allows synthetic tests to reach alert eligibility."""
    rule = SyntheticTestRule()
    trusted = TrustedContext()

    # Synthetic below threshold
    ctx_below = FilterContext(
        event=AuthenticationFailureEvent(source="SyntheticTestMonitor"),
        environmental_context=EnvironmentalContext(),
        consecutive_failures=1,
        threshold=3,
        is_synthetic=True,
    )
    res_below = rule.evaluate(ctx_below, trusted)
    assert res_below is not None
    assert res_below.decision == FilterDecision.FILTER

    # Synthetic at threshold
    ctx_at = FilterContext(
        event=AuthenticationFailureEvent(source="SyntheticTestMonitor"),
        environmental_context=EnvironmentalContext(),
        consecutive_failures=3,
        threshold=3,
        is_synthetic=True,
    )
    res_at = rule.evaluate(ctx_at, trusted)
    assert res_at is not None
    assert res_at.decision == FilterDecision.ALERT_ELIGIBLE


def test_explicit_trusted_context_rule() -> None:
    """Verify ExplicitTrustedContextRule filters trusted accounts with objective explanation."""
    rule = ExplicitTrustedContextRule()
    trusted = TrustedContext(trusted_users=["authorized_user"])

    ctx_trusted = FilterContext(
        event=AuthenticationFailureEvent(username="authorized_user"),
        environmental_context=EnvironmentalContext(),
    )
    res_trusted = rule.evaluate(ctx_trusted, trusted)
    assert res_trusted is not None
    assert res_trusted.decision == FilterDecision.FILTER
    assert "authorized_user" in res_trusted.explanation

    ctx_untrusted = FilterContext(
        event=AuthenticationFailureEvent(username="stranger"),
        environmental_context=EnvironmentalContext(),
    )
    assert rule.evaluate(ctx_untrusted, trusted) is None


def test_environmental_context_rule_unknown_is_not_threat() -> None:
    """Verify UNKNOWN environmental telemetry does not trigger an alert if context required."""
    rule = EnvironmentalContextRule()
    trusted = TrustedContext()

    env_unknown = EnvironmentalContext(
        device_state=DeviceState.UNKNOWN,
        network_context=NetworkContext(state=NetworkState.UNKNOWN),
    )
    ctx = FilterContext(
        event=AuthenticationFailureEvent(username="user1"),
        environmental_context=env_unknown,
    )

    # When require_context_for_alert is False, returns None (passes to next rule)
    assert rule.evaluate(ctx, trusted, require_context_for_alert=False) is None

    # When require_context_for_alert is True, completely unknown context is filtered
    res = rule.evaluate(ctx, trusted, require_context_for_alert=True)
    assert res is not None
    assert res.decision == FilterDecision.FILTER
    assert "UNKNOWN != THREAT" in res.explanation


def test_threshold_evaluation_rule() -> None:
    """Verify ThresholdEvaluationRule filters events below threshold."""
    rule = ThresholdEvaluationRule()
    trusted = TrustedContext()

    ctx_below = FilterContext(
        event=AuthenticationFailureEvent(username="user1"),
        environmental_context=EnvironmentalContext(),
        consecutive_failures=2,
        threshold=3,
    )
    res_below = rule.evaluate(ctx_below, trusted)
    assert res_below is not None
    assert res_below.decision == FilterDecision.FILTER
    assert "currently below the alert threshold" in res_below.explanation

    ctx_at = FilterContext(
        event=AuthenticationFailureEvent(username="user1"),
        environmental_context=EnvironmentalContext(),
        consecutive_failures=3,
        threshold=3,
    )
    assert rule.evaluate(ctx_at, trusted) is None


def test_alert_eligibility_rule() -> None:
    """Verify AlertEligibilityRule generates objective, factual alert justification."""
    rule = AlertEligibilityRule()
    trusted = TrustedContext()

    ctx = FilterContext(
        event=AuthenticationFailureEvent(username="unknown_user"),
        environmental_context=EnvironmentalContext(device_state=DeviceState.ACTIVE),
        consecutive_failures=3,
        threshold=3,
        window_seconds=60.0,
    )
    res = rule.evaluate(ctx, trusted)
    assert res is not None
    assert res.decision == FilterDecision.ALERT_ELIGIBLE
    assert "Repeated authentication failures detected" in res.explanation
    assert "hacker" not in res.explanation.lower()
    assert "attacker" not in res.explanation.lower()


def test_trusted_network_rule() -> None:
    """Verify ExplicitTrustedContextRule matches trusted network identifier."""
    rule = ExplicitTrustedContextRule()
    trusted = TrustedContext(trusted_networks=["trusted_office_net"])

    env_trusted = EnvironmentalContext(
        network_context=NetworkContext(network_identifier="trusted_office_net")
    )
    ctx_trusted = FilterContext(
        event=AuthenticationFailureEvent(username="unknown_user"),
        environmental_context=env_trusted,
    )
    res_trusted = rule.evaluate(ctx_trusted, trusted)
    assert res_trusted is not None
    assert res_trusted.decision == FilterDecision.FILTER
    assert "trusted_office_net" in res_trusted.explanation


def test_trusted_auth_type_rule() -> None:
    """Verify ExplicitTrustedContextRule matches trusted authentication type."""
    rule = ExplicitTrustedContextRule()
    trusted = TrustedContext(trusted_auth_types=["local"])

    ctx_trusted = FilterContext(
        event=AuthenticationFailureEvent(username="test_user", authentication_type="local"),
        environmental_context=EnvironmentalContext(),
    )
    res_trusted = rule.evaluate(ctx_trusted, trusted)
    assert res_trusted is not None
    assert res_trusted.decision == FilterDecision.FILTER
    assert "local" in res_trusted.explanation
