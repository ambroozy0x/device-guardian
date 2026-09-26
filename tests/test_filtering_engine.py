"""Unit tests for SmartFilterEngine orchestration."""

from __future__ import annotations

from unittest.mock import MagicMock

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.models import EnvironmentalContext
from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.models import (
    FilterContext,
    FilterDecision,
    FilterResult,
)
from device_guardian.filtering.rules import BaseFilterRule
from device_guardian.filtering.trusted import TrustedContext


class DummyHighPriorityRule(BaseFilterRule):
    """Custom test rule with high priority."""

    @property
    def rule_id(self) -> str:
        return "RULE_DUMMY_HIGH"

    @property
    def priority(self) -> int:
        return 5

    def evaluate(self, context, trusted_context, filtering_enabled=True, require_context_for_alert=False):
        if context.event.username == "special_blocked_user":
            return FilterResult(
                decision=FilterDecision.FILTER,
                rule_id=self.rule_id,
                explanation="Blocked by custom high-priority rule",
            )
        return None


def test_smart_filter_engine_rule_ordering() -> None:
    """Verify SmartFilterEngine sorts rules strictly by priority."""
    rule1 = DummyHighPriorityRule()  # priority 5
    engine = SmartFilterEngine(rules=[rule1])

    assert engine.rules[0].priority == 5
    assert engine.rules[0].rule_id == "RULE_DUMMY_HIGH"


def test_smart_filter_engine_evaluates_first_matching_rule() -> None:
    """Verify engine returns the result of the first matching rule."""
    engine = SmartFilterEngine(
        trusted_context=TrustedContext(trusted_users=["alice"]),
        rules=[DummyHighPriorityRule()],
    )

    ev_dummy = AuthenticationFailureEvent(username="special_blocked_user")
    ctx = FilterContext(event=ev_dummy, environmental_context=EnvironmentalContext())

    res = engine.evaluate(ctx)
    assert res.decision == FilterDecision.FILTER
    assert res.rule_id == "RULE_DUMMY_HIGH"


def test_smart_filter_engine_fallback_when_no_rules_match() -> None:
    """Verify engine returns default fallback when rules list is empty."""
    engine = SmartFilterEngine(rules=[])
    ctx = FilterContext(
        event=AuthenticationFailureEvent(username="anyone"),
        environmental_context=EnvironmentalContext(),
    )
    res = engine.evaluate(ctx)
    assert res.decision == FilterDecision.ALERT_ELIGIBLE
    assert res.rule_id == "RULE_DEFAULT_FALLBACK"
