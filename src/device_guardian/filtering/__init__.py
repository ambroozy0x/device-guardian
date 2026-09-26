"""Filtering subsystem for Device Guardian (Phase 4).

Provides deterministic, explainable smart filtering for authentication and
environmental detection events.
"""

from __future__ import annotations

from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.models import FilterContext, FilterDecision, FilterResult
from device_guardian.filtering.rules import (
    DEFAULT_RULES,
    AlertEligibilityRule,
    BaseFilterRule,
    DisabledFilteringRule,
    EnvironmentalContextRule,
    ExplicitTrustedContextRule,
    SyntheticTestRule,
    ThresholdEvaluationRule,
)
from device_guardian.filtering.trusted import TrustedContext

__all__ = [
    "AlertEligibilityRule",
    "BaseFilterRule",
    "DEFAULT_RULES",
    "DisabledFilteringRule",
    "EnvironmentalContextRule",
    "ExplicitTrustedContextRule",
    "FilterContext",
    "FilterDecision",
    "FilterResult",
    "SmartFilterEngine",
    "SyntheticTestRule",
    "ThresholdEvaluationRule",
    "TrustedContext",
]
