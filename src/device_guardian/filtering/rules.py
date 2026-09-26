"""Deterministic rule evaluations for Smart Filtering (Phase 4).

Adheres strictly to Phase 4 Rule Priority:
1. Safety & configuration validation
2. Disabled detection bypass
3. Synthetic / test context
4. Explicit trusted context
5. Environmental context requirements
6. Threshold state verification
7. Final alert eligibility
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from device_guardian.environment.models import DeviceState, NetworkState
from device_guardian.filtering.models import FilterContext, FilterDecision, FilterResult
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.logger import get_logger

logger = get_logger("filtering.rules")


class BaseFilterRule(ABC):
    """Abstract base class for a deterministic filter rule."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule."""
        raise NotImplementedError

    @property
    @abstractmethod
    def priority(self) -> int:
        """Evaluation priority (lower numbers evaluate first)."""
        raise NotImplementedError

    @abstractmethod
    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        """Evaluate rule against context.

        Returns:
            FilterResult if this rule makes a definitive decision, or None to pass to next rule.
        """
        raise NotImplementedError


class DisabledFilteringRule(BaseFilterRule):
    """Rule 2: If smart filtering is disabled, pass events directly to the alert pipeline."""

    @property
    def rule_id(self) -> str:
        return "RULE_FILTERING_DISABLED"

    @property
    def priority(self) -> int:
        return 20

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        if not filtering_enabled:
            return FilterResult(
                decision=FilterDecision.ALERT_ELIGIBLE,
                rule_id=self.rule_id,
                explanation="Smart filtering is disabled in configuration; passing event to alert pipeline.",
                matched_conditions=["filtering_disabled=True"],
                context_summary=context.environmental_context.format_summary(),
            )
        return None


class SyntheticTestRule(BaseFilterRule):
    """Rule 3: Synthetic test events bypass trusted filters for reliable test coverage."""

    @property
    def rule_id(self) -> str:
        return "RULE_SYNTHETIC_TEST"

    @property
    def priority(self) -> int:
        return 30

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        if context.is_synthetic:
            # If threshold is reached in synthetic test, allow alert
            if context.consecutive_failures >= context.threshold:
                return FilterResult(
                    decision=FilterDecision.ALERT_ELIGIBLE,
                    rule_id=self.rule_id,
                    explanation=(
                        f"Synthetic test reached threshold ({context.consecutive_failures}/{context.threshold}); "
                        f"dispatched for test verification."
                    ),
                    matched_conditions=["is_synthetic=True"],
                    context_summary=context.environmental_context.format_summary(),
                )
            else:
                return FilterResult(
                    decision=FilterDecision.FILTER,
                    rule_id=self.rule_id,
                    explanation=(
                        f"Synthetic test below threshold ({context.consecutive_failures}/{context.threshold}); "
                        f"accumulating."
                    ),
                    matched_conditions=["is_synthetic=True"],
                    context_summary=context.environmental_context.format_summary(),
                )
        return None


class ExplicitTrustedContextRule(BaseFilterRule):
    """Rule 4: Benignly filter events matching explicitly configured trusted users or contexts."""

    @property
    def rule_id(self) -> str:
        return "RULE_TRUSTED_CONTEXT_MATCH"

    @property
    def priority(self) -> int:
        return 40

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        is_trusted, reasons = trusted_context.evaluate_trust(
            context.event,
            context.environmental_context,
        )
        if is_trusted:
            explanation = (
                f"Authentication event filtered because configured trusted condition(s) matched: "
                f"{', '.join(reasons)}."
            )
            return FilterResult(
                decision=FilterDecision.FILTER,
                rule_id=self.rule_id,
                explanation=explanation,
                matched_conditions=reasons,
                context_summary=context.environmental_context.format_summary(),
            )
        return None


class EnvironmentalContextRule(BaseFilterRule):
    """Rule 5: Verify environmental requirements if strict context is required."""

    @property
    def rule_id(self) -> str:
        return "RULE_ENVIRONMENTAL_REQUIREMENT"

    @property
    def priority(self) -> int:
        return 50

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        if not require_context_for_alert:
            return None

        env = context.environmental_context
        # If strict context is required, but both device and network state are completely UNKNOWN,
        # remember Section 13: UNKNOWN != THREAT. Benignly filter rather than treating as threat.
        if env.device_state == DeviceState.UNKNOWN and env.network_context.state == NetworkState.UNKNOWN:
            return FilterResult(
                decision=FilterDecision.FILTER,
                rule_id=self.rule_id,
                explanation=(
                    "Alert filtered because REQUIRE_CONTEXT_FOR_ALERT is enabled, "
                    "but environmental telemetry was completely unavailable (UNKNOWN != THREAT)."
                ),
                matched_conditions=["device_state=UNKNOWN", "network_state=UNKNOWN"],
                context_summary=env.format_summary(),
            )

        return None


class ThresholdEvaluationRule(BaseFilterRule):
    """Rule 6: Check whether the consecutive failures have reached the configured threshold."""

    @property
    def rule_id(self) -> str:
        return "RULE_THRESHOLD_EVALUATION"

    @property
    def priority(self) -> int:
        return 60

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        if context.consecutive_failures < context.threshold:
            return FilterResult(
                decision=FilterDecision.FILTER,
                rule_id=self.rule_id,
                explanation=(
                    f"Authentication failure recorded ({context.consecutive_failures}/{context.threshold}); "
                    f"currently below the alert threshold in {context.window_seconds:.0f}s window."
                ),
                matched_conditions=[
                    f"consecutive_failures={context.consecutive_failures}",
                    f"threshold={context.threshold}",
                ],
                context_summary=context.environmental_context.format_summary(),
            )
        return None


class AlertEligibilityRule(BaseFilterRule):
    """Rule 7: Final decision rule when all conditions justify alert dispatch."""

    @property
    def rule_id(self) -> str:
        return "RULE_ALERT_ELIGIBLE"

    @property
    def priority(self) -> int:
        return 70

    def evaluate(
        self,
        context: FilterContext,
        trusted_context: TrustedContext,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> Optional[FilterResult]:
        env = context.environmental_context
        explanation = (
            f"Repeated authentication failures detected within configured window "
            f"({context.consecutive_failures} failures in {context.window_seconds:.0f}s). "
            f"Device State: {env.device_state.value}. "
            f"Network: {env.network_context.state.value}. "
            f"No trusted context matched."
        )
        return FilterResult(
            decision=FilterDecision.ALERT_ELIGIBLE,
            rule_id=self.rule_id,
            explanation=explanation,
            matched_conditions=[
                f"failures_reached_threshold={context.consecutive_failures}>={context.threshold}",
                f"device_state={env.device_state.value}",
                f"network_state={env.network_context.state.value}",
                "trusted_context_unmatched=True",
            ],
            context_summary=env.format_summary(),
        )


DEFAULT_RULES: list[BaseFilterRule] = [
    DisabledFilteringRule(),
    SyntheticTestRule(),
    ExplicitTrustedContextRule(),
    EnvironmentalContextRule(),
    ThresholdEvaluationRule(),
    AlertEligibilityRule(),
]
