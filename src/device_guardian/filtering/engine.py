"""Smart Filter Engine coordinating deterministic rule evaluation.

Processes FilterContext through configured rules in strict priority order,
producing explainable FilterResults.
"""

from __future__ import annotations

from typing import Iterable, Optional

from device_guardian.filtering.models import FilterContext, FilterDecision, FilterResult
from device_guardian.filtering.rules import DEFAULT_RULES, BaseFilterRule
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.logger import get_logger

logger = get_logger("filtering.engine")


class SmartFilterEngine:
    """Evaluates detection events against deterministic rules and environmental context."""

    def __init__(
        self,
        trusted_context: Optional[TrustedContext] = None,
        rules: Optional[Iterable[BaseFilterRule]] = None,
        filtering_enabled: bool = True,
        require_context_for_alert: bool = False,
    ) -> None:
        """Initialize smart filter engine.

        Args:
            trusted_context: Configured trusted context definitions.
            rules: Collection of filter rules (defaults to DEFAULT_RULES).
            filtering_enabled: Master switch for smart filtering.
            require_context_for_alert: Whether alerts require positive environmental context.
        """
        self.trusted_context = trusted_context or TrustedContext()
        self.filtering_enabled = filtering_enabled
        self.require_context_for_alert = require_context_for_alert

        rule_list = list(rules) if rules is not None else list(DEFAULT_RULES)
        # Guarantee strict deterministic ordering by priority
        self._rules: list[BaseFilterRule] = sorted(rule_list, key=lambda r: r.priority)

    @property
    def rules(self) -> list[BaseFilterRule]:
        """Return registered rules in evaluation order."""
        return list(self._rules)

    def evaluate(self, context: FilterContext) -> FilterResult:
        """Evaluate FilterContext through registered rules in deterministic order.

        Args:
            context: FilterContext payload containing event and environmental telemetry.

        Returns:
            FilterResult containing decision, rule_id, and objective explanation.
        """
        for rule in self._rules:
            result = rule.evaluate(
                context=context,
                trusted_context=self.trusted_context,
                filtering_enabled=self.filtering_enabled,
                require_context_for_alert=self.require_context_for_alert,
            )
            if result is not None:
                logger.info(
                    "Filter decision: rule=%s decision=%s username=%s",
                    result.rule_id,
                    result.decision.value,
                    context.event.username,
                )
                logger.debug("Filter explanation: %s", result.explanation)
                return result

        # Fallback default: if no rule matched, preserve safety and mark alert eligible
        fallback = FilterResult(
            decision=FilterDecision.ALERT_ELIGIBLE,
            rule_id="RULE_DEFAULT_FALLBACK",
            explanation="Event evaluated with no active filters matched; passing to alert pipeline.",
            context_summary=context.environmental_context.format_summary(),
        )
        logger.info(
            "Filter decision: rule=%s decision=%s",
            fallback.rule_id,
            fallback.decision.value,
        )
        return fallback
