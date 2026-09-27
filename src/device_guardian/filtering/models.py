"""Data models for Smart Filtering subsystem (Phase 4).

Represents evaluation contexts, filter decisions, and explainable results.
Strictly objective and rule-based.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from device_guardian.detection.models import AuthenticationFailureEvent
    from device_guardian.environment.models import EnvironmentalContext


class FilterDecision(str, Enum):
    """Result of a filter rule evaluation."""

    ALLOW = "allow"
    FILTER = "filter"
    ALERT_ELIGIBLE = "alert_eligible"


@dataclass
class FilterResult:
    """Detailed and explainable outcome of smart filter evaluation."""

    decision: FilterDecision
    rule_id: str
    explanation: str
    matched_conditions: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=datetime.now)
    context_summary: str = ""

    def is_alert_eligible(self) -> bool:
        """Convenience method checking if alert is justified."""
        return self.decision == FilterDecision.ALERT_ELIGIBLE

    def is_filtered(self) -> bool:
        """Convenience method checking if event was benignly suppressed."""
        return self.decision == FilterDecision.FILTER


@dataclass
class FilterContext:
    """Input payload evaluated by the smart filtering engine."""

    event: AuthenticationFailureEvent
    environmental_context: EnvironmentalContext
    consecutive_failures: int = 1
    threshold: int = 3
    window_seconds: float = 60.0
    is_synthetic: bool = False
    details: dict[str, Any] = field(default_factory=dict)
