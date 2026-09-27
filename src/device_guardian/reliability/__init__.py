"""Reliability, performance, and soak-testing infrastructure for Device Guardian (Phase 14).

Provides:
- Resource lifecycle management & memory leak defense.
- Operational reliability metrics tracking.
- Bounded network retries and circuit breaker protection.
- Rate-limited logging and log storm suppression.
- Standalone and continuous soak testing framework (smoke, short, extended, production).
"""

from __future__ import annotations

from device_guardian.reliability.metrics import (
    ReliabilityMetricsTracker,
    get_reliability_metrics,
)

__all__ = [
    "ReliabilityMetricsTracker",
    "get_reliability_metrics",
]
