"""Sliding window threshold evaluation for authentication failures.

Tracks recent failure timestamps and determines when failure bursts
exceed the configured threshold within the sliding time window.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Deque

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.logger import get_logger

logger = get_logger("detection.threshold")


class SlidingWindowThresholdEngine:
    """Evaluates whether authentication failures exceed a threshold in a sliding window."""

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: float = 60.0,
    ) -> None:
        """Initialize the threshold engine.

        Args:
            threshold: Minimum number of failures required to trigger an alert (>= 1).
            window_seconds: Time window in seconds to accumulate failures (> 0).
        """
        if threshold < 1:
            raise ValueError(f"Threshold must be at least 1, got {threshold}")
        if window_seconds <= 0:
            raise ValueError(f"Window seconds must be positive, got {window_seconds}")

        self._threshold = threshold
        self._window_seconds = window_seconds
        self._events: Deque[AuthenticationFailureEvent] = deque()

    @property
    def threshold(self) -> int:
        """Configured threshold limit."""
        return self._threshold

    @property
    def window_seconds(self) -> float:
        """Configured sliding time window in seconds."""
        return self._window_seconds

    def record_event(
        self,
        event: AuthenticationFailureEvent,
    ) -> tuple[bool, int, list[AuthenticationFailureEvent]]:
        """Record a failure event and evaluate if threshold is reached within the window.

        Args:
            event: The new AuthenticationFailureEvent to evaluate.

        Returns:
            Tuple of (threshold_reached: bool, current_count: int, window_events: list).
        """
        now = event.timestamp
        cutoff = now - timedelta(seconds=self._window_seconds)

        # Discard expired events outside the sliding window
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

        # Add the new event
        self._events.append(event)
        current_count = len(self._events)

        logger.debug(
            "Recorded authentication failure (count: %d/%d in %.1fs window).",
            current_count,
            self._threshold,
            self._window_seconds,
        )

        threshold_reached = current_count >= self._threshold
        return threshold_reached, current_count, list(self._events)

    def current_events(self) -> list[AuthenticationFailureEvent]:
        """Return a copy of events currently inside the sliding window."""
        return list(self._events)

    def reset(self) -> None:
        """Clear all recorded events in the window."""
        self._events.clear()
