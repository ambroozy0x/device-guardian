"""Alert cooldown management to prevent alert storms.

Suppresses rapid consecutive alerts after a qualifying event triggers,
while allowing underlying event monitoring to continue uninterrupted.
"""

from __future__ import annotations

import time
from typing import Optional

from device_guardian.logger import get_logger

logger = get_logger("detection.cooldown")


class AlertCooldownManager:
    """Manages cooldown intervals between dispatched security alerts."""

    def __init__(self, cooldown_seconds: float = 300.0) -> None:
        """Initialize cooldown manager.

        Args:
            cooldown_seconds: Minimum seconds required between consecutive alerts (>= 0).
        """
        if cooldown_seconds < 0:
            raise ValueError(f"Cooldown seconds must be non-negative, got {cooldown_seconds}")

        self._cooldown_seconds = cooldown_seconds
        self._last_alert_timestamp: Optional[float] = None

    @property
    def cooldown_seconds(self) -> float:
        """Configured cooldown duration in seconds."""
        return self._cooldown_seconds

    def is_in_cooldown(self, current_time: Optional[float] = None) -> bool:
        """Check if currently within the alert cooldown window.

        Args:
            current_time: Optional explicit UNIX timestamp (defaults to time.time()).

        Returns:
            True if in cooldown, False if ready to alert.
        """
        if self._last_alert_timestamp is None:
            return False

        now = current_time if current_time is not None else time.time()
        elapsed = now - self._last_alert_timestamp
        return elapsed < self._cooldown_seconds

    def can_alert(self, current_time: Optional[float] = None) -> bool:
        """Determine if a new alert is permitted."""
        return not self.is_in_cooldown(current_time)

    def record_alert(self, current_time: Optional[float] = None) -> None:
        """Record the timestamp of a newly dispatched alert.

        Args:
            current_time: Optional explicit UNIX timestamp (defaults to time.time()).
        """
        now = current_time if current_time is not None else time.time()
        self._last_alert_timestamp = now
        logger.info(
            "Alert dispatched. Cooldown period of %.1f seconds activated.",
            self._cooldown_seconds,
        )

    def time_remaining(self, current_time: Optional[float] = None) -> float:
        """Calculate the seconds remaining in the current cooldown window.

        Returns:
            Float seconds remaining, or 0.0 if not in cooldown.
        """
        if self._last_alert_timestamp is None:
            return 0.0

        now = current_time if current_time is not None else time.time()
        elapsed = now - self._last_alert_timestamp
        remaining = self._cooldown_seconds - elapsed
        return max(0.0, remaining)

    def reset(self) -> None:
        """Reset cooldown state, making alerts immediately permissible."""
        self._last_alert_timestamp = None
