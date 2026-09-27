"""Circuit breaker pattern for resilient external network operations (Phase 14).

Prevents repeated CPU spinning, socket exhaustion, and log storms
when external services (e.g., Telegram API, IP Geolocation) experience outages.
Transitions cleanly between CLOSED, OPEN, and HALF_OPEN states.
"""

from __future__ import annotations

from enum import Enum
import threading
import time
from typing import Any, Callable, Optional, TypeVar

from device_guardian.logger import get_logger

logger = get_logger("reliability.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    """Deterministic states of a Circuit Breaker."""

    CLOSED = "CLOSED"        # Normal operation: requests allowed
    OPEN = "OPEN"            # Outage detected: requests fast-fail immediately
    HALF_OPEN = "HALF_OPEN"  # Testing recovery: limited trial requests allowed


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""

    pass


class CircuitBreaker:
    """Thread-safe circuit breaker protecting external service calls."""

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        """Initialize circuit breaker.

        Args:
            name: Identifier for logging and diagnostics.
            failure_threshold: Number of consecutive failures to trip circuit OPEN.
            recovery_timeout: Seconds to remain OPEN before attempting HALF_OPEN probe.
            success_threshold: Consecutive successes in HALF_OPEN to return to CLOSED.
        """
        self.name = name
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.1, recovery_timeout)
        self.success_threshold = max(1, success_threshold)

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.time()

    @property
    def state(self) -> CircuitState:
        """Current state of the circuit breaker, taking recovery timeout into account."""
        with self._lock:
            self._evaluate_state_transition()
            return self._state

    def _evaluate_state_transition(self) -> None:
        """Internal helper to check if OPEN circuit should transition to HALF_OPEN."""
        if self._state == CircuitState.OPEN:
            now = time.time()
            if (now - self._last_state_change) >= self.recovery_timeout:
                logger.info(
                    "Circuit breaker '%s' recovery timeout (%.1fs) elapsed. Transitioning OPEN -> HALF_OPEN.",
                    self.name,
                    self.recovery_timeout,
                )
                self._state = CircuitState.HALF_OPEN
                self._consecutive_successes = 0
                self._last_state_change = now

    def allow_request(self) -> bool:
        """Check whether a request should be permitted or fast-failed.

        Returns:
            True if request is allowed, False if fast-failed.
        """
        with self._lock:
            self._evaluate_state_transition()
            return self._state in {CircuitState.CLOSED, CircuitState.HALF_OPEN}

    def record_success(self) -> None:
        """Record a successful execution."""
        with self._lock:
            self._consecutive_failures = 0
            if self._state == CircuitState.HALF_OPEN:
                self._consecutive_successes += 1
                if self._consecutive_successes >= self.success_threshold:
                    logger.info(
                        "Circuit breaker '%s' achieved %d consecutive successes. Transitioning HALF_OPEN -> CLOSED.",
                        self.name,
                        self._consecutive_successes,
                    )
                    self._state = CircuitState.CLOSED
                    self._consecutive_successes = 0
                    self._last_state_change = time.time()

    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Record a failed execution."""
        now = time.time()
        with self._lock:
            self._last_failure_time = now
            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "Circuit breaker '%s' probe failed (%s). Transitioning HALF_OPEN -> OPEN.",
                    self.name,
                    error or "probe failure",
                )
                self._state = CircuitState.OPEN
                self._consecutive_successes = 0
                self._last_state_change = now
            elif self._state == CircuitState.CLOSED:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.failure_threshold:
                    logger.warning(
                        "Circuit breaker '%s' reached %d consecutive failures (%s). Tripping circuit CLOSED -> OPEN.",
                        self.name,
                        self._consecutive_failures,
                        error or "threshold exceeded",
                    )
                    self._state = CircuitState.OPEN
                    self._consecutive_failures = 0
                    self._last_state_change = now

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute a function through the circuit breaker.

        Args:
            func: Callable to invoke.
            *args: Positional arguments for func.
            **kwargs: Keyword arguments for func.

        Returns:
            The return value of func(*args, **kwargs).

        Raises:
            CircuitBreakerOpenError: If circuit is OPEN and fast-failing.
            Exception: Any exception raised by func on execution.
        """
        with self._lock:
            self._evaluate_state_transition()
            if self._state == CircuitState.OPEN:
                remaining = max(0.0, self.recovery_timeout - (time.time() - self._last_state_change))
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is OPEN (fast-failing; retry in {remaining:.1f}s)."
                )

        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as exc:
            self.record_failure(exc)
            raise

    def reset(self) -> None:
        """Force reset the circuit breaker to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._consecutive_failures = 0
            self._consecutive_successes = 0
            self._last_state_change = time.time()
            self._last_failure_time = 0.0
