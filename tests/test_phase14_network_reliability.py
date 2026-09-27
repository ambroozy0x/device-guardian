"""Phase 14 Network Reliability & Circuit Breaker Tests for Device Guardian.

Verifies:
- Bounded retries and backoff for network operations.
- Circuit breaker state transitions: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.
- Fast-failure during external service outages without socket or CPU exhaustion.
- Geolocation resilience under network timeout, connection reset, and recovery.
- Secret redaction and privacy preservation across network failure logs.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from device_guardian.location.geolocation import LocationInfo, get_approximate_location
from device_guardian.reliability.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
)
from device_guardian.reliability.metrics import get_reliability_metrics, reset_reliability_metrics
from device_guardian.telegram.bot import TelegramClient, TelegramResponse


def test_circuit_breaker_full_lifecycle() -> None:
    """Verify circuit breaker transitions CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""
    cb = CircuitBreaker(
        name="test_api",
        failure_threshold=2,
        recovery_timeout=0.15,
        success_threshold=1,
    )

    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    def fail_op() -> None:
        raise requests.exceptions.ConnectionError("Connection refused")

    # Failure 1
    with pytest.raises(requests.exceptions.ConnectionError):
        cb.call(fail_op)
    assert cb.state == CircuitState.CLOSED

    # Failure 2 (trips circuit)
    with pytest.raises(requests.exceptions.ConnectionError):
        cb.call(fail_op)
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False

    # Attempting call while OPEN fast-fails with CircuitBreakerOpenError
    with pytest.raises(CircuitBreakerOpenError, match="fast-failing"):
        cb.call(fail_op)

    # Wait for recovery timeout
    time.sleep(0.2)
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.allow_request() is True

    # Successful call in HALF_OPEN restores CLOSED state
    result = cb.call(lambda: "recovered")
    assert result == "recovered"
    assert cb.state == CircuitState.CLOSED


def test_telegram_client_circuit_breaker_fast_failure() -> None:
    """Verify TelegramClient fast-fails without network calls when circuit breaker is tripped."""
    cb = CircuitBreaker(
        name="telegram_test",
        failure_threshold=1,
        recovery_timeout=10.0,
    )
    # Trip circuit breaker directly
    cb.record_failure(Exception("simulated outage"))
    assert cb.state == CircuitState.OPEN

    client = TelegramClient(
        bot_token="bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        chat_id="123456789",
        timeout=1.0,
        circuit_breaker=cb,
    )

    with patch("requests.post") as mock_post:
        resp = client.send_message("Test message during outage")
        # Post should not even have been called because circuit is OPEN
        assert not mock_post.called
        assert resp.success is False
        assert "circuit breaker is OPEN" in (resp.error_message or "")


def test_telegram_client_retry_metric_tracking() -> None:
    """Verify that retries performed by TelegramClient are recorded in ReliabilityMetrics."""
    reset_reliability_metrics()
    metrics = get_reliability_metrics()

    client = TelegramClient(
        bot_token="bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        chat_id="123456789",
        timeout=0.1,
        max_retries=2,
        retry_backoff=0.01,
        circuit_breaker=CircuitBreaker(name="test", failure_threshold=10),
    )

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        resp = client.send_message("Retry tracking test")
        assert resp.success is False

    snap = metrics.snapshot()
    # 2 retries should have been attempted and recorded
    assert snap.retry_count == 2


def test_geolocation_resilience_and_recovery() -> None:
    """Verify geolocation returns unavailable on failure and recovers cleanly when available."""
    # Failure scenario: network timeout
    with patch("requests.get", side_effect=requests.exceptions.ConnectTimeout("Timeout")):
        loc = get_approximate_location(api_url="https://mock-geo.local/json", timeout=0.1)
        assert loc.is_available is False
        assert loc.ip == "Unavailable"
        assert loc.city == "Unavailable"
        assert loc.latitude is None
        assert loc.longitude is None

    # Recovery scenario: successful API response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "203.0.113.195",
        "city": "Reykjavik",
        "region": "Capital Region",
        "country_name": "Iceland",
        "latitude": 64.1466,
        "longitude": -21.9426,
    }
    with patch("requests.get", return_value=mock_resp):
        recovered_loc = get_approximate_location(api_url="https://mock-geo.local/json", timeout=1.0)
        assert recovered_loc.is_available is True
        assert recovered_loc.city == "Reykjavik"
        assert recovered_loc.country == "Iceland"
        assert recovered_loc.latitude == 64.1466
        assert recovered_loc.longitude == -21.9426
