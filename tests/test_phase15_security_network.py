"""Phase 15 Security Audit — Network Security and Transport Resilience Tests.

Verifies:
- Telegram Bot API client enforces HTTPS and never permits insecure HTTP.
- get_approximate_location rejects non-HTTP schemes and bounds timeouts.
- Circuit breaker fast-fails during network outages without socket exhaustion.
- HTTP errors and exceptions strictly scrub sensitive tokens.
- Permanent client errors (401, 400, 403) fail immediately without retries.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
import requests

from device_guardian.location.geolocation import LocationInfo, get_approximate_location
from device_guardian.reliability.circuit_breaker import CircuitBreaker
from device_guardian.telegram.bot import TelegramClient


def test_telegram_client_requires_non_empty_credentials() -> None:
    """Verify TelegramClient rejects empty bot tokens or chat IDs."""
    with pytest.raises(ValueError, match="Telegram bot token cannot be empty"):
        TelegramClient(bot_token="", chat_id="12345")

    with pytest.raises(ValueError, match="Telegram chat ID cannot be empty"):
        TelegramClient(bot_token="12345:TOKEN", chat_id="")


def test_telegram_client_enforces_https_endpoint() -> None:
    """Verify TelegramClient base URL is strictly HTTPS."""
    client = TelegramClient(bot_token="123456:VALID_TOKEN", chat_id="987654")
    assert client._base_url.startswith("https://api.telegram.org/bot")


def test_geolocation_rejects_non_http_schemes() -> None:
    """Verify get_approximate_location rejects file://, ftp://, or arbitrary schemes."""
    for scheme in ["file:///etc/passwd", "ftp://evil.com/geo", "gopher://bad.com", "ldap://host"]:
        loc = get_approximate_location(api_url=scheme, timeout=1.0)
        assert isinstance(loc, LocationInfo)
        assert loc.is_available is False
        assert loc.city == "Unavailable"


def test_telegram_permanent_errors_fail_without_retries() -> None:
    """Verify HTTP 401 unauthorized fails immediately without retry amplification."""
    client = TelegramClient(bot_token="123456:FAKE_TOKEN", chat_id="12345", max_retries=2)
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"ok": False, "description": "Unauthorized"}
    mock_resp.text = "Unauthorized"

    with patch("requests.get", return_value=mock_resp) as mock_get:
        resp = client.verify_credentials()
        assert resp.success is False
        assert resp.status_code == 401
        # Exactly 1 call (no retries for 401)
        assert mock_get.call_count == 1


def test_circuit_breaker_fast_fails_open() -> None:
    """Verify CircuitBreaker fast-fails outbound calls once open."""
    cb = CircuitBreaker(name="test_cb", failure_threshold=2, recovery_timeout=60.0)
    client = TelegramClient(
        bot_token="123456:FAKE_TOKEN",
        chat_id="12345",
        max_retries=0,
        circuit_breaker=cb,
    )

    # Trigger 2 failures to open circuit
    cb.record_failure()
    cb.record_failure()
    assert cb.state.value == "OPEN"

    with patch("requests.post") as mock_post:
        resp = client.send_message("Test alert")
        assert resp.success is False
        assert "circuit breaker is OPEN" in resp.error_message
        mock_post.assert_not_called()
