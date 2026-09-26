"""Centralized Secret Redaction System for Device Guardian (Phase 6).

Provides proactive and deterministic scrubbing of sensitive credentials
(e.g., Telegram tokens, chat IDs, secret keys) across logs, exception messages,
status files, and CLI diagnostic output.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Set

# Universal pattern matching Telegram bot token structure: <digits>:<alphanumeric_- (min 30 chars)>
_TELEGRAM_TOKEN_PATTERN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")
_TELEGRAM_URL_PATTERN = re.compile(r"https?://api\.telegram\.org/bot([^/\s]+)/")
_BEARER_AUTH_PATTERN = re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;]+")
_BASIC_AUTH_PATTERN = re.compile(r"(?i)(Authorization:\s*Basic\s+)[^\s,;]+")
_QUERY_SECRET_PATTERN = re.compile(r"(?i)(?<=[?&])(token|bot_token|api_key|apikey|secret|password|key)=([^&\s]+)")
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SENSITIVE_KEY_NAMES = {
    "token",
    "bot_token",
    "telegram_bot_token",
    "secret",
    "password",
    "key",
    "api_key",
    "chat_id",
    "telegram_chat_id",
}


class SecretRedactor:
    """Manages active credential registration and deterministic redaction."""

    def __init__(self) -> None:
        self._registered_secrets: Set[str] = set()

    def register_secret(self, secret: Optional[str]) -> None:
        """Register a known sensitive secret to be scrubbed across all operations.

        Args:
            secret: Raw secret string to add to redaction filter.
        """
        if secret and isinstance(secret, str):
            clean = secret.strip()
            # Only register secrets of meaningful length to prevent accidental scrubbing of common short substrings
            if len(clean) >= 6:
                self._registered_secrets.add(clean)

    def clear(self) -> None:
        """Clear all registered secrets."""
        self._registered_secrets.clear()

    def redact(self, text: str) -> str:
        """Scrub all registered secrets, sensitive patterns, and unsafe control chars from text.

        Args:
            text: Arbitrary string content (logs, exception trace, diagnostic text).

        Returns:
            Sanitized string with sensitive tokens replaced with redaction placeholders.
        """
        if not text or not isinstance(text, str):
            return text

        # 1. Redact URL embedded tokens
        sanitized = _TELEGRAM_URL_PATTERN.sub("https://api.telegram.org/bot[REDACTED_TOKEN]/", text)

        # 2. Redact Bearer and Basic authentication headers
        sanitized = _BEARER_AUTH_PATTERN.sub(r"\1[REDACTED_TOKEN]", sanitized)
        sanitized = _BASIC_AUTH_PATTERN.sub(r"\1[REDACTED_TOKEN]", sanitized)

        # 3. Redact query parameter credentials
        sanitized = _QUERY_SECRET_PATTERN.sub(r"\1=[REDACTED_SECRET]", sanitized)

        # 4. Redact structural Telegram tokens
        sanitized = _TELEGRAM_TOKEN_PATTERN.sub("[REDACTED_TOKEN]", sanitized)

        # 5. Redact explicitly registered secrets
        for secret in self._registered_secrets:
            if secret in sanitized:
                sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")

        # 6. Strip ANSI escape sequences to prevent terminal / log injection
        sanitized = _ANSI_ESCAPE_PATTERN.sub("", sanitized)

        # 7. Strip dangerous non-printable control characters
        sanitized = _CONTROL_CHAR_PATTERN.sub("", sanitized)

        return sanitized

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively scrub sensitive keys and string values in a dictionary.

        Args:
            data: Arbitrary dictionary.

        Returns:
            Sanitized dictionary safe for JSON serialization and diagnostic inspection.
        """
        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sens in k_lower for sens in _SENSITIVE_KEY_NAMES):
                # Mask entire sensitive field
                sanitized[k] = "[REDACTED_SECRET]"
            elif isinstance(v, dict):
                sanitized[k] = self.redact_dict(v)
            elif isinstance(v, list):
                sanitized[k] = [
                    self.redact(item) if isinstance(item, str)
                    else (self.redact_dict(item) if isinstance(item, dict) else item)
                    for item in v
                ]
            elif isinstance(v, str):
                sanitized[k] = self.redact(v)
            else:
                sanitized[k] = v
        return sanitized

    def redact_exception(self, exc: Exception) -> str:
        """Format and sanitize an exception message."""
        return self.redact(f"{type(exc).__name__}: {exc}")


_GLOBAL_REDACTOR = SecretRedactor()


def get_redactor() -> SecretRedactor:
    """Obtain the global SecretRedactor instance."""
    return _GLOBAL_REDACTOR


def redact_string(text: str) -> str:
    """Convenience function to redact a string with the global SecretRedactor."""
    return _GLOBAL_REDACTOR.redact(text)
