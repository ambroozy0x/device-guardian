"""SecretValue abstraction and secret classification for Device Guardian (Phase 6).

Guarantees sensitive values (e.g., Telegram bot tokens, chat IDs, API keys)
cannot be inadvertently leaked through repr(), str(), formatting, logging,
or exception serialization.
"""

from __future__ import annotations

from typing import Any, Optional


class SecretValue:
    """Encapsulates a sensitive string, masking it across all standard string conversions."""

    def __init__(self, value: Optional[str | SecretValue] = None) -> None:
        """Initialize SecretValue.

        Args:
            value: Raw secret string, existing SecretValue, or None.
        """
        if isinstance(value, SecretValue):
            self._secret: str = value.get_secret_value()
        elif value is None:
            self._secret = ""
        else:
            self._secret = str(value)

    def get_secret_value(self) -> str:
        """Retrieve the raw, unmasked secret string.

        Must only be invoked by authorized internal modules (e.g., TelegramClient)
        requiring the genuine credential for network communication.
        """
        return self._secret

    @property
    def raw(self) -> str:
        """Alias for get_secret_value()."""
        return self._secret

    def is_empty(self) -> bool:
        """Check if the secret is None, empty, or composed exclusively of whitespace."""
        return not bool(self._secret and self._secret.strip())

    def mask(self, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """Produce a safe, masked representation for human visual verification.

        Args:
            prefix_len: Number of characters to expose at start.
            suffix_len: Number of characters to expose at end.

        Returns:
            Masked string representation (e.g. '1234***abcd' or '***EMPTY***').
        """
        raw = self._secret.strip()
        if not raw:
            return "***EMPTY***"
        if len(raw) <= (prefix_len + suffix_len):
            return "***REDACTED***"
        return f"{raw[:prefix_len]}***{raw[-suffix_len:]}"

    def strip(self) -> SecretValue:
        """Return a new SecretValue with leading and trailing whitespace removed."""
        return SecretValue(self._secret.strip())

    def startswith(self, prefix: str | tuple[str, ...]) -> bool:
        """Check prefix on the raw secret string."""
        return self._secret.startswith(prefix)

    def endswith(self, suffix: str | tuple[str, ...]) -> bool:
        """Check suffix on the raw secret string."""
        return self._secret.endswith(suffix)

    def replace(self, old: str, new: str, count: int = -1) -> SecretValue:
        """Return new SecretValue with replaced substring."""
        return SecretValue(self._secret.replace(old, new, count))

    def split(self, sep: Optional[str] = None, maxsplit: int = -1) -> list[str]:
        """Split the raw secret string."""
        return self._secret.split(sep, maxsplit)

    def __contains__(self, item: Any) -> bool:
        """Check substring containment."""
        return str(item) in self._secret

    def __bool__(self) -> bool:
        """Truthiness evaluates whether non-whitespace secret content is present."""
        return bool(self._secret and self._secret.strip())

    def __len__(self) -> int:
        """Return length of secret content without exposing it."""
        return len(self._secret)

    def __str__(self) -> str:
        """String conversion returns masked representation to prevent accidental exposure."""
        return "********" if self._secret else "***EMPTY***"

    def __repr__(self) -> str:
        """Repr returns safe constructor syntax with masked content."""
        masked_view = self.mask()
        return f"SecretValue('{masked_view}')"

    def __format__(self, format_spec: str) -> str:
        """Formatting returns masked representation."""
        return "********" if self._secret else "***EMPTY***"

    def __eq__(self, other: Any) -> bool:
        """Allow equality comparison against other SecretValue objects or plain strings."""
        if isinstance(other, SecretValue):
            return self._secret == other._secret
        if isinstance(other, str):
            return self._secret == other
        return False

    def __hash__(self) -> int:
        return hash(self._secret)


def mask_secret(value: Optional[str | SecretValue], prefix_len: int = 4, suffix_len: int = 4) -> str:
    """Utility function to safely mask a secret or sensitive string."""
    if value is None:
        return "***EMPTY***"
    if isinstance(value, SecretValue):
        return value.mask(prefix_len=prefix_len, suffix_len=suffix_len)
    raw = str(value).strip()
    if not raw:
        return "***EMPTY***"
    if len(raw) <= (prefix_len + suffix_len):
        return "***REDACTED***"
    return f"{raw[:prefix_len]}***{raw[-suffix_len:]}"
