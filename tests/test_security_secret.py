"""Tests for SecretValue encapsulation, masking, and immutability (Phase 6)."""

import pytest

from device_guardian.security.secret import SecretValue, mask_secret


def test_secret_value_masking():
    """Verify SecretValue masks representation and string output."""
    raw = "123456789:ABCdefGHI_jkl123456"
    sec = SecretValue(raw)

    # __str__ must be opaque asterisks
    assert str(sec) == "********"
    assert raw not in str(sec)

    # __repr__ must contain class name and masked preview
    repr_str = repr(sec)
    assert raw not in repr_str
    assert "SecretValue(" in repr_str
    assert "1234***3456" in repr_str

    # mask() produces standard masked preview
    assert sec.mask() == "1234***3456"

    # Raw secret extraction
    assert sec.get_secret_value() == raw
    assert sec.raw == raw


def test_secret_value_empty_and_none():
    """Verify empty and None inputs produce expected safe outputs."""
    empty1 = SecretValue("")
    assert empty1.is_empty()
    assert not bool(empty1)
    assert empty1.mask() == "***EMPTY***"
    assert empty1.get_secret_value() == ""

    empty2 = SecretValue(None)  # type: ignore
    assert empty2.is_empty()
    assert not bool(empty2)
    assert empty2.mask() == "***EMPTY***"


def test_secret_value_short():
    """Verify secrets <= 8 chars are masked with ***REDACTED*** for security."""
    short_sec = SecretValue("12345")
    assert short_sec.mask() == "***REDACTED***"
    assert str(short_sec) == "********"


def test_secret_value_equality():
    """Verify SecretValue comparison with strings and other SecretValue instances."""
    raw = "test_token_secret_12345"
    s1 = SecretValue(raw)
    s2 = SecretValue(raw)
    s3 = SecretValue("different_secret")

    # Equality with SecretValue
    assert s1 == s2
    assert s1 != s3

    # Drop-in equality with raw string for backward compatibility
    assert s1 == raw
    assert s1 != "different_secret"
    assert raw == s1

    # Incompatible types
    assert s1 != 12345
    assert s1 != None


def test_secret_value_string_methods():
    """Verify SecretValue string operations preserve raw content when explicitly invoked."""
    raw = "  123456789:SECRET_ABC  "
    sec = SecretValue(raw)

    assert len(sec) == len(raw)
    assert sec.strip() == "123456789:SECRET_ABC"
    assert sec.startswith("  1234")
    assert sec.endswith("ABC  ")
    assert "SECRET" in sec
    assert sec.split(":") == ["  123456789", "SECRET_ABC  "]
    assert sec.replace("SECRET", "TOKEN") == "  123456789:TOKEN_ABC  "


def test_secret_value_formatting():
    """Verify f-string formatting never leaks raw secret."""
    raw = "987654321:TOP_SECRET_CREDENTIAL"
    sec = SecretValue(raw)

    # Standard interpolation defaults to __str__ (opaque mask)
    formatted = f"Token is: {sec}"
    assert raw not in formatted
    assert "Token is: ********" == formatted

    # repr interpolation formats as SecretValue(...)
    formatted_repr = f"Token is: {sec!r}"
    assert raw not in formatted_repr
    assert "9876***TIAL" in formatted_repr


def test_mask_secret_helper():
    """Verify mask_secret helper function."""
    assert mask_secret(None) == "***EMPTY***"
    assert mask_secret("") == "***EMPTY***"
    assert mask_secret("short") == "***REDACTED***"
    assert mask_secret("1234567890abcdef") == "1234***cdef"
    assert mask_secret(SecretValue("1234567890abcdef")) == "1234***cdef"
