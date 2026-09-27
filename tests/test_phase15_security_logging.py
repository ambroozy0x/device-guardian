"""Phase 15 Security Audit — Logging and Privacy Security Tests.

Verifies:
- DuplicateLogFilter never suppresses CRITICAL records or security audit logs.
- RedactingFilter sanitizes log arguments against newline/carriage-return injection (\\r\\n).
- RedactingFilter truncates oversized log messages (> 65,536 characters).
- RedactingFilter scrubs Telegram bot tokens, URLs, and registered secrets.
"""

from __future__ import annotations

import logging
from device_guardian.logger import DuplicateLogFilter, RedactingFilter


def test_duplicate_log_filter_never_suppresses_critical_logs() -> None:
    """Verify DuplicateLogFilter allows repeated CRITICAL records without suppression."""
    dfilter = DuplicateLogFilter(max_repeats=2, window_seconds=10.0)
    record = logging.LogRecord(
        name="test_logger",
        level=logging.CRITICAL,
        pathname="test.py",
        lineno=10,
        msg="CRITICAL: Hardware security failure detected!",
        args=(),
        exc_info=None,
    )
    # Repeated 5 times — all must return True
    for _ in range(5):
        assert dfilter.filter(record) is True


def test_duplicate_log_filter_never_suppresses_security_audit_events() -> None:
    """Verify DuplicateLogFilter allows repeated security audit records without suppression."""
    dfilter = DuplicateLogFilter(max_repeats=2, window_seconds=10.0)
    record = logging.LogRecord(
        name="security.events",
        level=logging.WARNING,
        pathname="test.py",
        lineno=20,
        msg="SECURITY_PATH_REJECTED: Unauthorized path traversal attempt.",
        args=(),
        exc_info=None,
    )
    for _ in range(5):
        assert dfilter.filter(record) is True


def test_redacting_filter_sanitizes_log_injection_newlines() -> None:
    """Verify log arguments containing \\r\\n are escaped to prevent log record forging."""
    rfilter = RedactingFilter()
    record = logging.LogRecord(
        name="app",
        level=logging.INFO,
        pathname="test.py",
        lineno=30,
        msg="User attempted action with input: %s",
        args=("normal_input\r\n[CRITICAL] FAKE SECURITY EVENT: Root access granted\n",),
        exc_info=None,
    )
    assert rfilter.filter(record) is True
    assert "\r" not in record.args[0]
    assert "\n" not in record.args[0]
    assert "\\n" in record.args[0]


def test_redacting_filter_truncates_oversized_messages() -> None:
    """Verify log records exceeding 65,536 chars are truncated safely."""
    huge_msg = "X" * 100000
    record = logging.LogRecord(
        name="app",
        level=logging.INFO,
        pathname="test.py",
        lineno=40,
        msg=huge_msg,
        args=(),
        exc_info=None,
    )
    rfilter = RedactingFilter()
    assert rfilter.filter(record) is True
    assert len(record.msg) < 70000
    assert "[TRUNCATED_EXCESSIVE_LENGTH]" in record.msg


def test_redacting_filter_scrubs_telegram_token() -> None:
    """Verify RedactingFilter scrubs Telegram bot tokens in msg and args."""
    rfilter = RedactingFilter()
    token = "123456789:ABCdefGHI_jkl1234567890abcdefABC"
    record = logging.LogRecord(
        name="app",
        level=logging.INFO,
        pathname="test.py",
        lineno=50,
        msg=f"Dispatched alert using bot token: {token}",
        args=(),
        exc_info=None,
    )
    assert rfilter.filter(record) is True
    assert token not in record.msg
    assert "[REDACTED_TOKEN]" in record.msg
