"""Tests for Phase 9 Log Injection Defense, Secret Scrubbing, and Audit Logging."""

from __future__ import annotations

import logging
from pathlib import Path
import pytest

from device_guardian.logger import (
    MAX_LOG_RECORD_LENGTH,
    RedactingFilter,
    get_logger,
    setup_logging,
)
from device_guardian.security.events import (
    SecurityAuditEvent,
    SecurityAuditLogger,
    SecurityEventType,
)
from device_guardian.security.redactor import SecretRedactor


def test_log_sanitizer_newline_escaping():
    """Verify RedactingFilter escapes carriage returns and newlines in arguments."""
    r_filter = RedactingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Login attempt from user: %s",
        args=("admin\r\n[CRITICAL] System Compromised!",),
        exc_info=None,
    )
    r_filter.filter(record)
    assert "\r" not in record.args[0]
    assert "\n" not in record.args[0]
    assert "\\n" in record.args[0]


def test_log_sanitizer_bounded_length():
    """Verify RedactingFilter truncates excessively large log messages."""
    r_filter = RedactingFilter()
    huge_payload = "A" * (MAX_LOG_RECORD_LENGTH + 5000)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="%s",
        args=(huge_payload,),
        exc_info=None,
    )
    r_filter.filter(record)
    assert len(record.args[0]) <= MAX_LOG_RECORD_LENGTH + 100
    assert "... [TRUNCATED_EXCESSIVE_LENGTH]" in record.args[0]


def test_secret_redactor_ansi_escape_scrubbing():
    """Verify SecretRedactor removes terminal escape codes (ANSI color/control sequences)."""
    redactor = SecretRedactor()
    ansi_input = "\x1b[31;1mCRITICAL ALERT\x1b[0m normal text"
    scrubbed = redactor.redact(ansi_input)
    assert "\x1b[" not in scrubbed
    assert "CRITICAL ALERT normal text" in scrubbed


def test_secret_redactor_query_param_tokens():
    """Verify SecretRedactor scrubs token/key/secret query parameters in URLs."""
    redactor = SecretRedactor()
    urls = [
        "https://api.telegram.org/bot1234:ABC/sendMessage?token=super_secret_query_val",
        "https://example.com/api?apiKey=987654321_secret&other=safe",
        "https://example.com/check?secret=TOP_SECRET_123",
    ]
    for url in urls:
        redacted = redactor.redact(url)
        assert "super_secret_query_val" not in redacted
        assert "987654321_secret" not in redacted
        assert "TOP_SECRET_123" not in redacted
        assert "[REDACTED" in redacted


def test_secret_redactor_basic_auth_headers():
    """Verify SecretRedactor scrubs Basic authorization headers."""
    redactor = SecretRedactor()
    auth_header = "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw=="
    redacted = redactor.redact(auth_header)
    assert "dXNlcjpwYXNzd29yZDEyMw==" not in redacted
    assert "Authorization: Basic [REDACTED" in redacted


def test_rotating_file_handler_used(tmp_path: Path):
    """Verify setup_logging configures a RotatingFileHandler with 10MB limit."""
    import device_guardian.logger as dg_logger
    from logging.handlers import RotatingFileHandler

    dg_logger._LOGGER_INITIALIZED = False
    log_file = tmp_path / "app.log"
    logger = setup_logging(log_level="DEBUG", log_file=str(log_file))

    rotating_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(rotating_handlers) >= 1
    handler = rotating_handlers[0]
    assert handler.maxBytes == 10 * 1024 * 1024
    assert handler.backupCount == 5


def test_security_audit_logger_records_event():
    """Verify SecurityAuditLogger formats events as structured JSON with secret redaction."""
    audit_logger = SecurityAuditLogger.get_instance()

    event = audit_logger.log_event(
        event_type=SecurityEventType.SECURITY_PATH_REJECTED,
        subsystem="filesystem",
        message="Symlink rejected",
        details={"path": "C:\\fake\\path"},
    )

    assert event.event_type == SecurityEventType.SECURITY_PATH_REJECTED
    assert event.subsystem == "filesystem"
    json_str = event.to_json()
    assert "SECURITY_PATH_REJECTED" in json_str
    assert "filesystem" in json_str
