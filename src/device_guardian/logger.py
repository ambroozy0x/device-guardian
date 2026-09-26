"""Logging infrastructure for Device Guardian.

Configures structured logging with privacy protections.
Guarantees sensitive data (e.g., bot tokens, passwords) are scrubbed.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import re
import sys
from pathlib import Path
from typing import Optional

# Common regex patterns to detect and scrub Telegram bot tokens or credentials
_TELEGRAM_TOKEN_REGEX = re.compile(r"bot\d{6,12}:[A-Za-z0-9_-]{30,}")
_URL_TOKEN_REGEX = re.compile(r"https?://api\.telegram\.org/bot([^/]+)/")
MAX_LOG_RECORD_LENGTH = 65536


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs sensitive patterns and log-injection characters."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._sanitize(record.msg, is_format_str=True)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    self._sanitize(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: (self._sanitize(str(v)) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
        return True

    @classmethod
    def _sanitize(cls, text: str, is_format_str: bool = False) -> str:
        """Sanitize text for length, credentials, ANSI escapes, and log injection."""
        if not isinstance(text, str):
            return text
        if len(text) > MAX_LOG_RECORD_LENGTH:
            text = text[:MAX_LOG_RECORD_LENGTH] + " ... [TRUNCATED_EXCESSIVE_LENGTH]"

        # Redact secrets and strip ANSI escapes
        text = cls._redact(text)

        # In log arguments, sanitize unescaped newlines/carriage returns to prevent log forging
        if not is_format_str:
            text = text.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")

        return text

    @staticmethod
    def _redact(text: str) -> str:
        try:
            from device_guardian.security.redactor import get_redactor
            return get_redactor().redact(text)
        except Exception:
            text = _URL_TOKEN_REGEX.sub("https://api.telegram.org/bot[REDACTED_TOKEN]/", text)
            text = _TELEGRAM_TOKEN_REGEX.sub("bot[REDACTED_TOKEN]", text)
            return text


_LOGGER_INITIALIZED = False


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path | str] = None,
) -> logging.Logger:
    """Initialize root logger configuration for Device Guardian.

    Args:
        log_level: Desired log level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
        log_file: Optional path to write a log file.

    Returns:
        The configured root logger.
    """
    global _LOGGER_INITIALIZED

    level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger("device_guardian")
    root_logger.setLevel(level)

    # Avoid duplicate handlers if called multiple times
    if not _LOGGER_INITIALIZED:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        redacting_filter = RedactingFilter()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(redacting_filter)
        root_logger.addHandler(console_handler)

        # File handler with bounded size rotation (10 MB, 5 backups)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                str(log_path),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(redacting_filter)
            root_logger.addHandler(file_handler)

        root_logger.propagate = False
        _LOGGER_INITIALIZED = True

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the device_guardian namespace.

    Args:
        name: Name of the module/subsystem.

    Returns:
        Child logger instance.
    """
    if not name.startswith("device_guardian"):
        name = f"device_guardian.{name}"
    return logging.getLogger(name)
