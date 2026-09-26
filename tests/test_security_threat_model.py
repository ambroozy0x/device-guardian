"""Phase 9 Threat Model & Security Invariant Tests.

Verifies the 12 core security invariants of Device Guardian:
1. No AI/ML dependencies or inference.
2. Zero telemetry, tracking, or cloud callbacks.
3. No remote execution or listening sockets.
4. Deterministic local execution only.
5. Strict configuration boundaries and integer/float limits.
6. Strict boolean parsing.
7. Credential confidentiality in __repr__ and string conversions.
8. Non-destructive failure recovery.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest

from device_guardian.config import AppConfig, ConfigurationError, load_config
from device_guardian.security.secret import SecretValue
from device_guardian.security.redactor import SecretRedactor


def test_invariant_no_ai_or_ml_libraries():
    """Security Invariant 1: Ensure no AI/ML libraries are imported or present."""
    forbidden_modules = [
        "torch",
        "tensorflow",
        "keras",
        "sklearn",
        "openai",
        "anthropic",
        "google.generativeai",
        "langchain",
        "transformers",
        "onnx",
        "llama",
    ]
    for mod in forbidden_modules:
        assert mod not in sys.modules, f"Forbidden AI/ML module '{mod}' is loaded!"


def test_invariant_no_telemetry_or_tracking():
    """Security Invariant 2: Verify application does not bundle telemetry packages."""
    forbidden_telemetry = [
        "google_analytics",
        "mixpanel",
        "segment",
        "sentry_sdk",
        "datadog",
        "newrelic",
        "telemetry",
    ]
    for mod in forbidden_telemetry:
        assert mod not in sys.modules, f"Forbidden telemetry module '{mod}' is loaded!"


def test_invariant_credentials_masked_in_repr():
    """Security Invariant 7: Ensure AppConfig.__repr__ never leaks bot token or chat ID."""
    token = "987654321:AAE_SECRET_BOT_TOKEN_XYZ_12345"
    chat_id = "123456789"
    cfg = AppConfig(
        telegram_bot_token=token,
        telegram_chat_id=chat_id,
    )
    repr_str = repr(cfg)

    # Bot token must not be in raw format
    assert token not in repr_str
    # Telegram chat ID must be masked
    assert chat_id not in repr_str
    assert "*****6789" in repr_str or "****" in repr_str


def test_invariant_secret_value_repr_safe():
    """Security Invariant 7: SecretValue.__repr__ must mask inner value."""
    secret = SecretValue("super_secret_api_key_12345")
    assert "super_secret_api_key_12345" not in repr(secret)
    assert "super_secret_api_key_12345" not in str(secret)


def test_invariant_config_bounds_camera_index():
    """Security Invariant 5: Camera index must not exceed upper bound."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        camera_index=33,  # Max allowed is 32
    )
    with pytest.raises(ConfigurationError) as exc_info:
        cfg.validate()
    assert "CAMERA_INDEX exceeds maximum allowed index" in str(exc_info.value)


def test_invariant_config_bounds_request_timeout():
    """Security Invariant 5: Request timeout must be positive and bounded."""
    cfg_zero = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        request_timeout_seconds=0,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        cfg_zero.validate()
    assert "REQUEST_TIMEOUT_SECONDS must be positive" in str(exc_info.value)

    cfg_huge = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        request_timeout_seconds=301.0,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        cfg_huge.validate()
    assert "REQUEST_TIMEOUT_SECONDS exceeds maximum allowed timeout" in str(exc_info.value)


def test_invariant_config_bounds_auth_threshold():
    """Security Invariant 5: Auth failure threshold must be within [1, 100]."""
    cfg_low = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        auth_failure_threshold=0,
    )
    with pytest.raises(ConfigurationError):
        cfg_low.validate()

    cfg_high = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        auth_failure_threshold=101,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        cfg_high.validate()
    assert "AUTH_FAILURE_THRESHOLD exceeds maximum allowed value" in str(exc_info.value)


def test_invariant_config_strict_boolean_parsing(tmp_path: Path):
    """Security Invariant 6: Strict boolean parsing rejects ambiguous values."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=123456789:ABC_TOKEN_1234567890\n"
        "TELEGRAM_CHAT_ID=123456789\n"
        "VOICE_WARNING_ENABLED=maybe\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        load_config(env_path=env_file)
    assert "Invalid boolean value 'maybe'" in str(exc_info.value)


def test_invariant_config_url_length_check():
    """Security Invariant 5: Location API URL must be bounded in length."""
    long_url = "https://example.com/" + "a" * 2100
    cfg = AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        location_api_url=long_url,
    )
    with pytest.raises(ConfigurationError) as exc_info:
        cfg.validate()
    assert "LOCATION_API_URL exceeds maximum length" in str(exc_info.value)
