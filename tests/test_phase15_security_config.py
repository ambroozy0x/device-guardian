"""Phase 15 Security Audit — Configuration Security Tests.

Verifies:
- Secure production defaults for dangerous or sensitive settings.
- Explicit validation rejects placeholder credentials (your_telegram_bot_token_here).
- Numeric limits are strictly bounded (camera_index, timeouts, threshold, window).
- Ambiguous boolean representations raise ConfigurationError.
"""

from __future__ import annotations

import pytest

from device_guardian.config import AppConfig, ConfigurationError, _parse_bool


def test_config_secure_defaults() -> None:
    """Verify application defaults favor privacy and security."""
    config = AppConfig()
    # Dangerous or invasive features default to off
    assert config.background_mode_enabled is False
    assert config.start_with_system is False
    assert config.require_context_for_alert is False
    # Single-instance mutual exclusion defaults to on
    assert config.single_instance_enabled is True
    # Cooldowns default to safe positive intervals
    assert config.auth_alert_cooldown_seconds >= 60.0
    assert config.voice_warning_cooldown_seconds >= 60.0


def test_config_validation_rejects_placeholder_tokens() -> None:
    """Verify validate() rejects unconfigured placeholder strings."""
    for placeholder in ["your_telegram_bot_token_here", "YOUR_BOT_TOKEN", "CHANGE_ME"]:
        config = AppConfig(
            telegram_bot_token=placeholder,
            telegram_chat_id="12345678",
            telegram_alert_enabled=True,
        )
        with pytest.raises(ConfigurationError, match="placeholder value"):
            config.validate()


def test_config_validation_bounds_numeric_settings() -> None:
    """Verify validate() rejects negative, zero, or excessively large settings."""
    # Negative camera index
    with pytest.raises(ConfigurationError, match="CAMERA_INDEX"):
        AppConfig(camera_index=-1).validate()

    # Camera index > 32
    with pytest.raises(ConfigurationError, match="CAMERA_INDEX"):
        AppConfig(camera_index=99).validate()

    # Timeout <= 0
    with pytest.raises(ConfigurationError, match="REQUEST_TIMEOUT_SECONDS"):
        AppConfig(request_timeout_seconds=0.0).validate()

    # Threshold < 1
    with pytest.raises(ConfigurationError, match="AUTH_FAILURE_THRESHOLD"):
        AppConfig(auth_failure_threshold=0).validate()

    # Threshold > 100
    with pytest.raises(ConfigurationError, match="AUTH_FAILURE_THRESHOLD"):
        AppConfig(auth_failure_threshold=500).validate()


def test_config_boolean_parser_rejects_ambiguous_strings() -> None:
    """Verify _parse_bool rejects ambiguous truthy/falsy values with ConfigurationError."""
    assert _parse_bool("true", "TEST_KEY") is True
    assert _parse_bool("1", "TEST_KEY") is True
    assert _parse_bool("false", "TEST_KEY") is False
    assert _parse_bool("0", "TEST_KEY") is False

    ambiguous_values = ["maybe", "enabled", "disabled", "2", "none", "null"]
    for val in ambiguous_values:
        with pytest.raises(ConfigurationError, match="Invalid boolean value"):
            _parse_bool(val, "TEST_KEY")
