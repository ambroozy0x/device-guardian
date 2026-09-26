"""Tests for configuration subsystem validation and readiness reporting (Phase 6)."""

import pytest

from device_guardian.config import AppConfig
from device_guardian.security.validation import (
    ConfigValidationReport,
    ValidationState,
    validate_subsystems,
)


@pytest.fixture
def valid_config():
    return AppConfig(
        telegram_bot_token="123456789:ABC_VALID_TOKEN_1234567890",
        telegram_chat_id="123456789",
        camera_index=0,
        request_timeout_seconds=10.0,
        auth_failure_threshold=3,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
        voice_warning_enabled=True,
        smart_filtering_enabled=True,
    )


def test_validate_subsystems_fully_ready(valid_config):
    """Verify fully configured AppConfig reports ready and all valid subsystems."""
    report = validate_subsystems(valid_config)

    assert report.is_ready is True
    assert len(report.subsystems) >= 6

    # Verify individual subsystems
    status_map = {sub.name: sub.state for sub in report.subsystems}
    assert status_map["Application"] == ValidationState.VALID
    assert status_map["Runtime"] == ValidationState.VALID
    assert status_map["Detection Engine"] == ValidationState.VALID
    assert status_map["Smart Filtering"] == ValidationState.VALID
    assert status_map["Telegram Credentials"] == ValidationState.VALID
    assert status_map["Hardware Camera"] == ValidationState.VALID
    assert status_map["Geolocation API"] == ValidationState.VALID


def test_validate_subsystems_missing_credentials():
    """Verify empty/placeholder credentials produce MISSING state and remediation action."""
    config = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="",
    )
    report = validate_subsystems(config)

    assert report.is_ready is False
    status_map = {sub.name: sub.state for sub in report.subsystems}
    assert status_map["Telegram Credentials"] == ValidationState.MISSING
    assert report.recommended_action is not None
    assert "--setup" in report.recommended_action


def test_validate_subsystems_invalid_token():
    """Verify invalid format credentials produce INVALID state."""
    config = AppConfig(
        telegram_bot_token="not_a_valid_token_no_colon",
        telegram_chat_id="123456789",
    )
    report = validate_subsystems(config)

    assert report.is_ready is False
    status_map = {sub.name: sub.state for sub in report.subsystems}
    assert status_map["Telegram Credentials"] == ValidationState.INVALID


def test_validate_subsystems_disabled_features(valid_config):
    """Verify disabled modules report DISABLED validation state."""
    valid_config.smart_filtering_enabled = False
    valid_config.camera_alert_enabled = False
    valid_config.location_alert_enabled = False

    report = validate_subsystems(valid_config)
    status_map = {sub.name: sub.state for sub in report.subsystems}

    assert status_map["Smart Filtering"] == ValidationState.DISABLED
    assert status_map["Hardware Camera"] == ValidationState.DISABLED
    assert status_map["Geolocation API"] == ValidationState.DISABLED


def test_format_report_table_output(valid_config):
    """Verify format_report renders structured text table cleanly."""
    report = validate_subsystems(valid_config)
    formatted = report.format_report()

    assert "Configuration Validation" in formatted
    assert "Overall Status: READY" in formatted
    assert "Telegram Credentials" in formatted
    assert "PASS" in formatted
