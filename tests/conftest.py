"""Pytest test suite configuration and isolation fixtures."""

import pytest


@pytest.fixture(autouse=True)
def isolate_environment_variables(monkeypatch):
    """Ensure tests do not leak environment variables to other tests."""
    vars_to_clear = [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "CAMERA_INDEX",
        "REQUEST_TIMEOUT_SECONDS",
        "LOCATION_API_URL",
        "AUTH_FAILURE_THRESHOLD",
        "AUTH_FAILURE_WINDOW_SECONDS",
        "AUTH_ALERT_COOLDOWN_SECONDS",
        "VOICE_WARNING_ENABLED",
        "VOICE_WARNING_TEXT",
        "VOICE_WARNING_COOLDOWN_SECONDS",
        "SMART_FILTERING_ENABLED",
        "DEVICE_GUARDIAN_TRUSTED_USERS",
        "TRUSTED_USERS",
        "DEVICE_GUARDIAN_TRUSTED_NETWORKS",
        "TRUSTED_NETWORKS",
        "DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES",
        "TRUSTED_AUTH_TYPES",
        "ENVIRONMENTAL_TRIGGERS_ENABLED",
        "NETWORK_CONTEXT_ENABLED",
        "DEVICE_STATE_CONTEXT_ENABLED",
        "REQUIRE_CONTEXT_FOR_ALERT",
        "CAMERA_ALERT_ENABLED",
        "LOCATION_ALERT_ENABLED",
        "TELEGRAM_ALERT_ENABLED",
    ]
    for var in vars_to_clear:
        monkeypatch.delenv(var, raising=False)
