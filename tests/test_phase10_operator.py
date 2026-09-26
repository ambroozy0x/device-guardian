"""Tests for Phase 10 unified operator status surface and 15 inquiries."""

from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig
from device_guardian.recovery.health import HealthStatus, SubsystemHealth, SystemHealthReport
from device_guardian.ux.operator import (
    format_operator_dashboard,
    get_operator_summary,
)


@pytest.fixture
def mock_config():
    return AppConfig(
        telegram_bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        telegram_chat_id="123456789",
        camera_alert_enabled=True,
        location_alert_enabled=True,
        voice_warning_enabled=True,
    )


def test_operator_summary_structure(mock_config):
    """Verify operator summary contains all required structural sections."""
    summary = get_operator_summary(config=mock_config)
    assert "version" in summary
    assert "runtime" in summary
    assert "configuration" in summary
    assert "health" in summary
    assert "recovery" in summary
    assert "updates" in summary


def test_operator_dashboard_answers_15_inquiries(mock_config):
    """Verify dashboard explicitly answers all 15 operator inquiries."""
    summary = get_operator_summary(config=mock_config)
    dashboard = format_operator_dashboard(summary)

    # Check 15 inquiries presence
    assert "1. Running:" in dashboard
    assert "2. Configured:" in dashboard
    assert "3. Security Engine:" in dashboard
    assert "4. Degraded Subsystems:" in dashboard
    assert "5. Recent Activity:" in dashboard
    assert "6. Alert Generation:" in dashboard
    assert "7. Alert Suppression:" in dashboard
    assert "8. Telegram Channel:" in dashboard
    assert "9. Available Sensors:" in dashboard
    assert "10. Update Pending:" in dashboard
    assert "11. Recovery Required:" in dashboard
    assert "12. Safe Next Action:" in dashboard
    assert "13. Destructive Action:" in dashboard
    assert "14. Local Storage:" in dashboard
    assert "15. Remote Transfer:" in dashboard


def test_operator_dashboard_empty_states():
    """Verify empty states are informative and avoid raw brackets or None."""
    empty_summary = {
        "version": "0.1.0",
        "runtime": {
            "state": "STOPPED",
            "pid": None,
            "uptime": "00:00:00",
            "is_locked": False,
            "startup_enabled": False,
            "restarts_count": 0,
            "events_processed": 0,
            "alerts_dispatched": 0,
            "alerts_filtered": 0,
            "alerts_cooldown": 0,
            "last_cycle": None,
            "last_error": None,
        },
        "configuration": {
            "loaded": True,
            "error": None,
            "telegram_configured": False,
            "camera_enabled": False,
            "location_enabled": False,
            "voice_enabled": False,
        },
        "health": {
            "overall": "HEALTHY",
            "subsystems": [],
            "degraded_count": 0,
            "degraded_subsystems": [],
            "failed_count": 0,
            "failed_subsystems": [],
        },
        "recovery": {
            "recovery_required": False,
            "state_files": {},
            "data_directory": "/tmp/test",
        },
        "updates": {
            "current_version": "0.1.0",
            "interrupted_transaction": None,
            "rollback_available": False,
            "rollback_versions": [],
        },
    }

    dashboard = format_operator_dashboard(empty_summary)

    # Ensure meaningful empty state messages
    assert "No security events recorded (system operating normally)" in dashboard
    assert "NONE (All active subsystems operating normally)" in dashboard
    assert "No update transaction is active" in dashboard
    assert "None stored (initial clean release)" in dashboard
    assert "All monitored state files are intact; no recovery actions required" in dashboard

    # Ensure no raw ugly string representations
    assert "None (inactive)" in dashboard
    assert "[]" not in dashboard


def test_operator_dashboard_degraded_and_recovery_alert():
    """Verify degraded subsystems and recovery requirements trigger explicit operator guidance."""
    deg_summary = {
        "version": "0.1.0",
        "runtime": {
            "state": "RUNNING",
            "pid": 4321,
            "uptime": "01:23:45",
            "is_locked": True,
            "startup_enabled": True,
            "restarts_count": 1,
            "events_processed": 5,
            "alerts_dispatched": 1,
            "alerts_filtered": 2,
            "alerts_cooldown": 1,
            "last_cycle": "2026-09-26 14:00:00",
            "last_error": None,
        },
        "configuration": {
            "loaded": True,
            "error": None,
            "telegram_configured": False,
            "camera_enabled": True,
            "location_enabled": True,
            "voice_enabled": True,
        },
        "health": {
            "overall": "DEGRADED",
            "subsystems": [
                {"name": "Telegram Subsystem", "status": "NOT_CONFIGURED", "message": "Credentials missing"},
                {"name": "SecretStore Subsystem", "status": "DEGRADED", "message": "DPAPI fallback active"},
            ],
            "degraded_count": 1,
            "degraded_subsystems": ["SecretStore Subsystem"],
            "failed_count": 0,
            "failed_subsystems": [],
        },
        "recovery": {
            "recovery_required": True,
            "state_files": {
                "runtime_status.json": {"exists": True, "has_backup": True, "corrupted_copies": ["corrupt.1"]}
            },
            "data_directory": "/data",
        },
        "updates": {
            "current_version": "0.1.0",
            "interrupted_transaction": None,
            "rollback_available": True,
            "rollback_versions": ["0.0.9"],
        },
    }

    dashboard = format_operator_dashboard(deg_summary)

    assert "SecretStore Subsystem" in dashboard
    assert "YES (Corrupted state files detected; run --repair-state)" in dashboard
    assert "Execute 'device-guardian --repair-state'" in dashboard
    assert "Available (v0.0.9)" in dashboard


def test_operator_dashboard_secret_redaction(mock_config):
    """Verify that sensitive tokens and chat IDs never appear in operator dashboard."""
    raw_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
    summary = get_operator_summary(config=mock_config)
    dashboard = format_operator_dashboard(summary)

    assert raw_token not in dashboard
    assert "ABC-DEF" not in dashboard
