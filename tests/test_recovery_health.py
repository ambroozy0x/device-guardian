"""Unit tests for Phase 8 system health assessment and deterministic status models."""

from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig
from device_guardian.recovery.health import (
    HealthStatus,
    SubsystemHealth,
    SystemHealthReport,
    assess_system_health,
)


def test_health_status_enum_values():
    """Verify strictly defined deterministic HealthStatus values."""
    assert HealthStatus.HEALTHY.value == "HEALTHY"
    assert HealthStatus.DEGRADED.value == "DEGRADED"
    assert HealthStatus.FAILED.value == "FAILED"
    assert HealthStatus.UNKNOWN.value == "UNKNOWN"
    assert HealthStatus.NOT_CONFIGURED.value == "NOT_CONFIGURED"


def test_system_health_report_overall_status_rules():
    """Verify deterministic derivation of overall system health."""
    # All healthy -> HEALTHY
    rep = SystemHealthReport(subsystems=[
        SubsystemHealth("Sub1", HealthStatus.HEALTHY, "OK"),
        SubsystemHealth("Sub2", HealthStatus.HEALTHY, "OK"),
    ])
    assert rep.overall_status == HealthStatus.HEALTHY
    assert rep.status == HealthStatus.HEALTHY

    # One degraded -> DEGRADED
    rep = SystemHealthReport(subsystems=[
        SubsystemHealth("Sub1", HealthStatus.HEALTHY, "OK"),
        SubsystemHealth("Sub2", HealthStatus.DEGRADED, "Warning"),
    ])
    assert rep.overall_status == HealthStatus.DEGRADED

    # One failed -> FAILED (overrides DEGRADED)
    rep = SystemHealthReport(subsystems=[
        SubsystemHealth("Sub1", HealthStatus.HEALTHY, "OK"),
        SubsystemHealth("Sub2", HealthStatus.DEGRADED, "Warning"),
        SubsystemHealth("Sub3", HealthStatus.FAILED, "Critical Error"),
    ])
    assert rep.overall_status == HealthStatus.FAILED

    # All not configured -> NOT_CONFIGURED
    rep = SystemHealthReport(subsystems=[
        SubsystemHealth("Sub1", HealthStatus.NOT_CONFIGURED, "N/A"),
        SubsystemHealth("Sub2", HealthStatus.NOT_CONFIGURED, "N/A"),
    ])
    assert rep.overall_status == HealthStatus.NOT_CONFIGURED


def test_system_health_report_serialization():
    """Verify SystemHealthReport format_report and to_dict produce structured non-predictive output."""
    rep = SystemHealthReport(
        timestamp="2026-09-26T12:00:00Z",
        subsystems=[
            SubsystemHealth("Camera", HealthStatus.HEALTHY, "Camera 0 ready", details={"idx": 0}),
            SubsystemHealth("Telegram", HealthStatus.DEGRADED, "Invalid token", details={"code": 401}),
        ],
    )

    formatted = rep.format_report()
    assert "Overall System Health: DEGRADED" in formatted
    assert "Camera" in formatted
    assert "Telegram" in formatted
    # Must NOT have predictive danger or threat scores
    assert "threat score" not in formatted.lower()
    assert "danger level" not in formatted.lower()

    data = rep.to_dict()
    assert data["status"] == "DEGRADED"
    assert data["overall_status"] == "DEGRADED"
    assert data["timestamp"] == "2026-09-26T12:00:00Z"
    assert len(data["subsystems"]) == 2
    assert data["subsystems"][0]["name"] == "Camera"
    assert data["subsystems"][0]["status"] == "HEALTHY"


def test_assess_system_health_unconfigured():
    """Verify assess_system_health with config=None returns appropriate subsystem statuses."""
    report = assess_system_health(config=None)
    assert isinstance(report, SystemHealthReport)
    assert len(report.subsystems) >= 7

    names = {s.name for s in report.subsystems}
    assert "Configuration" in names
    assert "Secret Store" in names
    assert "Camera Sensor" in names
    assert "Geolocation Sensor" in names
    assert "Telegram Channel" in names
    assert "Update Subsystem" in names
    assert "Single Instance Lock" in names


def test_assess_system_health_configured_mock():
    """Verify assess_system_health evaluates configured components without throwing exceptions."""
    cfg = AppConfig(
        telegram_bot_token="123456:ABCdefGHIjklMNOpqrs",
        telegram_chat_id="987654321",
    )

    with patch("device_guardian.telegram.bot.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True, "result": {"id": 123}}
        mock_get.return_value = mock_resp

        report = assess_system_health(config=cfg)
        tg_sub = next(s for s in report.subsystems if s.name == "Telegram Channel")
        assert tg_sub.status == HealthStatus.HEALTHY
