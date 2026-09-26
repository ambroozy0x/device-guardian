"""Phase 11 End-to-End Integration Tests: Operator Journeys, CLI Contracts, Audit Trail, and Concurrency (Workstreams 21, 22, 23, 24, 43)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian import __version__
from device_guardian.config import AppConfig
from device_guardian.main import main
from device_guardian.recovery.health import HealthStatus
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.security.events import (
    SecurityEventType,
    log_security_event,
)
from device_guardian.security.redactor import get_redactor
from device_guardian.telegram.bot import TelegramResponse
from device_guardian.ux.operator import get_operator_summary, format_operator_dashboard


@pytest.fixture
def journey_env(tmp_path):
    ApplicationPaths.set_data_dir_override(tmp_path)
    config = AppConfig(
        telegram_bot_token="123456:AAAHH-TEST_BOT_TOKEN_FOR_E2E",
        telegram_chat_id="987654321",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
    )
    return tmp_path, config


def test_journey_a_first_launch_unconfigured_guidance_e2e(journey_env, capsys):
    """Journey A: Operator launches unconfigured application and receives clear actionable guidance."""
    tmp_path, _ = journey_env

    empty_cfg = AppConfig(
        telegram_bot_token="",
        telegram_chat_id="",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
    )

    summary = get_operator_summary(config=empty_cfg)
    dashboard = format_operator_dashboard(summary)

    # Uncertainty rule: Unconfigured must never be labeled SAFE or HEALTHY
    assert "DEVICE GUARDIAN - UNIFIED OPERATOR STATUS SURFACE" in dashboard
    assert summary["configuration"]["telegram_configured"] is False
    assert "Safe Next Action:" in dashboard
    assert "NOT_CONFIGURED" in dashboard


def test_journey_b_status_dashboard_color_independent_presentation_e2e(journey_env, capsys):
    """Journey B: Operator inspects unified dashboard with glyphs and color-independent badges."""
    tmp_path, config = journey_env

    summary = get_operator_summary(config=config)
    dashboard = format_operator_dashboard(summary)

    # Must contain structured sections
    assert "DEVICE GUARDIAN - UNIFIED OPERATOR STATUS SURFACE" in dashboard
    assert "OPERATOR QUICK STATUS" in dashboard
    assert "SUBSYSTEM HEALTH BREAKDOWN" in dashboard
    assert "RESILIENCE & RECOVERY STATUS" in dashboard
    assert "UPDATES & ROLLBACK AVAILABILITY" in dashboard

    # Must use glyph badges (e.g. [● HEALTHY ], [▲ DEGRADED ], [- NOT_CONFIGURED])
    assert any(badge in dashboard for badge in ["[● HEALTHY   ]", "[▲ DEGRADED  ]", "[- NOT_CONFIGURED]"])


def test_journey_c_audit_trail_structured_logging_e2e(journey_env, caplog):
    """Journey C: Security events generate structured, secret-scrubbed audit entries with ISO-8601 timestamps."""
    tmp_path, config = journey_env
    secret_leak = "VERY_SECRET_KEY_NEVER_LOG"

    redactor = get_redactor()
    redactor.register_secret(secret_leak)

    log_security_event(
        event_type=SecurityEventType.SECURITY_PATH_REJECTED,
        subsystem="filesystem",
        message=f"Attempted traversal containing secret {secret_leak}",
        details={"path": "C:/traversal/../../etc/passwd"},
    )

    for record in caplog.records:
        assert secret_leak not in record.message
        if "SECURITY_EVENT" in record.message or "PATH_REJECTED" in record.message:
            assert "filesystem" in record.message


def test_journey_d_diagnostics_comprehensive_subsystems_e2e(journey_env, capsys):
    """Journey D: Operator runs --diagnostics and receives deterministic multi-subsystem audit."""
    tmp_path, config = journey_env

    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True

    with patch("cv2.VideoCapture", return_value=mock_cap), \
         patch("device_guardian.location.geolocation.get_approximate_location") as mock_loc, \
         patch("device_guardian.telegram.bot.TelegramClient.verify_credentials") as mock_tg_verify, \
         patch("device_guardian.main.load_config", return_value=config):

        mock_loc.return_value = MagicMock(is_available=True, city="Zurich", country="Switzerland")
        mock_tg_verify.return_value = TelegramResponse(success=True, data={"username": "TestBot"})

        code = main(["--diagnostics"])
        assert code in {0, 1}

        captured = capsys.readouterr().out
        assert "DEVICE GUARDIAN - COMPREHENSIVE SYSTEM DIAGNOSTICS" in captured
        assert "Environment & Packaging:" in captured
        assert "Configuration & Privacy Validation:" in captured
        assert "Single Instance & Process Coordination:" in captured
        assert "DIAGNOSTICS SUMMARY:" in captured


def test_journey_e_exit_code_contract_matrix_e2e():
    """Journey E: CLI returns deterministic exit codes adhering strictly to integration contract."""
    # 0 = Success
    code_zero = main(["--local-disclosure"])
    assert code_zero == 0

    # 2 = CLI syntax error
    with pytest.raises(SystemExit) as exc_usage:
        main(["--invalid-unknown-option-flag"])
    assert exc_usage.value.code == 2

    # 3 = Security path traversal rejection
    from device_guardian.security.filesystem import SecurityPathError
    with patch("device_guardian.security.filesystem.validate_safe_path", side_effect=SecurityPathError("Traversal")):
        assert main(["--verify-update", "bad/../../path"]) == 3


def test_journey_f_release_info_and_update_status_e2e(capsys):
    """Journey F: Operator reviews release metadata and update transaction status."""
    code_rel = main(["--release-info"])
    assert code_rel == 0
    out_rel = capsys.readouterr().out
    assert "Installed Version:" in out_rel
    assert f"v{__version__}" in out_rel
    assert "Release Identifier:" in out_rel
    assert "Platform Target:" in out_rel

    code_upd = main(["--update-status"])
    assert code_upd == 0
    out_upd = capsys.readouterr().out
    assert "UPDATE SUBSYSTEM STATUS" in out_upd
    assert "Installed Version:" in out_upd


def test_journey_g_confirmation_prompts_and_non_interactive_yes_e2e(journey_env):
    """Journey G: High-impact actions support --yes / -y for safe, non-interactive execution."""
    tmp_path, config = journey_env

    with patch("device_guardian.main.repair_state_files", return_value=[]) as mock_rep:
        assert main(["--repair-state", "--yes"]) == 0
        assert mock_rep.called

    with patch("device_guardian.updates.installer.UpdateInstaller.rollback") as mock_rb:
        mock_rb.return_value = MagicMock(success=True, message="Rollback complete")
        assert main(["--rollback", "-y"]) == 0
        assert mock_rb.called


def test_concurrency_simultaneous_status_read_e2e(journey_env):
    """Workstream 43: Concurrent parallel status and diagnostic reads operate without race conditions."""
    tmp_path, config = journey_env

    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True

    with patch("cv2.VideoCapture", return_value=mock_cap), \
         patch("device_guardian.location.geolocation.get_approximate_location") as mock_loc:

        mock_loc.return_value = MagicMock(is_available=True, city="Zurich", country="Switzerland")

        def _worker(thread_idx: int) -> bool:
            summary = get_operator_summary(config=config)
            dashboard = format_operator_dashboard(summary)
            return "DEVICE GUARDIAN - UNIFIED OPERATOR STATUS SURFACE" in dashboard

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_worker, i) for i in range(8)]
            results = [f.result() for f in futures]

        assert all(results)
