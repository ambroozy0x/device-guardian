"""Unit tests for Phase 8 recovery, repair, and integrity verification CLI commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian import __version__
from device_guardian.main import (
    main,
    repair_state_cli,
    show_recovery_status,
    verify_installation_cli,
)
from device_guardian.recovery.health import HealthStatus, SystemHealthReport


def test_cli_version_includes_phase_8(capsys):
    """Verify --version argument outputs Phase 8 description."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert f"Device Guardian v{__version__}" in captured.out or f"Device Guardian v{__version__}" in captured.err
    assert "Phase 8" in captured.out or "Phase 8" in captured.err


def test_cli_recovery_status_invocation(capsys):
    """Verify --recovery-status argument executes cleanly and displays recovery information."""
    mock_health = SystemHealthReport(subsystems=[])
    mock_status = {
        "recovery_required": False,
        "system_health": mock_health.to_dict(),
        "execution_mode": "source",
        "data_directory": "test_dir",
        "state_files": {
            "runtime_status.json": {"exists": True, "has_backup": True, "corrupted_copies": []}
        },
    }

    with patch("device_guardian.main.get_recovery_status", return_value=mock_status):
        code = main(["--recovery-status"])
        assert code == 0
        captured = capsys.readouterr()
        assert "DISASTER RECOVERY & SYSTEM HEALTH" in captured.out
        assert "Overall System Health" in captured.out
        assert "runtime_status.json" in captured.out


def test_cli_repair_state_invocation(capsys):
    """Verify --repair-state argument executes and outputs repaired files."""
    mock_repairs = [
        {
            "target": "runtime_status.json",
            "action": "repaired",
            "preserved_backup": "runtime_status.json.corrupt.123",
            "reason": "Corrupt JSON",
        }
    ]

    with patch("device_guardian.main.repair_state_files", return_value=mock_repairs):
        code = main(["--repair-state"])
        assert code == 0
        captured = capsys.readouterr()
        assert "STATE FILE REPAIR & RESET" in captured.out
        assert "runtime_status.json" in captured.out
        assert "runtime_status.json.corrupt.123" in captured.out


def test_cli_repair_state_clean_invocation(capsys):
    """Verify --repair-state reports clean state when no files need repair."""
    with patch("device_guardian.main.repair_state_files", return_value=[]):
        code = main(["--repair-state"])
        assert code == 0
        captured = capsys.readouterr()
        assert "All monitored state files are intact" in captured.out


def test_cli_verify_installation_valid(capsys):
    """Verify --verify-installation displays valid installation results."""
    mock_details = {
        "mode": "Source Package",
        "executable_path": "test_app.exe",
        "executable_sha256": "abcdef123456",
        "checks": [
            {"check": "executable_presence", "status": "PASS", "message": "Binary present"},
            {"check": "data_directory", "status": "PASS", "message": "Dir verified"},
        ],
    }

    with patch("device_guardian.main.verify_installation_integrity", return_value=(True, "All checks passed.", mock_details)):
        code = main(["--verify-installation"])
        assert code == 0
        captured = capsys.readouterr()
        assert "INSTALLATION INTEGRITY VERIFICATION" in captured.out
        assert "VALID" in captured.out
        assert "executable_presence" in captured.out
