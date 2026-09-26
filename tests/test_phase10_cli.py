"""Tests for Phase 10 CLI UX, exit code contract, and help disclosure surfaces."""

from io import StringIO
from unittest.mock import MagicMock, patch
import pytest

from device_guardian import __version__
from device_guardian.main import (
    main,
    show_local_disclosure,
    show_state_model,
)


def test_cli_version_includes_phase_10(capsys):
    """Verify --version argument outputs Phase 10 description while preserving Phase 8/9 tags."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    version_text = captured.out or captured.err
    assert f"Device Guardian v{__version__}" in version_text
    assert "Phase 8" in version_text
    assert "Phase 9" in version_text
    assert "Phase 10" in version_text


def test_cli_local_disclosure_command(capsys):
    """Verify --local-disclosure outputs complete local data and privacy disclosure."""
    code = main(["--local-disclosure"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "LOCAL DATA DISCLOSURE & PRIVACY GUIDE" in captured
    assert "What Device Guardian Stores Locally:" in captured
    assert "What Remains Strictly Local:" in captured
    assert "What Information Can Leave The Machine:" in captured
    assert "What Is NEVER Collected (Absolute Boundaries):" in captured
    assert "Guarantees & Limitations:" in captured


def test_cli_state_model_command(capsys):
    """Verify --state-model outputs UX state model and uncertainty definitions."""
    code = main(["--state-model"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "DEVICE GUARDIAN - UX STATE MODEL" in captured
    assert "HEALTHY" in captured
    assert "DEGRADED" in captured
    assert "FAILED" in captured
    assert "UNKNOWN" in captured
    assert "NOT_CONFIGURED" in captured
    assert "UNKNOWN is NEVER interpreted or shown as SAFE" in captured


def test_cli_exit_code_contract():
    """Verify deterministic CLI exit code contract across standard execution paths."""
    # 0 = Success (e.g. --local-disclosure, --state-model, --recovery-status)
    with patch("device_guardian.main.get_recovery_status", return_value={"recovery_required": False, "system_health": {"status": "HEALTHY", "subsystems": []}}):
        assert main(["--recovery-status"]) == 0

    # 2 = CLI Usage Error (argparse invalid argument)
    with pytest.raises(SystemExit) as exc:
        main(["--nonexistent-argument-xyz"])
    assert exc.value.code == 2

    # 3 = Security / Verification Rejection (e.g. directory traversal or insecure update path)
    from device_guardian.security.filesystem import SecurityPathError
    with patch("device_guardian.security.filesystem.validate_safe_path", side_effect=SecurityPathError("Path traversal rejected")):
        assert main(["--verify-update", "malicious/../../etc/passwd"]) == 3

    # 3 = Installation Integrity Rejection
    with patch("device_guardian.main.verify_installation_integrity", return_value=(False, "Executable hash mismatch", {})):
        assert main(["--verify-installation"]) == 3


def test_cli_destructive_actions_support_yes_flag():
    """Verify destructive CLI flags accept --yes / -y to run non-interactively."""
    with patch("device_guardian.main.repair_state_files", return_value=[]):
        assert main(["--repair-state", "--yes"]) == 0
        assert main(["--repair-state", "-y"]) == 0

    with patch("device_guardian.updates.installer.UpdateInstaller.rollback") as mock_rb:
        mock_rb.return_value = MagicMock(success=True, message="Rolled back")
        assert main(["--rollback", "--yes"]) == 0

    with patch("device_guardian.main.create_startup_manager") as mock_sm_cls:
        mock_sm = MagicMock()
        mock_sm.is_supported.return_value = True
        mock_sm.disable.return_value = True
        mock_sm_cls.return_value = mock_sm
        assert main(["--remove-startup", "--yes"]) == 0
