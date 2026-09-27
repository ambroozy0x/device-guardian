"""Tests for Phase 7 CLI flags and commands."""

from pathlib import Path
import pytest

from device_guardian.main import main
from tests.test_updates_verifier import create_mock_update_package


def test_cli_release_info(capsys):
    """Verify --release-info flag prints release details and exits 0."""
    code = main(["--release-info"])
    assert code == 0
    captured = capsys.readouterr()
    assert "RELEASE & BUILD INFORMATION" in captured.out
    assert "Installed Version:" in captured.out
    assert "Verification Key:" in captured.out


def test_cli_update_status(capsys):
    """Verify --update-status flag prints status summary and exits 0."""
    code = main(["--update-status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "UPDATE SUBSYSTEM STATUS" in captured.out
    assert "Installed Version:" in captured.out
    assert "Transaction State:" in captured.out


def test_cli_verify_update_missing_file(capsys):
    """Verify --verify-update on nonexistent file exits with code 1."""
    code = main(["--verify-update", "nonexistent_package.zip"])
    assert code == 1
    captured = capsys.readouterr()
    assert "REJECTED" in captured.out


def test_cli_verify_update_valid_package(tmp_path: Path, capsys):
    """Verify --verify-update on authentic package passes and exits 0."""
    from device_guardian.updates.keys import set_trusted_public_key_override

    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="1.1.0")
    try:
        set_trusted_public_key_override(pub_key)
        code = main(["--verify-update", str(zip_pkg)])
        assert code == 0
        captured = capsys.readouterr()
        assert "VERIFICATION STATUS:   VALID (PASS)" in captured.out
    finally:
        set_trusted_public_key_override(None)


def test_cli_install_update_rejected_package(tmp_path: Path, capsys):
    """Verify --install-update on corrupted package is aborted and exits 1."""
    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="1.1.0", corrupt_hash=True)
    code = main(["--install-update", str(zip_pkg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "FAILED" in captured.out or "Installation aborted" in captured.out
