"""Unit tests for Phase 8 repair and installation verification operations."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.recovery.repair import (
    get_recovery_status,
    repair_state_files,
    verify_installation_integrity,
)
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.updates.manifest import ReleaseArtifact, ReleaseManifest


def test_repair_state_files_intact_no_action(tmp_path: Path):
    """Verify repair_state_files does nothing when state files are missing or valid."""
    with patch.object(ApplicationPaths, "get_user_data_dir", return_value=tmp_path):
        with patch.object(ApplicationPaths, "get_status_file_path", return_value=tmp_path / "runtime_status.json"):
            with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=tmp_path / "update_transaction.json"):
                repairs = repair_state_files()
                assert len(repairs) == 0


def test_repair_corrupted_runtime_status_preserves_corrupt_file(tmp_path: Path):
    """Verify corrupted runtime_status.json is preserved as .corrupt.<ts> and reset to valid default."""
    status_file = tmp_path / "runtime_status.json"
    status_file.write_text("{corrupt json: not valid!", encoding="utf-8")

    with patch.object(ApplicationPaths, "get_user_data_dir", return_value=tmp_path):
        with patch.object(ApplicationPaths, "get_status_file_path", return_value=status_file):
            with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=tmp_path / "update_transaction.json"):
                repairs = repair_state_files()

                assert len(repairs) == 1
                assert repairs[0]["action"] == "repaired"
                assert "runtime_status.json" in repairs[0]["target"]

                # Verify preserved corrupted file exists
                preserved_path = Path(repairs[0]["preserved_backup"])
                assert preserved_path.is_file()
                assert preserved_path.read_text(encoding="utf-8") == "{corrupt json: not valid!"

                # Verify new status file has clean valid JSON
                assert status_file.is_file()
                data = json.loads(status_file.read_text(encoding="utf-8"))
                assert "state" in data


def test_repair_corrupted_update_transaction_preserves_corrupt_file(tmp_path: Path):
    """Verify corrupted update_transaction.json is preserved as .corrupt.<ts> and reset to IDLE."""
    txn_file = tmp_path / "update_transaction.json"
    txn_file.write_text("corrupt_bytes_here", encoding="utf-8")

    with patch.object(ApplicationPaths, "get_user_data_dir", return_value=tmp_path):
        with patch.object(ApplicationPaths, "get_status_file_path", return_value=tmp_path / "runtime_status.json"):
            with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=txn_file):
                repairs = repair_state_files()

                assert len(repairs) == 1
                assert repairs[0]["action"] == "repaired"
                assert "update_transaction.json" in repairs[0]["target"]

                preserved_path = Path(repairs[0]["preserved_backup"])
                assert preserved_path.is_file()
                assert preserved_path.read_text(encoding="utf-8") == "corrupt_bytes_here"

                assert txn_file.is_file()
                data = json.loads(txn_file.read_text(encoding="utf-8"))
                assert data["state"] == "IDLE"


def test_verify_installation_integrity_basic():
    """Verify basic installation verification checks."""
    is_valid, msg, details = verify_installation_integrity()
    assert isinstance(is_valid, bool)
    assert isinstance(msg, str)
    assert "executable_path" in details
    assert "checks" in details
    assert any(c["check"] == "executable_presence" for c in details["checks"])
    assert any(c["check"] == "data_directory" for c in details["checks"])


def test_verify_installation_integrity_detects_hash_mismatch(tmp_path: Path):
    """Verify binary tampering is detected when SHA-256 does not match release manifest."""
    fake_exe = tmp_path / "fake_app.exe"
    fake_exe.write_bytes(b"TAMPERED_BINARY_CONTENT")

    manifest = ReleaseManifest(
        version="0.2.0",
        release_id="rel-020",
        release_date="2026-09-26T00:00:00Z",
        platform="windows",
        architecture="x64",
        artifacts=[
            ReleaseArtifact(
                filename="fake_app.exe",
                sha256="0000000000000000000000000000000000000000000000000000000000000000",
                size_bytes=100,
                platform="windows",
                architecture="x64",
            )
        ],
    )
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

    with patch.object(ApplicationPaths, "is_frozen", return_value=True):
        with patch.object(ApplicationPaths, "get_executable_path", return_value=fake_exe):
            with patch("platform.system", return_value="Windows"):
                is_valid, msg, details = verify_installation_integrity()
                assert is_valid is False
                assert "mismatch" in msg.lower()
                sha_check = next(c for c in details["checks"] if c["check"] == "sha256_match")
                assert sha_check["status"] == "FAIL"


def test_get_recovery_status_structure(tmp_path: Path):
    """Verify get_recovery_status returns all required metadata and subsystem assessments."""
    with patch.object(ApplicationPaths, "get_user_data_dir", return_value=tmp_path):
        status = get_recovery_status()
        assert "recovery_required" in status
        assert "system_health" in status
        assert "execution_mode" in status
        assert "data_directory" in status
        assert "state_files" in status
        assert "timestamp" in status

        state_files = status["state_files"]
        assert "runtime_status.json" in state_files
        assert "update_transaction.json" in state_files
        assert "secrets.json" in state_files
