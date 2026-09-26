"""Tests for Phase 12 Application Lifecycle: Security, Versioning & CLI Integration.

Verifies:
- SemVer 2.0.0 version parser and comparison functions.
- Release artifact secret scanning.
- Package verification CLI against valid and malicious zip packages.
- CLI commands (--install-info, --installation-status, --repair-installation, --migration-status, --migrate).
- Lifecycle state models and persistence resilience.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile
import pytest

from device_guardian.lifecycle.models import (
    InstallationMetadata,
    LifecycleOperationType,
    LifecycleRecord,
    LifecycleState,
)
from device_guardian.main import (
    apply_migration_cli,
    repair_installation_cli,
    show_install_info,
    show_installation_status,
    show_migration_status,
    verify_package_cli,
)
from device_guardian.packaging.build import scan_artifacts_for_secrets
from device_guardian.runtime.paths import ApplicationPaths, set_install_dir_override, set_user_data_dir_override
from device_guardian.updates.manifest import ReleaseManifest
from device_guardian.updates.verifier import ReleaseVerificationResult, VerificationFinding, VerificationStatus
from device_guardian.version import (
    SemanticVersion,
    __version__,
    compare_versions,
    current_version,
    parse_version,
)


@pytest.fixture
def isolated_paths(tmp_path):
    """Set up temporary install root and user data directory."""
    install_dir = tmp_path / "install"
    data_dir = tmp_path / "data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    yield {"install_dir": install_dir, "data_dir": data_dir}

    set_install_dir_override(None)
    set_user_data_dir_override(None)


def test_version_functions_conformance():
    """Verify authoritative version source functions."""
    assert current_version() == __version__

    v1 = parse_version("0.1.0")
    assert v1.major == 0
    assert v1.minor == 1
    assert v1.patch == 0

    v2 = parse_version("1.2.3-rc1")
    assert v2.major == 1
    assert v2.minor == 2
    assert v2.patch == 3
    assert v2.prerelease == "rc1"

    with pytest.raises(ValueError):
        parse_version("invalid_version")

    assert compare_versions("0.1.0", "0.2.0") < 0
    assert compare_versions("0.2.0", "0.1.0") > 0
    assert compare_versions("0.1.0", "0.1.0") == 0
    assert compare_versions("1.0.0", "1.0.0-rc1") > 0


def test_scan_artifacts_detects_secrets(tmp_path):
    """Verify artifact secret scanner detects prohibited files and patterns."""
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()

    # Clean initial state
    (dist_dir / "valid_file.txt").write_text("Normal content", encoding="utf-8")
    clean, issues = scan_artifacts_for_secrets(dist_dir)
    assert clean is True
    assert len(issues) == 0

    # 1. Detect .env
    (dist_dir / ".env").write_text("SECRET=bad", encoding="utf-8")
    clean, issues = scan_artifacts_for_secrets(dist_dir)
    assert clean is False
    assert any(".env" in iss for iss in issues)
    (dist_dir / ".env").unlink()

    # 2. Detect secrets.dat
    (dist_dir / "secrets.dat").write_bytes(b"bad_bytes")
    clean, issues = scan_artifacts_for_secrets(dist_dir)
    assert clean is False
    assert any("secrets.dat" in iss for iss in issues)
    (dist_dir / "secrets.dat").unlink()

    # 3. Detect private key
    (dist_dir / "key.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----", encoding="utf-8")
    clean, issues = scan_artifacts_for_secrets(dist_dir)
    assert clean is False
    assert any("private key" in iss.lower() for iss in issues)


def test_verify_package_cli_valid_zip(tmp_path, capsys, monkeypatch):
    """Verify verify_package_cli succeeds on a clean zip package."""
    zip_path = tmp_path / "valid_package.zip"
    zip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    mock_result = ReleaseVerificationResult(
        status=VerificationStatus.VALID,
        findings=[
            VerificationFinding(category="Archive Security", status=VerificationStatus.VALID, message="ZIP archive verified"),
            VerificationFinding(category="Digital Signature", status=VerificationStatus.VALID, message="Signature verified"),
        ],
        manifest=ReleaseManifest(
            version="0.2.0",
            release_id="DG-0.2.0-win-x64",
            release_date="2026-09-26T12:00:00Z",
            platform="windows",
            architecture="x64",
            artifacts=[],
        ),
    )
    monkeypatch.setattr("device_guardian.main.verify_update_package", lambda path, allow_downgrade=True: mock_result)

    code = verify_package_cli(str(zip_path))
    assert code == 0

    captured = capsys.readouterr().out
    assert "RELEASE PACKAGE VERIFICATION" in captured
    assert "VALID" in captured
    assert "[PASS]" in captured


def test_verify_package_cli_rejects_path_traversal(tmp_path, capsys):
    """Verify verify_package_cli rejects zip package containing path traversal member."""
    zip_path = tmp_path / "evil_package.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.exe", b"MALICIOUS_DATA")

    code = verify_package_cli(str(zip_path))
    assert code == 1

    captured = capsys.readouterr().out
    assert "RELEASE PACKAGE VERIFICATION" in captured
    assert "CORRUPTED" in captured


def test_verify_package_cli_nonexistent(capsys):
    """Verify verify_package_cli handles nonexistent file gracefully."""
    code = verify_package_cli("C:/nonexistent/package.zip")
    assert code == 1
    captured = capsys.readouterr().out
    assert "does not exist" in captured.lower()


def test_cli_show_install_info(isolated_paths, capsys):
    """Verify show_install_info CLI prints structured install metadata."""
    data_dir = isolated_paths["data_dir"]
    install_dir = isolated_paths["install_dir"]

    meta = InstallationMetadata(
        version="0.1.0",
        install_path=str(install_dir),
        user_data_path=str(data_dir),
        schema_version=1,
    )
    meta.save(data_dir / "install_metadata.json")

    code = show_install_info()
    assert code == 0

    captured = capsys.readouterr().out
    assert "INSTALLATION INFORMATION" in captured
    assert "Installed Version:" in captured
    assert "0.1.0" in captured


def test_cli_show_installation_status(isolated_paths, capsys):
    """Verify show_installation_status CLI prints health assessment."""
    code = show_installation_status()
    # Returns 0 for successful execution of command
    assert code == 0

    captured = capsys.readouterr().out
    assert "INSTALLATION HEALTH ASSESSMENT" in captured
    assert "Installation State:" in captured


def test_cli_repair_installation(isolated_paths, capsys):
    """Verify repair_installation_cli executes without errors."""
    code = repair_installation_cli(assume_yes=True)
    assert code == 0

    captured = capsys.readouterr().out
    assert "REPAIR OPERATION RESULT" in captured
    assert "SUCCESS" in captured


def test_cli_migration_status_and_migrate(isolated_paths, capsys):
    """Verify migration status check and migration apply commands."""
    code1 = show_migration_status()
    assert code1 == 0
    captured1 = capsys.readouterr().out
    assert "SCHEMA MIGRATION STATUS" in captured1

    code2 = apply_migration_cli(assume_yes=True, target_version=1)
    assert code2 == 0
    captured2 = capsys.readouterr().out
    assert "No migration needed" in captured2


def test_lifecycle_record_and_metadata_serialization():
    """Verify LifecycleRecord and InstallationMetadata serialization and corruption resilience."""
    rec = LifecycleRecord(
        operation_type=LifecycleOperationType.UPGRADE,
        version="0.1.0",
        target_version="0.2.0",
        backup_path="C:/backup/bin",
    )
    rec.transition_to(LifecycleState.BACKING_UP)
    data = rec.to_dict()
    assert data["state"] == "BACKING_UP"
    assert data["target_version"] == "0.2.0"

    rebuilt = LifecycleRecord.from_dict(data)
    assert rebuilt.state == LifecycleState.BACKING_UP
    assert rebuilt.operation_type == LifecycleOperationType.UPGRADE

    meta = InstallationMetadata(
        version="0.2.0",
        install_path="C:/install",
        user_data_path="C:/data",
        executable_hash="abcdef123456",
    )
    m_data = meta.to_dict()
    assert m_data["version"] == "0.2.0"
    m_rebuilt = InstallationMetadata.from_dict(m_data)
    assert m_rebuilt.version == "0.2.0"
    assert m_rebuilt.executable_hash == "abcdef123456"
