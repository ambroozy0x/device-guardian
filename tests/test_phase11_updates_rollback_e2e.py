"""Phase 11 End-to-End Integration Tests: Updates, Manifest Verification, Rollback, and Archive Hardening (Workstreams 15, 16, 17, 18, 19, 44)."""

from pathlib import Path
import zipfile
import pytest

from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.updates.archive import ArchiveSecurityError, SafeZipExtractor
from device_guardian.updates.installer import InstallationResult, UpdateInstaller
from device_guardian.updates.transaction import (
    TransactionState,
    UpdateTransaction,
    check_and_recover_interrupted_transaction,
)
from device_guardian.updates.verifier import VerificationStatus, verify_update_package
from tests.test_updates_verifier import create_mock_update_package


@pytest.fixture
def update_env(tmp_path):
    ApplicationPaths.set_data_dir_override(tmp_path)
    return tmp_path


def test_full_update_lifecycle_e2e(update_env):
    """Verify complete end-to-end update installation workflow."""
    tmp_path = update_env
    target_dir = tmp_path / "installed_app"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_exe = target_dir / "device-guardian.exe"
    target_exe.write_bytes(b"INITIAL_RELEASE_BINARY_v0_1_0")

    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="0.2.0")

    # Install update
    result = UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )

    assert result.success is True
    assert result.installed_version == "0.2.0"
    assert target_exe.read_bytes() == b"GENUINE_DEVICE_GUARDIAN_NEW_RELEASE_BINARY"
    assert result.backup_path is not None
    assert result.backup_path.is_file()
    assert result.backup_path.read_bytes() == b"INITIAL_RELEASE_BINARY_v0_1_0"


def test_update_rollback_restoration_e2e(update_env):
    """Verify rollback restores previous binary perfectly and cleanly."""
    tmp_path = update_env
    target_dir = tmp_path / "installed_app"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_exe = target_dir / "device-guardian.exe"
    target_exe.write_bytes(b"INITIAL_RELEASE_BINARY_v0_1_0")

    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="0.2.0")

    # Install then rollback
    UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )
    assert target_exe.read_bytes() == b"GENUINE_DEVICE_GUARDIAN_NEW_RELEASE_BINARY"

    rollback_res = UpdateInstaller.rollback(target_executable_override=target_exe)
    assert rollback_res.success is True
    assert target_exe.read_bytes() == b"INITIAL_RELEASE_BINARY_v0_1_0"


def test_update_rejection_bad_hash_e2e(update_env):
    """Verify package with tampered SHA-256 is rejected without touching target binary."""
    tmp_path = update_env
    target_exe = tmp_path / "device-guardian.exe"
    target_exe.write_bytes(b"IMMUTABLE_ORIGINAL_BINARY")

    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="0.2.0", corrupt_hash=True)

    result = UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )

    assert result.success is False
    assert "verification failed" in (result.message or "").lower() or "integrity" in (result.message or "").lower()
    # Target binary must not have been modified
    assert target_exe.read_bytes() == b"IMMUTABLE_ORIGINAL_BINARY"


def test_update_rejection_bad_signature_e2e(update_env):
    """Verify package with invalid Ed25519 signature is rejected at verification gate."""
    tmp_path = update_env
    target_exe = tmp_path / "device-guardian.exe"
    target_exe.write_bytes(b"IMMUTABLE_ORIGINAL_BINARY")

    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="0.2.0", corrupt_signature=True)

    result = UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )

    assert result.success is False
    assert target_exe.read_bytes() == b"IMMUTABLE_ORIGINAL_BINARY"


def test_interrupted_update_recovery_fsm_e2e(update_env):
    """Verify crash during INSTALLING is detected at startup and flagged for rollback."""
    txn = UpdateTransaction(
        state=TransactionState.INSTALLING,
        target_version="0.3.0",
        previous_version="0.2.0",
    )
    txn.save()

    recovery = check_and_recover_interrupted_transaction()
    assert recovery["status"] == "interrupted"
    assert recovery["action"] == "rollback_required"

    current = UpdateTransaction.load()
    assert current.state == TransactionState.ROLLBACK_REQUIRED


def test_safezip_path_traversal_rejection_e2e(update_env):
    """Verify SafeZipExtractor rejects directory traversal entries."""
    tmp_path = update_env
    zip_file = tmp_path / "traversal.zip"
    dest_dir = tmp_path / "dest"

    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("../../evil.exe", b"EVIL")

    with pytest.raises(ArchiveSecurityError):
        SafeZipExtractor.extract(zip_file, dest_dir)


def test_safezip_prohibited_extension_rejection_e2e(update_env):
    """Verify SafeZipExtractor rejects archives containing prohibited executable scripts."""
    tmp_path = update_env
    zip_file = tmp_path / "script.zip"
    dest_dir = tmp_path / "dest"

    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("payload.cmd", b"@echo off\necho pwned")

    with pytest.raises(ArchiveSecurityError):
        SafeZipExtractor.extract(zip_file, dest_dir)


def test_safezip_size_limit_rejection_e2e(update_env):
    """Verify SafeZipExtractor blocks zip bombs or files claiming excessive size."""
    tmp_path = update_env
    zip_file = tmp_path / "bomb.zip"
    dest_dir = tmp_path / "dest"

    with zipfile.ZipFile(zip_file, "w") as zf:
        # Create an entry claiming size larger than limit
        zinfo = zipfile.ZipInfo("huge_file.exe")
        zinfo.file_size = 500000000
        zf.writestr(zinfo, b"x" * 1024)

    with pytest.raises(ArchiveSecurityError):
        SafeZipExtractor.extract(zip_file, dest_dir, max_single_file_size_bytes=1000)
