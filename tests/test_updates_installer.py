"""Tests for Phase 7 UpdateInstaller deployment and rollback engine."""

from pathlib import Path
import pytest

from device_guardian.updates.installer import InstallationResult, UpdateInstaller
from device_guardian.updates.transaction import TransactionState, UpdateTransaction
from tests.test_updates_verifier import create_mock_update_package


def test_install_update_and_rollback(tmp_path: Path):
    """Test full cycle: install update, verify backup created, and perform rollback."""
    # Create target mock executable
    target_dir = tmp_path / "installed_app"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_exe = target_dir / "device-guardian.exe"
    target_exe.write_bytes(b"INITIAL_VERSION_0_1_0_BINARY")

    # Create mock update package for v1.1.0
    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="1.1.0")

    # Perform install
    install_res = UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )

    assert install_res.success is True
    assert install_res.installed_version == "1.1.0"
    assert target_exe.read_bytes() == b"GENUINE_DEVICE_GUARDIAN_NEW_RELEASE_BINARY"
    assert install_res.backup_path is not None
    assert install_res.backup_path.is_file()
    assert install_res.backup_path.read_bytes() == b"INITIAL_VERSION_0_1_0_BINARY"

    # Now perform rollback
    rollback_res = UpdateInstaller.rollback(target_executable_override=target_exe)
    assert rollback_res.success is True
    assert target_exe.read_bytes() == b"INITIAL_VERSION_0_1_0_BINARY"


def test_install_update_rejected_package(tmp_path: Path):
    """Verify rejected update does not replace the target executable."""
    target_dir = tmp_path / "installed_app"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_exe = target_dir / "device-guardian.exe"
    target_exe.write_bytes(b"EXISTING_IMMUTABLE_BINARY")

    # Package with corrupted hash
    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    zip_pkg, pub_key = create_mock_update_package(pkg_dir, version="1.1.0", corrupt_hash=True)

    install_res = UpdateInstaller.install_update(
        package_path=zip_pkg,
        public_key=pub_key,
        target_executable_override=target_exe,
    )

    assert install_res.success is False
    assert target_exe.read_bytes() == b"EXISTING_IMMUTABLE_BINARY"
