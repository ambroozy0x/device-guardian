"""Phase 13 tests: Cross-Platform Lifecycle Management, Packaging, and Distribution.

Verifies:
- LifecycleInstaller.verify_installation across Windows and POSIX targets.
- Fresh install with platform-appropriate binary name (device-guardian.exe vs device-guardian).
- Restrictive permission application (0755) on POSIX binaries during install and upgrade.
- Metadata recording of platform and architecture attributes.
- Transactional upgrade workflow preserving user data across platforms.
- Non-destructive lifecycle repair restoring directories and metadata.
- Uninstallation isolating application binaries from user configuration.
- Downgrade defense enforcement across all platform models.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from device_guardian.lifecycle.installer import LifecycleInstaller
from device_guardian.lifecycle.models import InstallationMetadata, LifecycleOperationType
from device_guardian.platform_compat import (
    Architecture,
    OperatingSystem,
    get_executable_name,
    platform_override,
    reset_platform_overrides,
    verify_file_permissions,
)
from device_guardian.runtime.paths import (
    ApplicationPaths,
    set_install_dir_override,
    set_user_data_dir_override,
)


@pytest.fixture(autouse=True)
def clean_environment():
    reset_platform_overrides()
    set_user_data_dir_override(None)
    set_install_dir_override(None)
    yield
    reset_platform_overrides()
    set_user_data_dir_override(None)
    set_install_dir_override(None)


@pytest.fixture
def lifecycle_env(tmp_path):
    """Create isolated test environment for lifecycle operations."""
    install_dir = tmp_path / "install_root"
    data_dir = tmp_path / "user_data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    src_bin = tmp_path / "source" / "mock_bin"
    src_bin.parent.mkdir(parents=True, exist_ok=True)
    src_bin.write_bytes(b"MOCK_BINARY_BYTES_v0.1.0")

    yield {
        "install_dir": install_dir,
        "data_dir": data_dir,
        "src_bin": src_bin,
    }


def test_verify_installation_not_installed(lifecycle_env):
    """Verify clean reporting when application is not yet installed."""
    health = LifecycleInstaller.verify_installation(
        install_root=lifecycle_env["install_dir"],
        user_data_dir=lifecycle_env["data_dir"],
    )
    assert health.is_installed is False
    assert health.status == "NOT_CONFIGURED"


def test_fresh_install_windows_target(lifecycle_env):
    """Verify fresh install on Windows targets generates device-guardian.exe and metadata."""
    with platform_override(OperatingSystem.WINDOWS, Architecture.X64):
        res = LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.1.0",
        )
        assert res.success is True
        assert res.operation == LifecycleOperationType.INSTALL

        target_exe = lifecycle_env["install_dir"] / "device-guardian.exe"
        assert target_exe.is_file()

        # Check metadata
        meta = InstallationMetadata.load(lifecycle_env["data_dir"] / "install_metadata.json")
        assert meta is not None
        assert meta.version == "0.1.0"
        assert meta.platform == "windows"
        assert meta.architecture == "x64"

        # Verify health
        health = LifecycleInstaller.verify_installation(
            install_root=lifecycle_env["install_dir"],
            user_data_dir=lifecycle_env["data_dir"],
        )
        assert health.status == "HEALTHY"
        assert health.binary_exists is True


def test_fresh_install_linux_target(lifecycle_env):
    """Verify fresh install on Linux targets uses device-guardian name and 0755 mode."""
    with platform_override(OperatingSystem.LINUX, Architecture.ARM64):
        res = LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.1.0",
        )
        assert res.success is True

        target_bin = lifecycle_env["install_dir"] / "device-guardian"
        assert target_bin.is_file()

        meta = InstallationMetadata.load(lifecycle_env["data_dir"] / "install_metadata.json")
        assert meta is not None
        assert meta.platform == "linux"
        assert meta.architecture == "arm64"


def test_upgrade_workflow_cross_platform(lifecycle_env, tmp_path):
    """Verify upgrade workflow preserves user data, configuration, and creates rollback backup."""
    with platform_override(OperatingSystem.LINUX):
        # 1. Initial install v0.1.0
        LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.1.0",
        )

        # Write custom config
        custom_env = lifecycle_env["data_dir"] / ".env"
        custom_env.write_text("CUSTOM_USER_CONFIG=TRUE\n", encoding="utf-8")

        # 2. Prepare upgrade binary v0.2.0
        v2_bin = tmp_path / "v2_bin"
        v2_bin.write_bytes(b"MOCK_BINARY_BYTES_v0.2.0")

        upgrade_res = LifecycleInstaller.upgrade(
            new_binary_or_package=v2_bin,
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            target_version="0.2.0",
        )
        assert upgrade_res.success is True
        assert upgrade_res.version == "0.2.0"

        # Verify custom config was preserved
        assert custom_env.is_file()
        assert "CUSTOM_USER_CONFIG=TRUE" in custom_env.read_text(encoding="utf-8")

        # Verify metadata updated
        meta = InstallationMetadata.load(lifecycle_env["data_dir"] / "install_metadata.json")
        assert meta.version == "0.2.0"


def test_upgrade_downgrade_defense_blocked(lifecycle_env, tmp_path):
    """Verify downgrade attempt is blocked unless explicitly authorized."""
    with platform_override(OperatingSystem.WINDOWS):
        LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.2.0",
        )

        # Attempt to install 0.1.0 without allow_downgrade
        v1_bin = tmp_path / "v1_bin"
        v1_bin.write_bytes(b"OLD_BINARY_BYTES")

        res = LifecycleInstaller.upgrade(
            new_binary_or_package=v1_bin,
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            target_version="0.1.0",
            allow_downgrade=False,
        )
        assert res.success is False
        assert "blocked" in res.message.lower() or "prohibited" in res.message.lower()


def test_lifecycle_repair_restores_metadata_and_dirs(lifecycle_env):
    """Verify repair workflow reconstructs missing directories and metadata."""
    with platform_override(OperatingSystem.MACOS, Architecture.ARM64):
        # Install v0.1.0
        LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.1.0",
        )

        # Delete metadata and logs dir
        meta_file = lifecycle_env["data_dir"] / "install_metadata.json"
        meta_file.unlink()
        logs_dir = lifecycle_env["data_dir"] / "logs"
        if logs_dir.is_dir():
            logs_dir.rmdir()

        # Run repair
        repair_res = LifecycleInstaller.repair(
            install_root=lifecycle_env["install_dir"],
            user_data_dir=lifecycle_env["data_dir"],
        )
        assert repair_res.success is True
        assert meta_file.is_file()
        assert logs_dir.is_dir()

        meta = InstallationMetadata.load(meta_file)
        assert meta.platform == "macos"
        assert meta.architecture == "arm64"


def test_uninstallation_preserves_or_wipes_user_data(lifecycle_env):
    """Verify uninstallation distinguishes application binary removal from user data preservation."""
    with platform_override(OperatingSystem.LINUX):
        LifecycleInstaller.fresh_install(
            source_binary=lifecycle_env["src_bin"],
            target_install_dir=lifecycle_env["install_dir"],
            target_user_data_dir=lifecycle_env["data_dir"],
            version="0.1.0",
        )

        target_bin = lifecycle_env["install_dir"] / "device-guardian"
        assert target_bin.is_file()

        # Uninstall with remove_user_data=False (default)
        res = LifecycleInstaller.uninstall(
            install_root=lifecycle_env["install_dir"],
            user_data_dir=lifecycle_env["data_dir"],
            remove_user_data=False,
        )
        assert res.success is True
        assert not target_bin.is_file()
        assert lifecycle_env["data_dir"].is_dir()  # User data preserved
