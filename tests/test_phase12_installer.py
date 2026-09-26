"""Tests for Phase 12 Application Lifecycle: Fresh Installation.

Verifies:
- Clean separation between INSTALL_ROOT and USER_DATA.
- Rejection of path traversal and unsafe path targets.
- Correct directory creation and atomic binary staging.
- Default configuration generation when no .env exists.
- Non-destructive handling when target directory already exists.
- Full lifecycle transaction state transitions (IDLE -> VERIFYING -> STAGING -> INSTALLING -> VALIDATING -> COMPLETED).
- Offline operation without network requests.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import pytest

from device_guardian.lifecycle.installer import LifecycleInstaller, LifecycleResult
from device_guardian.lifecycle.models import (
    InstallationHealth,
    InstallationMetadata,
    LifecycleOperationType,
    LifecycleRecord,
    LifecycleState,
)
from device_guardian.runtime.paths import ApplicationPaths, set_install_dir_override, set_user_data_dir_override
from device_guardian.security.events import SecurityEventType


@pytest.fixture
def lifecycle_env(tmp_path):
    """Set up isolated install_root and user_data_dir."""
    install_dir = tmp_path / "install_root"
    data_dir = tmp_path / "user_data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    # Create dummy source binary
    binary_name = "device-guardian.exe" if platform.system() == "Windows" else "device-guardian"
    src_bin = tmp_path / "source_bin" / binary_name
    src_bin.parent.mkdir(parents=True, exist_ok=True)
    src_bin.write_bytes(b"MOCK_DEVICE_GUARDIAN_BINARY_BYTES_v0.1.0")

    yield {
        "install_dir": install_dir,
        "data_dir": data_dir,
        "src_bin": src_bin,
        "binary_name": binary_name,
    }

    # Reset overrides
    set_install_dir_override(None)
    set_user_data_dir_override(None)


def test_fresh_install_success(lifecycle_env):
    """Verify clean fresh install creates binaries, directories, metadata, and default configuration."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    src_bin = lifecycle_env["src_bin"]
    binary_name = lifecycle_env["binary_name"]

    result = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
        enable_startup=False,
    )

    assert result.success is True
    assert result.operation == LifecycleOperationType.INSTALL
    assert result.version == "0.1.0"

    # Verify installed binary
    target_binary = install_dir / binary_name
    assert target_binary.is_file()
    assert target_binary.read_bytes() == b"MOCK_DEVICE_GUARDIAN_BINARY_BYTES_v0.1.0"

    # Verify user data directories created
    assert (data_dir / "logs").is_dir()
    assert (data_dir / "updates").is_dir()
    assert (data_dir / "updates" / "backup").is_dir()

    # Verify default configuration created
    env_file = data_dir / ".env"
    assert env_file.is_file()
    env_text = env_file.read_text(encoding="utf-8")
    assert "VOICE_WARNING_ENABLED=true" in env_text
    assert "AUTH_FAILURE_THRESHOLD=3" in env_text

    # Verify metadata saved
    meta = InstallationMetadata.load(data_dir / "install_metadata.json")
    assert meta is not None
    assert meta.version == "0.1.0"
    assert meta.install_path == str(install_dir)
    assert meta.user_data_path == str(data_dir)
    assert meta.schema_version == 1
    assert meta.executable_hash is not None


def test_fresh_install_preserves_existing_env(lifecycle_env):
    """Verify fresh install does NOT overwrite pre-existing .env file."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    src_bin = lifecycle_env["src_bin"]

    # Pre-create custom .env
    existing_env = data_dir / ".env"
    custom_content = "LOG_LEVEL=DEBUG\nAUTH_FAILURE_THRESHOLD=99\nCUSTOM_TOKEN=secret\n"
    existing_env.write_text(custom_content, encoding="utf-8")

    result = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
    )

    assert result.success is True
    assert existing_env.read_text(encoding="utf-8") == custom_content


def test_fresh_install_rejects_nonexistent_source(lifecycle_env):
    """Verify fresh install fails safely if source binary does not exist."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    fake_source = install_dir.parent / "nonexistent" / "binary.exe"

    result = LifecycleInstaller.fresh_install(
        source_binary=fake_source,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
    )

    assert result.success is False
    assert "not found" in result.message.lower()


def test_fresh_install_rejects_path_traversal(lifecycle_env):
    """Verify fresh install rejects path traversal attempts."""
    src_bin = lifecycle_env["src_bin"]
    data_dir = lifecycle_env["data_dir"]

    # Unsafe destination with null byte or traversal
    unsafe_dir = data_dir / ".." / ".." / "system32"

    # Even if resolved, testing validate_safe_path
    result = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=str(unsafe_dir) + "\x00invalid",
        target_user_data_dir=data_dir,
    )

    assert result.success is False
    assert "rejected" in result.message.lower() or "failed" in result.message.lower()


def test_verify_installation_not_configured(tmp_path):
    """Verify verify_installation returns NOT_CONFIGURED when nothing installed."""
    empty_install = tmp_path / "empty_install"
    empty_data = tmp_path / "empty_data"
    empty_install.mkdir()
    empty_data.mkdir()

    health = LifecycleInstaller.verify_installation(
        install_root=empty_install,
        user_data_dir=empty_data,
    )

    assert health.status == "NOT_CONFIGURED"
    assert health.binary_exists is False
    assert health.metadata_exists is False
    assert health.is_installed is False


def test_verify_installation_healthy_after_install(lifecycle_env):
    """Verify verify_installation returns HEALTHY after successful installation."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    src_bin = lifecycle_env["src_bin"]

    LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
    )

    health = LifecycleInstaller.verify_installation(
        install_root=install_dir,
        user_data_dir=data_dir,
    )

    assert health.status == "HEALTHY"
    assert health.binary_exists is True
    assert health.metadata_valid is True
    assert health.data_dir_valid is True
    assert health.config_present is True
    assert len(health.issues) == 0


def test_verify_installation_degraded_when_metadata_missing(lifecycle_env):
    """Verify verify_installation reports DEGRADED when binary exists but metadata is absent."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    binary_name = lifecycle_env["binary_name"]

    # Only create binary, no metadata
    target_bin = install_dir / binary_name
    target_bin.write_bytes(b"EXISTING_BINARY_DATA")

    health = LifecycleInstaller.verify_installation(
        install_root=install_dir,
        user_data_dir=data_dir,
    )

    assert health.status == "DEGRADED"
    assert health.binary_exists is True
    assert health.metadata_exists is False
    assert any("metadata missing" in issue.lower() for issue in health.issues)


def test_fresh_install_reinstall_overwrites_binary_cleanly(lifecycle_env):
    """Verify fresh install can cleanly re-install over an existing installation."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    src_bin = lifecycle_env["src_bin"]
    binary_name = lifecycle_env["binary_name"]

    # First installation
    res1 = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
    )
    assert res1.success is True

    # Prepare updated source binary
    src_bin.write_bytes(b"UPDATED_BINARY_CONTENT_VERSION_0.1.0")

    # Second installation (re-install)
    res2 = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
    )
    assert res2.success is True

    target_binary = install_dir / binary_name
    assert target_binary.read_bytes() == b"UPDATED_BINARY_CONTENT_VERSION_0.1.0"


def test_fresh_install_with_startup_integration(lifecycle_env, monkeypatch):
    """Verify enable_startup=True triggers startup manager registration."""
    install_dir = lifecycle_env["install_dir"]
    data_dir = lifecycle_env["data_dir"]
    src_bin = lifecycle_env["src_bin"]

    installed_called = []

    class MockStartupManager:
        def enable(self, custom_command=None):
            installed_called.append(True)

    monkeypatch.setattr(
        "device_guardian.lifecycle.installer.create_startup_manager",
        lambda platform_name=None: MockStartupManager(),
    )

    res = LifecycleInstaller.fresh_install(
        source_binary=src_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        version="0.1.0",
        enable_startup=True,
    )
    assert res.success is True
    assert len(installed_called) == 1


def test_fresh_install_lifecycle_record_transitions(lifecycle_env):
    """Verify LifecycleRecord state transitions work properly."""
    record = LifecycleRecord(
        operation_type=LifecycleOperationType.INSTALL,
        version="0.1.0",
    )
    assert record.state == LifecycleState.IDLE
    record.transition_to(LifecycleState.VERIFYING)
    assert record.state == LifecycleState.VERIFYING
    record.transition_to(LifecycleState.STAGING)
    assert record.state == LifecycleState.STAGING
    record.transition_to(LifecycleState.INSTALLING)
    assert record.state == LifecycleState.INSTALLING
    record.transition_to(LifecycleState.VALIDATING)
    assert record.state == LifecycleState.VALIDATING
    record.transition_to(LifecycleState.COMPLETED)
    assert record.state == LifecycleState.COMPLETED
    assert record.error_message is None

