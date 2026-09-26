"""Tests for Phase 12 Application Lifecycle: Safe Transactional Upgrades.

Verifies:
- Atomic binary swap and backup-on-upgrade.
- Downgrade protection (blocked without flag, allowed with flag).
- Absolute preservation of user data (.env, SecretStore, logs, audit trails).
- Automatic rollback if the upgraded binary fails validation.
- Concurrency and lock conflict protection via update.lock.
- Runtime coordination via guardian.control / guardian.lock without force-killing.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import pytest

from device_guardian.lifecycle.installer import LifecycleInstaller, LifecycleResult
from device_guardian.lifecycle.models import (
    InstallationMetadata,
    LifecycleOperationType,
    LifecycleRecord,
    LifecycleState,
)
from device_guardian.runtime.paths import ApplicationPaths, set_install_dir_override, set_user_data_dir_override
from device_guardian.updates.installer import _UpdateLockContext


@pytest.fixture
def installed_env(tmp_path):
    """Set up an existing installed application environment at v0.1.0."""
    install_dir = tmp_path / "installed_app"
    data_dir = tmp_path / "user_data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    binary_name = "device-guardian.exe" if platform.system() == "Windows" else "device-guardian"
    installed_binary = install_dir / binary_name
    installed_binary.write_bytes(b"INITIAL_APPLICATION_BINARY_v0.1.0")

    # Metadata
    meta = InstallationMetadata(
        version="0.1.0",
        install_path=str(install_dir),
        user_data_path=str(data_dir),
        schema_version=1,
    )
    meta.save(data_dir / "install_metadata.json")

    # User data: config, secrets, logs
    env_file = data_dir / ".env"
    env_file.write_text("AUTH_FAILURE_THRESHOLD=5\nCUSTOM_USER_SETTING=present\n", encoding="utf-8")

    secret_file = data_dir / "secrets.dat"
    secret_file.write_bytes(b"DPAPI_ENCRYPTED_OR_MOCK_SECRETS_DATA")

    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    audit_log = logs_dir / "audit.log"
    audit_log.write_text("EXISTING_AUDIT_LOG_LINE_1\n", encoding="utf-8")

    # Candidate new binary
    new_bin = tmp_path / "new_bin" / binary_name
    new_bin.parent.mkdir(parents=True, exist_ok=True)
    new_bin.write_bytes(b"UPGRADED_APPLICATION_BINARY_v0.2.0")

    yield {
        "install_dir": install_dir,
        "data_dir": data_dir,
        "installed_binary": installed_binary,
        "new_bin": new_bin,
        "binary_name": binary_name,
        "env_file": env_file,
        "secret_file": secret_file,
        "audit_log": audit_log,
    }

    set_install_dir_override(None)
    set_user_data_dir_override(None)


def test_upgrade_success_and_preservation(installed_env):
    """Verify upgrade successfully updates binary, creates backup, and preserves all user state."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]
    installed_binary = installed_env["installed_binary"]
    env_file = installed_env["env_file"]
    secret_file = installed_env["secret_file"]
    audit_log = installed_env["audit_log"]

    res = LifecycleInstaller.upgrade(
        new_binary_or_package=new_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.2.0",
        allow_downgrade=False,
    )

    assert res.success is True
    assert res.operation == LifecycleOperationType.UPGRADE
    assert res.version == "0.2.0"

    # 1. Binary is upgraded
    assert installed_binary.read_bytes() == b"UPGRADED_APPLICATION_BINARY_v0.2.0"

    # 2. Metadata is updated
    meta = InstallationMetadata.load(data_dir / "install_metadata.json")
    assert meta is not None
    assert meta.version == "0.2.0"
    assert meta.last_upgraded_at is not None

    # 3. User data is 100% preserved
    assert "CUSTOM_USER_SETTING=present" in env_file.read_text(encoding="utf-8")
    assert secret_file.read_bytes() == b"DPAPI_ENCRYPTED_OR_MOCK_SECRETS_DATA"
    assert "EXISTING_AUDIT_LOG_LINE_1" in audit_log.read_text(encoding="utf-8")

    # 4. Backup exists
    assert res.backup_path is not None
    assert Path(res.backup_path).is_file()
    assert Path(res.backup_path).read_bytes() == b"INITIAL_APPLICATION_BINARY_v0.1.0"


def test_upgrade_downgrade_defense_blocked(installed_env):
    """Verify downgrade without --allow-downgrade is blocked."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]
    installed_binary = installed_env["installed_binary"]

    # First update metadata to 0.2.0
    meta = InstallationMetadata(version="0.2.0", install_path=str(install_dir), user_data_path=str(data_dir))
    meta.save(data_dir / "install_metadata.json")

    # Attempt downgrade to 0.1.0 without flag
    res = LifecycleInstaller.upgrade(
        new_binary_or_package=new_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.1.0",
        allow_downgrade=False,
    )

    assert res.success is False
    assert "downgrade" in res.message.lower()
    # Installed binary remains unchanged
    assert installed_binary.read_bytes() == b"INITIAL_APPLICATION_BINARY_v0.1.0"


def test_upgrade_downgrade_allowed_with_flag(installed_env):
    """Verify downgrade succeeds when allow_downgrade=True."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]
    installed_binary = installed_env["installed_binary"]

    meta = InstallationMetadata(version="0.2.0", install_path=str(install_dir), user_data_path=str(data_dir))
    meta.save(data_dir / "install_metadata.json")

    res = LifecycleInstaller.upgrade(
        new_binary_or_package=new_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.1.0",
        allow_downgrade=True,
    )

    assert res.success is True
    assert res.version == "0.1.0"


def test_upgrade_same_version_reinstall(installed_env):
    """Verify upgrading to the same version (0.1.0 -> 0.1.0) is allowed."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]

    res = LifecycleInstaller.upgrade(
        new_binary_or_package=new_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.1.0",
        allow_downgrade=False,
    )

    assert res.success is True
    assert res.version == "0.1.0"


def test_upgrade_rollback_on_empty_binary(installed_env):
    """Verify automatic rollback if the new binary is empty (0 bytes)."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    installed_binary = installed_env["installed_binary"]

    # Create an empty new binary
    empty_bin = install_dir.parent / "empty_binary.exe"
    empty_bin.write_bytes(b"")

    res = LifecycleInstaller.upgrade(
        new_binary_or_package=empty_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.2.0",
    )

    assert res.success is False
    assert "restored previous version" in res.message.lower() or "validation failed" in res.message.lower()

    # The installed binary must have been rolled back to original content
    assert installed_binary.is_file()
    assert installed_binary.read_bytes() == b"INITIAL_APPLICATION_BINARY_v0.1.0"


def test_upgrade_lock_conflict(installed_env):
    """Verify upgrade fails cleanly when update.lock is held."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]

    lock_file = data_dir / "updates" / "update.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    # Acquire lock in test process
    lock_ctx = _UpdateLockContext(lock_file)
    lock_ctx.__enter__()

    try:
        res = LifecycleInstaller.upgrade(
            new_binary_or_package=new_bin,
            target_install_dir=install_dir,
            target_user_data_dir=data_dir,
            target_version="0.2.0",
        )
        assert res.success is False
        assert "lock conflict" in res.message.lower() or "could not acquire update lock" in res.message.lower()
    finally:
        lock_ctx.__exit__(None, None, None)


def test_upgrade_graceful_runtime_stop_coordination(installed_env):
    """Verify upgrade signals STOP via guardian.control when guardian.lock exists."""
    install_dir = installed_env["install_dir"]
    data_dir = installed_env["data_dir"]
    new_bin = installed_env["new_bin"]

    # Simulate running runtime
    lock_file = data_dir / "guardian.lock"
    lock_file.write_text(f"{os.getpid()}", encoding="utf-8")

    # In a background thread or shortly after start, simulate the runtime stopping cleanly
    import threading
    import time

    def simulate_shutdown():
        time.sleep(0.3)
        control_file = data_dir / "guardian.control"
        if control_file.is_file() and control_file.read_text(encoding="utf-8").strip() == "STOP":
            try:
                lock_file.unlink()
            except OSError:
                pass

    t = threading.Thread(target=simulate_shutdown)
    t.start()

    res = LifecycleInstaller.upgrade(
        new_binary_or_package=new_bin,
        target_install_dir=install_dir,
        target_user_data_dir=data_dir,
        target_version="0.2.0",
    )

    t.join(timeout=2.0)
    assert res.success is True
    assert res.version == "0.2.0"
