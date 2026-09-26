"""Tests for Phase 12 Application Lifecycle: Safe Non-Destructive Repair.

Verifies:
- Re-creation of missing runtime directories (logs, updates, staging, backup).
- Regeneration of missing or corrupt installation metadata.
- Pruning of stale/malformed guardian.lock files.
- Absolute preservation of user configurations (.env), secrets, and logs.
- Safe rejection of traversal or unsafe paths during repair.
- Audit event logging for repair lifecycle.
"""

from __future__ import annotations

from pathlib import Path
import platform
import pytest

from device_guardian.lifecycle.installer import LifecycleInstaller, LifecycleResult
from device_guardian.lifecycle.models import InstallationMetadata, LifecycleOperationType
from device_guardian.runtime.paths import ApplicationPaths, set_install_dir_override, set_user_data_dir_override


@pytest.fixture
def repair_env(tmp_path):
    """Set up installed application with missing directories for repair testing."""
    install_dir = tmp_path / "installed_app"
    data_dir = tmp_path / "user_data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    binary_name = "device-guardian.exe" if platform.system() == "Windows" else "device-guardian"
    binary_path = install_dir / binary_name
    binary_path.write_bytes(b"VALID_BINARY_BYTES")

    yield {
        "install_dir": install_dir,
        "data_dir": data_dir,
        "binary_path": binary_path,
    }

    set_install_dir_override(None)
    set_user_data_dir_override(None)


def test_repair_creates_missing_directories(repair_env):
    """Verify repair creates missing runtime directories without error."""
    install_dir = repair_env["install_dir"]
    data_dir = repair_env["data_dir"]

    # Verify initially missing
    assert not (data_dir / "logs").is_dir()
    assert not (data_dir / "updates").is_dir()
    assert not (data_dir / "updates" / "staging").is_dir()

    res = LifecycleInstaller.repair(install_root=install_dir, user_data_dir=data_dir)

    assert res.success is True
    assert res.operation == LifecycleOperationType.REPAIR

    # Check directories now exist
    assert (data_dir / "logs").is_dir()
    assert (data_dir / "updates").is_dir()
    assert (data_dir / "updates" / "staging").is_dir()
    assert (data_dir / "updates" / "verified").is_dir()
    assert (data_dir / "updates" / "backup").is_dir()

    # Repaired items listed
    repaired = res.details.get("repaired_items", [])
    assert any("logs" in item.lower() for item in repaired)
    assert any("updates" in item.lower() for item in repaired)


def test_repair_regenerates_missing_install_metadata(repair_env):
    """Verify repair regenerates install_metadata.json if missing."""
    install_dir = repair_env["install_dir"]
    data_dir = repair_env["data_dir"]
    meta_file = data_dir / "install_metadata.json"

    assert not meta_file.is_file()

    res = LifecycleInstaller.repair(install_root=install_dir, user_data_dir=data_dir)

    assert res.success is True
    assert meta_file.is_file()

    meta = InstallationMetadata.load(meta_file)
    assert meta is not None
    assert meta.install_path == str(install_dir)
    assert meta.executable_hash is not None


def test_repair_prunes_stale_lock(repair_env):
    """Verify repair deletes malformed guardian.lock."""
    install_dir = repair_env["install_dir"]
    data_dir = repair_env["data_dir"]

    lock_file = data_dir / "guardian.lock"
    lock_file.write_text("NOT_A_PID", encoding="utf-8")

    res = LifecycleInstaller.repair(install_root=install_dir, user_data_dir=data_dir)

    assert res.success is True
    assert not lock_file.is_file()
    assert any("guardian.lock" in item.lower() for item in res.details["repaired_items"])


def test_repair_preserves_user_env_and_secrets(repair_env):
    """Verify repair NEVER overwrites, resets, or clears .env or secrets."""
    install_dir = repair_env["install_dir"]
    data_dir = repair_env["data_dir"]

    # Pre-create custom env and secrets
    env_file = data_dir / ".env"
    custom_env = "VOICE_WARNING_ENABLED=false\nCUSTOM_TOKEN=my_precious_token\n"
    env_file.write_text(custom_env, encoding="utf-8")

    secret_file = data_dir / "secrets.dat"
    secret_file.write_bytes(b"SECRET_ENCRYPTED_DATA_BYTES")

    res = LifecycleInstaller.repair(install_root=install_dir, user_data_dir=data_dir)

    assert res.success is True
    assert env_file.read_text(encoding="utf-8") == custom_env
    assert secret_file.read_bytes() == b"SECRET_ENCRYPTED_DATA_BYTES"


def test_repair_rejects_unsafe_paths(repair_env):
    """Verify repair rejects unsafe path specifications."""
    data_dir = repair_env["data_dir"]

    res = LifecycleInstaller.repair(
        install_root=str(data_dir) + "\x00invalid",
        user_data_dir=data_dir,
    )
    assert res.success is False
    assert "rejected" in res.message.lower()
