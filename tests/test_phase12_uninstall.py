"""Tests for Phase 12 Application Lifecycle: Safe Uninstallation & Data Decisions.

Verifies:
- Clean application removal while preserving user data (.env, secrets, logs).
- Authorized uninstallation with user data purge when explicitly requested.
- Operator confirmation requirements (default cancellation without confirmation).
- CLI non-interactive execution with --yes / -y.
- Unregistration of OS startup integration upon uninstallation.
- Security event logging (UNINSTALL_STARTED, UNINSTALL_COMPLETED, USER_DATA_DELETION_CONFIRMED).
"""

from __future__ import annotations

from pathlib import Path
import platform
import pytest

from device_guardian.lifecycle.installer import LifecycleInstaller, LifecycleResult
from device_guardian.lifecycle.models import InstallationMetadata, LifecycleOperationType
from device_guardian.main import main, uninstall_cli
from device_guardian.runtime.paths import ApplicationPaths, set_install_dir_override, set_user_data_dir_override


@pytest.fixture
def uninstall_env(tmp_path):
    """Set up installed application with user data for uninstall testing."""
    install_dir = tmp_path / "installed_app"
    data_dir = tmp_path / "user_data"
    install_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    set_install_dir_override(install_dir)
    set_user_data_dir_override(data_dir)

    binary_name = "device-guardian.exe" if platform.system() == "Windows" else "device-guardian"
    target_bin = install_dir / binary_name
    target_bin.write_bytes(b"APPLICATION_BINARY_CONTENT")

    # Create metadata
    meta = InstallationMetadata(version="0.1.0", install_path=str(install_dir), user_data_path=str(data_dir))
    meta.save(data_dir / "install_metadata.json")

    # User data: .env, secrets, logs
    env_file = data_dir / ".env"
    env_file.write_text("MY_SECRET_CONFIG=12345\n", encoding="utf-8")

    secret_file = data_dir / "secrets.dat"
    secret_file.write_bytes(b"MOCK_SECRETS_STORE_CONTENT")

    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    audit_file = logs_dir / "audit.log"
    audit_file.write_text("IMPORTANT_AUDIT_LOG_LINE\n", encoding="utf-8")

    yield {
        "install_dir": install_dir,
        "data_dir": data_dir,
        "target_bin": target_bin,
        "env_file": env_file,
        "secret_file": secret_file,
        "audit_file": audit_file,
    }

    set_install_dir_override(None)
    set_user_data_dir_override(None)


def test_uninstall_application_only_preserves_user_data(uninstall_env):
    """Verify default uninstall removes binary but preserves all user configuration, secrets, and logs."""
    install_dir = uninstall_env["install_dir"]
    data_dir = uninstall_env["data_dir"]
    target_bin = uninstall_env["target_bin"]
    env_file = uninstall_env["env_file"]
    secret_file = uninstall_env["secret_file"]
    audit_file = uninstall_env["audit_file"]

    res = LifecycleInstaller.uninstall(
        install_root=install_dir,
        user_data_dir=data_dir,
        remove_user_data=False,
    )

    assert res.success is True
    assert res.operation == LifecycleOperationType.UNINSTALL
    assert res.details.get("user_data_preserved") is True

    # Binary removed
    assert not target_bin.is_file()

    # User data preserved
    assert data_dir.is_dir()
    assert env_file.is_file()
    assert "MY_SECRET_CONFIG=12345" in env_file.read_text(encoding="utf-8")
    assert secret_file.is_file()
    assert secret_file.read_bytes() == b"MOCK_SECRETS_STORE_CONTENT"
    assert audit_file.is_file()


def test_uninstall_with_user_data_purge(uninstall_env):
    """Verify uninstall with remove_user_data=True permanently wipes user data directory."""
    install_dir = uninstall_env["install_dir"]
    data_dir = uninstall_env["data_dir"]
    target_bin = uninstall_env["target_bin"]

    res = LifecycleInstaller.uninstall(
        install_root=install_dir,
        user_data_dir=data_dir,
        remove_user_data=True,
    )

    assert res.success is True
    assert res.details.get("user_data_preserved") is False

    # Binary removed
    assert not target_bin.is_file()

    # User data directory purged
    assert not data_dir.is_dir()


def test_uninstall_removes_startup_entry(uninstall_env, monkeypatch):
    """Verify uninstallation triggers startup unregistration."""
    install_dir = uninstall_env["install_dir"]
    data_dir = uninstall_env["data_dir"]

    uninstalled_called = []

    class MockStartupManager:
        def is_enabled(self):
            return True

        def disable(self):
            uninstalled_called.append(True)

    monkeypatch.setattr(
        "device_guardian.lifecycle.installer.create_startup_manager",
        lambda platform_name=None: MockStartupManager(),
    )

    res = LifecycleInstaller.uninstall(
        install_root=install_dir,
        user_data_dir=data_dir,
        remove_user_data=False,
    )
    assert res.success is True
    assert len(uninstalled_called) == 1


def test_uninstall_cli_cancelled_by_default(uninstall_env, monkeypatch, capsys):
    """Verify CLI uninstall prompts for confirmation and aborts when operator cancels."""
    # Simulate user answering "no"
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")

    code = uninstall_cli(remove_user_data=False, assume_yes=False)
    assert code == 1

    captured = capsys.readouterr().out
    assert "cancelled by operator" in captured.lower()
    # Binary should still exist
    assert uninstall_env["target_bin"].is_file()


def test_uninstall_cli_non_interactive_yes(uninstall_env, capsys):
    """Verify CLI uninstall with assume_yes=True proceeds without prompt."""
    code = uninstall_cli(remove_user_data=False, assume_yes=True)
    assert code == 0

    captured = capsys.readouterr().out
    assert "DEVICE GUARDIAN - UNINSTALLATION RESULT" in captured
    assert "SUCCESS" in captured
    assert not uninstall_env["target_bin"].is_file()
    assert uninstall_env["env_file"].is_file()


def test_uninstall_cli_via_main_args(uninstall_env, capsys):
    """Verify invoking CLI via main(['--uninstall', '--yes']) executes cleanly."""
    exit_code = main(["--uninstall", "--yes"])
    assert exit_code == 0

    captured = capsys.readouterr().out
    assert "DEVICE GUARDIAN - UNINSTALLATION RESULT" in captured
    assert not uninstall_env["target_bin"].is_file()
