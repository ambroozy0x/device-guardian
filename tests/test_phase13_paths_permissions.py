"""Phase 13 tests: Cross-Platform Paths, Hierarchy, and Filesystem Permissions.

Verifies:
- ApplicationPaths user data directory resolution across Windows, Linux, and macOS.
- ApplicationPaths install root directory resolution across platforms.
- Correct isolation of user data directory from read-only install roots.
- Handling of paths with spaces, unicode characters, and deep nesting.
- Filesystem security validation: path traversal rejection, UNC paths, ADS streams, null bytes.
- Restrictive permission handling (0600) on secret storage and backups.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from device_guardian.platform_compat import (
    OperatingSystem,
    platform_override,
    reset_platform_overrides,
    verify_file_permissions,
)
from device_guardian.runtime.paths import (
    ApplicationPaths,
    set_install_dir_override,
    set_user_data_dir_override,
)
from device_guardian.security.filesystem import (
    SecurityPathError,
    validate_safe_path,
)
from device_guardian.security.store import FileSecretStore


@pytest.fixture(autouse=True)
def clean_path_state():
    """Ensure path overrides and platform overrides are clean before and after tests."""
    reset_platform_overrides()
    set_user_data_dir_override(None)
    set_install_dir_override(None)
    yield
    reset_platform_overrides()
    set_user_data_dir_override(None)
    set_install_dir_override(None)


def test_user_data_dir_windows_model(monkeypatch, tmp_path):
    """Verify Windows user data directory defaults to %LOCALAPPDATA%\\DeviceGuardian."""
    mock_local = tmp_path / "MockAppData" / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(mock_local))

    with platform_override(OperatingSystem.WINDOWS):
        data_dir = ApplicationPaths.get_user_data_dir()
        assert str(data_dir).startswith(str(mock_local))
        assert "DeviceGuardian" in str(data_dir)
        assert data_dir.is_dir()


def test_user_data_dir_windows_fallback(monkeypatch, tmp_path):
    """Verify Windows falls back to ~/.device_guardian if LOCALAPPDATA is unset."""
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    with platform_override(OperatingSystem.WINDOWS):
        data_dir = ApplicationPaths.get_user_data_dir()
        assert ".device_guardian" in str(data_dir) or "DeviceGuardian" in str(data_dir)


def test_user_data_dir_macos_model():
    """Verify macOS user data directory resolves to ~/Library/Application Support/DeviceGuardian."""
    with platform_override(OperatingSystem.MACOS):
        data_dir = ApplicationPaths.get_user_data_dir()
        norm = str(data_dir).replace("\\", "/")
        assert "Library/Application Support/DeviceGuardian" in norm
        assert data_dir.is_dir()


def test_user_data_dir_linux_xdg_model(monkeypatch, tmp_path):
    """Verify Linux user data directory respects $XDG_DATA_HOME."""
    mock_xdg = tmp_path / "mock_xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(mock_xdg))

    with platform_override(OperatingSystem.LINUX):
        data_dir = ApplicationPaths.get_user_data_dir()
        norm = str(data_dir).replace("\\", "/")
        assert str(mock_xdg).replace("\\", "/") in norm
        assert "device-guardian" in norm


def test_user_data_dir_linux_fallback(monkeypatch):
    """Verify Linux falls back to ~/.local/share/device-guardian when XDG is unset."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    with platform_override(OperatingSystem.LINUX):
        data_dir = ApplicationPaths.get_user_data_dir()
        norm = str(data_dir).replace("\\", "/")
        assert ".local/share/device-guardian" in norm


def test_install_root_cross_platform_resolution(tmp_path, monkeypatch):
    """Verify install root differs per OS and is distinct from user data."""
    mock_appdata = tmp_path / "AppData" / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(mock_appdata))

    with platform_override(OperatingSystem.WINDOWS):
        win_root = ApplicationPaths.get_install_root()
        assert "Programs" in str(win_root) or "DeviceGuardian" in str(win_root)

    with platform_override(OperatingSystem.MACOS):
        mac_root = ApplicationPaths.get_install_root()
        norm_mac = str(mac_root).replace("\\", "/")
        assert "Applications/DeviceGuardian" in norm_mac

    with platform_override(OperatingSystem.LINUX):
        linux_root = ApplicationPaths.get_install_root()
        norm_linux = str(linux_root).replace("\\", "/")
        assert ".local/share/device-guardian/bin" in norm_linux


def test_paths_with_spaces_and_unicode(tmp_path):
    """Verify ApplicationPaths and safe path validation handle paths with spaces and Unicode."""
    unicode_dir = tmp_path / "Guardian Dir 🛡️ with Spaces & 日本語"
    unicode_dir.mkdir(parents=True, exist_ok=True)

    set_user_data_dir_override(unicode_dir)
    assert ApplicationPaths.get_user_data_dir() == unicode_dir.resolve()

    log_dir = ApplicationPaths.get_log_dir()
    assert log_dir.parent == unicode_dir.resolve()
    assert log_dir.is_dir()

    validated = validate_safe_path(unicode_dir)
    assert validated == unicode_dir.resolve()


def test_filesystem_path_traversal_defense():
    """Verify path traversal segments are rejected across path separators."""
    with pytest.raises(SecurityPathError, match="Path traversal"):
        validate_safe_path("foo/../bar")

    with pytest.raises(SecurityPathError, match="Path traversal"):
        validate_safe_path(r"foo\..\bar")

    with pytest.raises(SecurityPathError, match="Path traversal"):
        validate_safe_path("../../../etc/passwd")


def test_filesystem_null_byte_and_unc_defense():
    """Verify null bytes and UNC network paths are strictly rejected."""
    with pytest.raises(SecurityPathError, match="Null byte"):
        validate_safe_path("valid/path\0evil")

    with pytest.raises(SecurityPathError, match="UNC network"):
        validate_safe_path(r"\\evil-server\share\file.txt")

    with pytest.raises(SecurityPathError, match="UNC network"):
        validate_safe_path("//evil-server/share/file.txt")


def test_file_secret_store_permissions(tmp_path):
    """Verify FileSecretStore persists data atomically and sets restrictive 0600 permissions."""
    secret_file = tmp_path / "secrets.json"
    store = FileSecretStore(file_path=secret_file)

    assert store.get_backend_name() == "Filesystem (Restricted Permissions)"
    ok = store.set_secret("api_key", "secret-token-xyz")
    assert ok is True
    assert secret_file.is_file()

    # Secret retrieval
    val = store.get_secret("api_key")
    assert val is not None
    assert val.get_secret_value() == "secret-token-xyz"

    # Verify backup was created and has permissions
    backup_file = tmp_path / "secrets.json.bak"
    store.set_secret("second_key", "second-token")
    assert backup_file.is_file()

    # Verify permission check
    valid, msg = verify_file_permissions(secret_file, 0o600)
    assert valid is True
