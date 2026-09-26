"""Tests for ApplicationPaths resource resolution and platform directories (Phase 5)."""

from pathlib import Path
import sys
from unittest.mock import patch
import pytest

from device_guardian.runtime.paths import ApplicationPaths


@pytest.fixture(autouse=True)
def reset_override():
    """Ensure data dir override is cleared before and after each test."""
    ApplicationPaths.set_data_dir_override(None)
    yield
    ApplicationPaths.set_data_dir_override(None)


def test_is_frozen_detection():
    """Verify is_frozen returns True only when sys.frozen and _MEIPASS are set."""
    with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", "/tmp/extracted", create=True):
        assert ApplicationPaths.is_frozen() is True

    # Without _MEIPASS
    if hasattr(sys, "frozen"):
        del sys.frozen
    assert ApplicationPaths.is_frozen() is False


def test_bundle_dir_source_vs_frozen(tmp_path):
    """Verify get_bundle_dir respects PyInstaller _MEIPASS extraction directory."""
    fake_meipass = str(tmp_path / "meipass_bundle")
    with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", fake_meipass, create=True):
        bundle_dir = ApplicationPaths.get_bundle_dir()
        assert str(bundle_dir) == str(Path(fake_meipass).resolve())

    # When running from source
    source_bundle = ApplicationPaths.get_bundle_dir()
    assert source_bundle.is_dir()
    assert (source_bundle / "src").is_dir() or (source_bundle / "tests").is_dir()


def test_data_dir_override(tmp_path):
    """Verify data directory override isolates mutable files."""
    custom_dir = tmp_path / "custom_data"
    ApplicationPaths.set_data_dir_override(custom_dir)

    assert ApplicationPaths.get_user_data_dir() == custom_dir
    assert custom_dir.is_dir()

    lock_path = ApplicationPaths.get_lock_file_path()
    assert lock_path.parent == custom_dir
    assert lock_path.name == "guardian.lock"

    status_path = ApplicationPaths.get_status_file_path()
    assert status_path.parent == custom_dir
    assert status_path.name == "runtime_status.json"

    control_path = ApplicationPaths.get_control_file_path()
    assert control_path.parent == custom_dir
    assert control_path.name == "guardian.control"


def test_log_dir_creation(tmp_path):
    """Verify log directory is placed in user data dir and automatically created."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    log_dir = ApplicationPaths.get_log_dir()
    assert log_dir == tmp_path / "logs"
    assert log_dir.is_dir()


def test_config_discovery(tmp_path):
    """Verify config file discovery checks CWD, user data dir, and executable dir."""
    ApplicationPaths.set_data_dir_override(tmp_path)
    user_env = tmp_path / ".env"
    user_env.write_text("TELEGRAM_BOT_TOKEN=test_token\n", encoding="utf-8")

    # With CWD having no .env, it should find user_env
    with patch("pathlib.Path.cwd", return_value=tmp_path / "empty_cwd"):
        discovered = ApplicationPaths.get_config_file_path()
        assert discovered == user_env
