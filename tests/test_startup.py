"""Tests for OS startup integration managers (Windows, Linux, macOS) (Phase 5)."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from device_guardian.startup import (
    LinuxStartupManager,
    MacOSStartupManager,
    WindowsStartupManager,
    create_startup_manager,
)


def test_windows_startup_manager_mock():
    """Verify WindowsStartupManager registry operations using mock winreg."""
    mock_winreg = MagicMock()
    mock_key = MagicMock()
    mock_winreg.OpenKey.return_value.__enter__.return_value = mock_key
    mock_winreg.QueryValueEx.return_value = ('"C:\\app.exe" --start', 1)

    mgr = WindowsStartupManager(winreg_module=mock_winreg)
    assert mgr.is_supported() is True
    assert mgr.is_enabled() is True
    assert mgr.get_command() == '"C:\\app.exe" --start'

    # Test enable
    assert mgr.enable('"C:\\custom.exe" --start') is True
    mock_winreg.SetValueEx.assert_called_once()

    # Test disable
    assert mgr.disable() is True
    mock_winreg.DeleteValue.assert_called_once()


def test_linux_startup_manager(tmp_path):
    """Verify LinuxStartupManager creates and cleans up XDG desktop autostart entry."""
    autostart_dir = tmp_path / "autostart"
    mgr = LinuxStartupManager(autostart_dir=autostart_dir)

    assert mgr.is_enabled() is False
    assert mgr.get_command() is None

    # Enable
    cmd = '"/usr/bin/device-guardian" --start'
    assert mgr.enable(custom_command=cmd) is True
    assert mgr.is_enabled() is True
    assert mgr.get_command() == cmd

    desktop_file = autostart_dir / "device-guardian.desktop"
    assert desktop_file.is_file()
    content = desktop_file.read_text(encoding="utf-8")
    assert "Exec=" in content
    assert "Device Guardian" in content

    # Disable
    assert mgr.disable() is True
    assert mgr.is_enabled() is False
    assert not desktop_file.is_file()


def test_macos_startup_manager(tmp_path):
    """Verify MacOSStartupManager creates and cleans up LaunchAgent plist."""
    launch_agents = tmp_path / "LaunchAgents"
    mgr = MacOSStartupManager(launch_agents_dir=launch_agents)

    assert mgr.is_enabled() is False
    assert mgr.get_command() is None

    cmd = '"/Applications/DeviceGuardian.app/Contents/MacOS/device-guardian" --start'
    assert mgr.enable(custom_command=cmd) is True
    assert mgr.is_enabled() is True

    plist_file = launch_agents / "com.deviceguardian.app.plist"
    assert plist_file.is_file()
    content = plist_file.read_text(encoding="utf-8")
    assert "com.deviceguardian.app" in content
    assert "RunAtLoad" in content

    # Disable
    assert mgr.disable() is True
    assert mgr.is_enabled() is False
    assert not plist_file.is_file()


def test_startup_factory():
    """Verify startup factory routes to platform specific managers."""
    win_mgr = create_startup_manager("Windows")
    assert isinstance(win_mgr, WindowsStartupManager)

    linux_mgr = create_startup_manager("Linux")
    assert isinstance(linux_mgr, LinuxStartupManager)

    mac_mgr = create_startup_manager("Darwin")
    assert isinstance(mac_mgr, MacOSStartupManager)
