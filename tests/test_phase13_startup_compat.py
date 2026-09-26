"""Phase 13 tests: Cross-Platform OS Startup Integration and Security Validation.

Verifies:
- Factory dispatch across Windows, Linux, macOS, and Unsupported platforms.
- LinuxStartupManager XDG autostart desktop entry creation, parsing, and removal.
- MacOSStartupManager LaunchAgent plist XML generation, argument parsing, and removal.
- WindowsStartupManager registry key management via mock winreg.
- BaseStartupManager command injection defense and metacharacter validation.
- Non-destructive and idempotent enable/disable behaviors across platforms.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from device_guardian.platform_compat import (
    OperatingSystem,
    platform_override,
    reset_platform_overrides,
)
from device_guardian.startup.base import BaseStartupManager
from device_guardian.startup.factory import UnsupportedStartupManager, create_startup_manager
from device_guardian.startup.linux import LinuxStartupManager
from device_guardian.startup.macos import MacOSStartupManager
from device_guardian.startup.windows import WindowsStartupManager


@pytest.fixture(autouse=True)
def clean_environment():
    reset_platform_overrides()
    yield
    reset_platform_overrides()


def test_factory_dispatch_across_platforms():
    """Verify create_startup_manager yields the proper platform manager class."""
    assert isinstance(create_startup_manager("Windows"), WindowsStartupManager)
    assert isinstance(create_startup_manager("Linux"), LinuxStartupManager)
    assert isinstance(create_startup_manager("Darwin"), MacOSStartupManager)
    assert isinstance(create_startup_manager("macOS"), MacOSStartupManager)
    assert isinstance(create_startup_manager("Solaris"), UnsupportedStartupManager)

    # Test via platform_override
    with platform_override(OperatingSystem.WINDOWS):
        assert isinstance(create_startup_manager(), WindowsStartupManager)

    with platform_override(OperatingSystem.LINUX):
        assert isinstance(create_startup_manager(), LinuxStartupManager)

    with platform_override(OperatingSystem.MACOS):
        assert isinstance(create_startup_manager(), MacOSStartupManager)


def test_linux_startup_manager_lifecycle(tmp_path):
    """Verify Linux XDG desktop entry creation, query, and removal."""
    autostart_dir = tmp_path / "autostart"
    mgr = LinuxStartupManager(autostart_dir=autostart_dir)

    with platform_override(OperatingSystem.LINUX):
        assert mgr.is_supported() is True
    with platform_override(OperatingSystem.WINDOWS):
        assert mgr.is_supported() is False

    assert mgr.is_enabled() is False
    assert mgr.get_command() is None

    # Enable autostart
    cmd = "/usr/bin/device-guardian --start"
    enabled = mgr.enable(custom_command=cmd)
    assert enabled is True
    assert mgr.is_enabled() is True
    assert mgr.get_command() == cmd

    desktop_file = autostart_dir / "device-guardian.desktop"
    assert desktop_file.is_file()
    content = desktop_file.read_text(encoding="utf-8")
    assert "[Desktop Entry]" in content
    assert f"Exec={cmd}" in content
    assert "Terminal=false" in content

    # Diagnostic details
    details = mgr.get_details()
    assert details["platform"] == "Linux"
    assert details["enabled"] is True
    assert details["command"] == cmd

    # Disable autostart
    disabled = mgr.disable()
    assert disabled is True
    assert mgr.is_enabled() is False
    assert not desktop_file.is_file()


def test_macos_startup_manager_lifecycle(tmp_path):
    """Verify macOS LaunchAgent plist XML generation, query, and removal."""
    launch_agents = tmp_path / "LaunchAgents"
    mgr = MacOSStartupManager(launch_agents_dir=launch_agents)

    with platform_override(OperatingSystem.MACOS):
        assert mgr.is_supported() is True
    with platform_override(OperatingSystem.WINDOWS):
        assert mgr.is_supported() is False

    assert mgr.is_enabled() is False
    assert mgr.get_command() is None

    # Enable LaunchAgent
    cmd = "/Applications/DeviceGuardian/device-guardian --start"
    enabled = mgr.enable(custom_command=cmd)
    assert enabled is True
    assert mgr.is_enabled() is True
    assert mgr.get_command() == cmd

    plist_file = launch_agents / "com.deviceguardian.app.plist"
    assert plist_file.is_file()
    xml_content = plist_file.read_text(encoding="utf-8")
    assert "com.deviceguardian.app" in xml_content
    assert "<key>RunAtLoad</key>" in xml_content
    assert "<true/>" in xml_content

    # Diagnostic details
    details = mgr.get_details()
    assert details["platform"] == "macOS"
    assert details["enabled"] is True

    # Disable LaunchAgent
    assert mgr.disable() is True
    assert mgr.is_enabled() is False
    assert not plist_file.is_file()


def test_windows_startup_manager_mock():
    """Verify Windows startup manager interaction with mock registry."""
    class MockWinreg:
        HKEY_CURRENT_USER = "HKCU"
        KEY_READ = 1
        KEY_SET_VALUE = 2
        REG_SZ = 1

        def __init__(self):
            self.registry = {}

        def OpenKey(self, root, subkey, reserved, access):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def QueryValueEx(self, key, value_name):
            if value_name in self.registry:
                return self.registry[value_name], 1
            raise FileNotFoundError()

        def SetValueEx(self, key, value_name, reserved, reg_type, value):
            self.registry[value_name] = value

        def DeleteValue(self, key, value_name):
            if value_name in self.registry:
                del self.registry[value_name]
            else:
                raise FileNotFoundError()

    mock_reg = MockWinreg()
    mgr = WindowsStartupManager(winreg_module=mock_reg)

    assert mgr.is_supported() is True
    assert mgr.is_enabled() is False

    # Enable
    cmd = r'"C:\Program Files\DeviceGuardian\device-guardian.exe" --start'
    assert mgr.enable(custom_command=cmd) is True
    assert mgr.is_enabled() is True
    assert mgr.get_command() == cmd

    # Details
    details = mgr.get_details()
    assert details["platform"] == "Windows"
    assert details["enabled"] is True

    # Disable
    assert mgr.disable() is True
    assert mgr.is_enabled() is False


def test_startup_command_security_validation():
    """Verify startup command validator rejects shell metacharacters and injection attempts."""
    # Safe commands
    assert BaseStartupManager.validate_startup_command(r'"C:\App\app.exe" --start') is True
    assert BaseStartupManager.validate_startup_command("/usr/bin/device-guardian --start") is True

    # Empty or None
    assert BaseStartupManager.validate_startup_command("") is False
    assert BaseStartupManager.validate_startup_command("   ") is False

    # Metacharacter injection attacks
    assert BaseStartupManager.validate_startup_command("app.exe & calc.exe") is False
    assert BaseStartupManager.validate_startup_command("app.exe | evil.exe") is False
    assert BaseStartupManager.validate_startup_command("app.exe ; rm -rf /") is False
    assert BaseStartupManager.validate_startup_command("app.exe > /dev/null") is False
    assert BaseStartupManager.validate_startup_command("app.exe < input.txt") is False
    assert BaseStartupManager.validate_startup_command("app.exe `whoami`") is False
    assert BaseStartupManager.validate_startup_command("app.exe $EVIL_VAR") is False
    assert BaseStartupManager.validate_startup_command("app.exe\ncalc.exe") is False


def test_unsupported_startup_manager():
    """Verify UnsupportedStartupManager safely returns False/None without exceptions."""
    mgr = UnsupportedStartupManager()
    assert mgr.is_supported() is False
    assert mgr.is_enabled() is False
    assert mgr.enable() is False
    assert mgr.disable() is False
    assert mgr.get_command() is None
    assert mgr.get_details()["supported"] is False
