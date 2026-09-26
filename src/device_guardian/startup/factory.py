"""Factory for OS-specific startup managers (Phase 5)."""

from __future__ import annotations

import platform
from typing import Optional

from device_guardian.startup.base import BaseStartupManager
from device_guardian.startup.linux import LinuxStartupManager
from device_guardian.startup.macos import MacOSStartupManager
from device_guardian.startup.windows import WindowsStartupManager


class UnsupportedStartupManager(BaseStartupManager):
    """Fallback startup manager for unsupported platforms."""

    def is_supported(self) -> bool:
        return False

    def is_enabled(self) -> bool:
        return False

    def enable(self, custom_command: Optional[str] = None) -> bool:
        return False

    def disable(self) -> bool:
        return False

    def get_command(self) -> Optional[str]:
        return None

    def get_details(self) -> dict:
        return {"platform": "unsupported", "supported": False, "enabled": False}


def create_startup_manager(platform_name: Optional[str] = None) -> BaseStartupManager:
    """Instantiate the startup manager matching the target operating system.

    Args:
        platform_name: Optional platform string override (e.g. 'Windows', 'Linux', 'Darwin').

    Returns:
        Instance of BaseStartupManager.
    """
    from device_guardian.platform_compat import OperatingSystem, get_current_os

    if platform_name:
        target_os = OperatingSystem.from_string(platform_name)
    else:
        target_os = get_current_os()

    if target_os == OperatingSystem.WINDOWS:
        return WindowsStartupManager()
    elif target_os == OperatingSystem.LINUX:
        return LinuxStartupManager()
    elif target_os == OperatingSystem.MACOS:
        return MacOSStartupManager()
    return UnsupportedStartupManager()
