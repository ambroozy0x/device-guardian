"""Device Guardian OS startup package (Phase 5).

Provides reversible, user-controlled autostart integration for Windows,
Linux, and macOS.
"""

from device_guardian.startup.base import BaseStartupManager
from device_guardian.startup.factory import create_startup_manager
from device_guardian.startup.linux import LinuxStartupManager
from device_guardian.startup.macos import MacOSStartupManager
from device_guardian.startup.windows import WindowsStartupManager

__all__ = [
    "BaseStartupManager",
    "LinuxStartupManager",
    "MacOSStartupManager",
    "WindowsStartupManager",
    "create_startup_manager",
]
