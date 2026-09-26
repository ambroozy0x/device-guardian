"""Windows startup integration manager using HKCU Run registry key (Phase 5).

Safely manages autostart via standard user HKCU registry:
- Root: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Key Name: "DeviceGuardian"
- Requires no elevation or administrator privileges.
- Reversible and safe.
"""

from __future__ import annotations

import platform
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.startup.base import BaseStartupManager

logger = get_logger("startup.windows")

REG_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_VALUE_NAME = "DeviceGuardian"


class WindowsStartupManager(BaseStartupManager):
    """Manages Windows startup entry via HKCU registry."""

    def __init__(self, winreg_module: Any = None) -> None:
        """Initialize Windows startup manager.

        Args:
            winreg_module: Optional winreg module override for testing.
        """
        self._winreg = winreg_module

    def _get_winreg(self) -> Any:
        """Obtain the winreg module if available."""
        if self._winreg is not None:
            return self._winreg
        if platform.system() != "Windows":
            return None
        try:
            import winreg
            return winreg
        except ImportError:
            return None

    def is_supported(self) -> bool:
        """Check if Windows registry startup is supported."""
        return self._get_winreg() is not None

    def is_enabled(self) -> bool:
        """Check if the HKCU Run registry value exists and is set."""
        winreg = self._get_winreg()
        if not winreg:
            return False

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REG_SUBKEY,
                0,
                winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, REG_VALUE_NAME)
                return bool(val and str(val).strip())
        except (FileNotFoundError, OSError):
            return False

    def enable(self, custom_command: Optional[str] = None) -> bool:
        """Write the startup command to HKCU Run key."""
        winreg = self._get_winreg()
        if not winreg:
            logger.error("Cannot enable startup: Windows registry is unavailable.")
            return False

        command = custom_command or self.get_default_command()

        if not self.validate_startup_command(command):
            logger.error("Startup command failed security validation: %s", command)
            return False

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REG_SUBKEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key,
                    REG_VALUE_NAME,
                    0,
                    winreg.REG_SZ,
                    command,
                )
            logger.info("Device Guardian successfully registered in Windows startup registry.")
            return True
        except OSError as exc:
            logger.error("Failed to write Windows startup registry key: %s", exc)
            return False

    def disable(self) -> bool:
        """Remove the startup entry from HKCU Run key."""
        winreg = self._get_winreg()
        if not winreg:
            return False

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REG_SUBKEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.DeleteValue(key, REG_VALUE_NAME)
            logger.info("Device Guardian removed from Windows startup registry.")
            return True
        except FileNotFoundError:
            # Already removed
            return True
        except OSError as exc:
            logger.error("Failed to delete Windows startup registry key: %s", exc)
            return False

    def get_command(self) -> Optional[str]:
        """Read the currently configured startup command."""
        winreg = self._get_winreg()
        if not winreg:
            return None

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REG_SUBKEY,
                0,
                winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, REG_VALUE_NAME)
                return str(val) if val else None
        except (FileNotFoundError, OSError):
            return None

    def get_details(self) -> dict[str, Any]:
        """Return diagnostic details regarding Windows startup registration."""
        supported = self.is_supported()
        enabled = self.is_enabled()
        cmd = self.get_command()
        return {
            "platform": "Windows",
            "supported": supported,
            "enabled": enabled,
            "registry_root": "HKEY_CURRENT_USER",
            "registry_key": REG_SUBKEY,
            "value_name": REG_VALUE_NAME,
            "command": cmd,
        }
