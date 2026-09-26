"""Linux startup integration manager via XDG autostart desktop entry (Phase 5).

Manages user autostart entry:
- Location: ~/.config/autostart/device-guardian.desktop
- Standard user permissions; no root/sudo needed.
- Reversible and safe.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.startup.base import BaseStartupManager

logger = get_logger("startup.linux")


class LinuxStartupManager(BaseStartupManager):
    """Manages Linux autostart desktop entry."""

    def __init__(self, autostart_dir: Optional[Path] = None) -> None:
        """Initialize Linux startup manager.

        Args:
            autostart_dir: Optional override for the autostart directory.
        """
        if autostart_dir:
            self.autostart_dir = Path(autostart_dir).resolve()
        else:
            config_home = os.environ.get("XDG_CONFIG_HOME")
            if config_home:
                self.autostart_dir = Path(config_home) / "autostart"
            else:
                self.autostart_dir = Path.home() / ".config" / "autostart"

        self.desktop_file = self.autostart_dir / "device-guardian.desktop"

    def is_supported(self) -> bool:
        """Check if Linux autostart is supported."""
        from device_guardian.platform_compat import is_linux
        return is_linux()

    def is_enabled(self) -> bool:
        """Check if desktop entry exists."""
        return self.desktop_file.is_file()

    def enable(self, custom_command: Optional[str] = None) -> bool:
        """Create the .desktop file in autostart directory."""
        command = custom_command or self.get_default_command()

        if not self.validate_startup_command(command):
            logger.error("Startup command failed security validation: %s", command)
            return False

        try:
            self.autostart_dir.mkdir(parents=True, exist_ok=True)
            content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Version=1.0\n"
                "Name=Device Guardian\n"
                "Comment=Personal anti-theft and intrusion alert system\n"
                f"Exec={command}\n"
                "Terminal=false\n"
                "Categories=Utility;Security;\n"
                "X-GNOME-Autostart-enabled=true\n"
            )
            self.desktop_file.write_text(content, encoding="utf-8")
            logger.info("Created Linux autostart entry at %s", self.desktop_file)
            return True
        except OSError as exc:
            logger.error("Failed to create Linux autostart entry: %s", exc)
            return False

    def disable(self) -> bool:
        """Remove the .desktop file from autostart directory."""
        try:
            if self.desktop_file.is_file():
                self.desktop_file.unlink()
                logger.info("Removed Linux autostart entry from %s", self.desktop_file)
            return True
        except OSError as exc:
            logger.error("Failed to delete Linux autostart entry: %s", exc)
            return False

    def get_command(self) -> Optional[str]:
        """Parse the Exec line from the desktop entry if present."""
        if not self.desktop_file.is_file():
            return None
        try:
            for line in self.desktop_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("Exec="):
                    return line[5:].strip()
            return None
        except OSError:
            return None

    def get_details(self) -> dict[str, Any]:
        """Return diagnostic details regarding Linux autostart registration."""
        return {
            "platform": "Linux",
            "supported": self.is_supported(),
            "enabled": self.is_enabled(),
            "desktop_file": str(self.desktop_file),
            "command": self.get_command(),
        }
