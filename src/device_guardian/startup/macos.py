"""macOS startup integration manager via LaunchAgent plist (Phase 5).

Manages user LaunchAgent:
- Location: ~/Library/LaunchAgents/com.deviceguardian.app.plist
- Standard user permissions; no root/sudo needed.
- Reversible and safe.
"""

from __future__ import annotations

from pathlib import Path
import platform
import shlex
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.startup.base import BaseStartupManager

logger = get_logger("startup.macos")

PLIST_NAME = "com.deviceguardian.app.plist"


class MacOSStartupManager(BaseStartupManager):
    """Manages macOS LaunchAgent autostart plist."""

    def __init__(self, launch_agents_dir: Optional[Path] = None) -> None:
        """Initialize macOS startup manager.

        Args:
            launch_agents_dir: Optional override for LaunchAgents directory.
        """
        if launch_agents_dir:
            self.launch_agents_dir = Path(launch_agents_dir).resolve()
        else:
            self.launch_agents_dir = Path.home() / "Library" / "LaunchAgents"

        self.plist_file = self.launch_agents_dir / PLIST_NAME

    def is_supported(self) -> bool:
        """Check if macOS LaunchAgent autostart is supported."""
        from device_guardian.platform_compat import is_macos
        return is_macos()

    def is_enabled(self) -> bool:
        """Check if LaunchAgent plist exists."""
        return self.plist_file.is_file()

    def enable(self, custom_command: Optional[str] = None) -> bool:
        """Create the LaunchAgent plist file."""
        command = custom_command or self.get_default_command()

        if not self.validate_startup_command(command):
            logger.error("Startup command failed security validation: %s", command)
            return False

        # Split command into arguments array for plist
        args = shlex.split(command, posix=True)
        args_xml = "\n".join(f"        <string>{arg}</string>" for arg in args)

        plist_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            '<dict>\n'
            '    <key>Label</key>\n'
            '    <string>com.deviceguardian.app</string>\n'
            '    <key>ProgramArguments</key>\n'
            '    <array>\n'
            f'{args_xml}\n'
            '    </array>\n'
            '    <key>RunAtLoad</key>\n'
            '    <true/>\n'
            '</dict>\n'
            '</plist>\n'
        )

        try:
            self.launch_agents_dir.mkdir(parents=True, exist_ok=True)
            self.plist_file.write_text(plist_content, encoding="utf-8")
            logger.info("Created macOS LaunchAgent plist at %s", self.plist_file)
            return True
        except OSError as exc:
            logger.error("Failed to create macOS LaunchAgent plist: %s", exc)
            return False

    def disable(self) -> bool:
        """Remove the LaunchAgent plist file."""
        try:
            if self.plist_file.is_file():
                self.plist_file.unlink()
                logger.info("Removed macOS LaunchAgent plist at %s", self.plist_file)
            return True
        except OSError as exc:
            logger.error("Failed to delete macOS LaunchAgent plist: %s", exc)
            return False

    def get_command(self) -> Optional[str]:
        """Extract arguments from the plist file if present."""
        if not self.plist_file.is_file():
            return None
        try:
            content = self.plist_file.read_text(encoding="utf-8")
            import re
            strings = re.findall(r"<string>(.*?)</string>", content)
            if len(strings) > 1:
                # First string is label, subsequent are program arguments
                return " ".join(strings[1:])
            return None
        except Exception:
            return None

    def get_details(self) -> dict[str, Any]:
        """Return diagnostic details regarding macOS startup registration."""
        return {
            "platform": "macOS",
            "supported": self.is_supported(),
            "enabled": self.is_enabled(),
            "plist_file": str(self.plist_file),
            "command": self.get_command(),
        }
