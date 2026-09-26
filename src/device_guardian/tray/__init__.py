"""Device Guardian system tray package (Phase 5).

Provides dynamic system tray status icon and context menu.
"""

from device_guardian.tray.icons import STATE_COLORS, create_tray_image
from device_guardian.tray.manager import TrayManager

__all__ = [
    "STATE_COLORS",
    "TrayManager",
    "create_tray_image",
]
