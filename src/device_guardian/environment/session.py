"""Device session and lock state detector for Device Guardian (Phase 4).

Detects whether the local device is ACTIVE, IDLE, LOCKED, or UNKNOWN.
Adheres strictly to Phase 4 safety boundaries:
- Uses only documented OS session facilities.
- Absolutely NO screenshots or screen captures.
- Absolutely NO keystroke monitoring or mouse tracking.
- Fails gracefully to DeviceState.UNKNOWN if platform API is unavailable.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Callable, Optional

from device_guardian.environment.models import DeviceState
from device_guardian.logger import get_logger

logger = get_logger("environment.session")


class DeviceStateDetector:
    """Detects local workstation operational/lock state safely and non-invasively."""

    def __init__(
        self,
        platform_detector: Optional[Callable[[], DeviceState]] = None,
    ) -> None:
        """Initialize the device state detector.

        Args:
            platform_detector: Optional hook to override platform detection for testing.
        """
        self._custom_detector = platform_detector

    def detect_device_state(self) -> DeviceState:
        """Query current workstation state.

        Returns:
            DeviceState enum value (ACTIVE, LOCKED, IDLE, or UNKNOWN).
        """
        if self._custom_detector is not None:
            try:
                return self._custom_detector()
            except Exception as exc:
                logger.debug("Custom device detector failed: %s", exc)
                return DeviceState.UNKNOWN

        sys_name = platform.system()
        try:
            if sys_name == "Windows":
                return self._detect_windows_state()
            elif sys_name == "Linux":
                return self._detect_linux_state()
            elif sys_name == "Darwin":
                return self._detect_macos_state()
            else:
                return DeviceState.UNKNOWN
        except Exception as exc:
            logger.debug("Device state detection error on %s: %s", sys_name, exc)
            return DeviceState.UNKNOWN

    def _detect_windows_state(self) -> DeviceState:
        """Detect Windows workstation lock state via OpenInputDesktop.

        When a Windows desktop is locked, the active desktop switches to 'Winlogon' /
        secure desktop, causing OpenInputDesktop to return Access Denied (error code 5).
        """
        try:
            import ctypes
            user32 = ctypes.windll.user32
            # DESKTOP_SWITCHDESKTOP = 0x0100
            h_desktop = user32.OpenInputDesktop(0, False, 0x0100)
            if h_desktop:
                user32.CloseDesktop(h_desktop)
                return DeviceState.ACTIVE
            else:
                # Error 5 is ERROR_ACCESS_DENIED, indicating locked desktop
                err = ctypes.GetLastError()
                if err == 5:
                    return DeviceState.LOCKED
                return DeviceState.UNKNOWN
        except Exception as exc:
            logger.debug("Windows desktop state check exception: %s", exc)
            return DeviceState.UNKNOWN

    def _detect_linux_state(self) -> DeviceState:
        """Detect Linux lock state via loginctl or screen lock tools."""
        try:
            # Check loginctl for active session locked hint
            res = subprocess.run(
                ["loginctl", "show-session", "self", "-p", "LockedHint"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res.returncode == 0:
                stdout = res.stdout.strip().lower()
                if "lockedhint=yes" in stdout:
                    return DeviceState.LOCKED
                elif "lockedhint=no" in stdout:
                    return DeviceState.ACTIVE

            return DeviceState.UNKNOWN
        except Exception:
            return DeviceState.UNKNOWN

    def _detect_macos_state(self) -> DeviceState:
        """Detect macOS lock/display state via Quartz session dictionary."""
        try:
            # Query CGSession dictionary or ioreg for screen lock state
            res = subprocess.run(
                ["ioreg", "-n", "Root", "-d1", "-a"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res.returncode == 0:
                if "CGSSessionScreenIsLocked" in res.stdout:
                    return DeviceState.LOCKED
                return DeviceState.ACTIVE

            return DeviceState.UNKNOWN
        except Exception:
            return DeviceState.UNKNOWN
