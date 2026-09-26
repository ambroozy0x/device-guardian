"""Detection package for Device Guardian (Phase 3).

Exposes operating system authentication failure monitors, threshold evaluation,
alert cooldown management, offline voice warnings, and the DetectionManager.
"""

from __future__ import annotations

from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.cooldown import AlertCooldownManager
from device_guardian.detection.linux import LinuxAuthLogMonitor
from device_guardian.detection.macos import MacOSAuthLogMonitor
from device_guardian.detection.manager import (
    DetectionManager,
    NullAuthenticationMonitor,
    create_platform_monitor,
)
from device_guardian.detection.models import (
    AuthenticationFailureEvent,
    DetectionStatus,
    MonitorState,
)
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.detection.voice import OfflineVoiceWarning
from device_guardian.detection.windows import WindowsSecurityLogMonitor

__all__ = [
    "AlertCooldownManager",
    "AuthenticationFailureEvent",
    "BaseAuthenticationMonitor",
    "DetectionManager",
    "DetectionStatus",
    "LinuxAuthLogMonitor",
    "MacOSAuthLogMonitor",
    "MonitorState",
    "NullAuthenticationMonitor",
    "OfflineVoiceWarning",
    "SlidingWindowThresholdEngine",
    "WindowsSecurityLogMonitor",
    "create_platform_monitor",
]
