"""Environment subsystem for Device Guardian (Phase 4).

Provides non-invasive detection and representation of local device and network state.
"""

from __future__ import annotations

from device_guardian.environment.detector import EnvironmentalDetector
from device_guardian.environment.models import (
    DeviceState,
    EnvironmentalContext,
    EnvironmentalEvent,
    NetworkContext,
    NetworkState,
)
from device_guardian.environment.network import NetworkDetector
from device_guardian.environment.session import DeviceStateDetector

__all__ = [
    "DeviceState",
    "DeviceStateDetector",
    "EnvironmentalContext",
    "EnvironmentalDetector",
    "EnvironmentalEvent",
    "NetworkContext",
    "NetworkDetector",
    "NetworkState",
]
