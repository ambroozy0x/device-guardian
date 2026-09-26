"""Environmental context data models for Device Guardian (Phase 4).

Represents non-invasive device and network state:
- DeviceState: ACTIVE, IDLE, LOCKED, UNKNOWN
- NetworkState: CONNECTED, DISCONNECTED, UNKNOWN
- NetworkContext: basic interface telemetry without packet capture or LAN scanning
- EnvironmentalContext: combined environmental snapshot with objective summary
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class DeviceState(str, Enum):
    """Operational/lock state of the local device."""

    ACTIVE = "ACTIVE"
    IDLE = "IDLE"
    LOCKED = "LOCKED"
    UNKNOWN = "UNKNOWN"


class NetworkState(str, Enum):
    """Network connectivity status."""

    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class NetworkContext:
    """Non-invasive network environment context.

    Captures only connectivity state and local interface availability.
    Strictly prohibits packet inspection, LAN scanning, or device enumeration.
    """

    connected: bool = False
    state: NetworkState = NetworkState.UNKNOWN
    interface_count: int = 0
    network_identifier: Optional[str] = None
    is_private_network: bool = False
    collected_at: datetime = field(default_factory=datetime.now)
    details: dict[str, Any] = field(default_factory=dict)

    def format_summary(self) -> str:
        """Return objective, factual summary of network state."""
        id_str = f", ID: {self.network_identifier}" if self.network_identifier else ""
        return (
            f"Network: {self.state.value} "
            f"(Interfaces: {self.interface_count}{id_str})"
        )


@dataclass
class EnvironmentalContext:
    """Snapshot of device and network environment at evaluation time."""

    device_state: DeviceState = DeviceState.UNKNOWN
    network_context: NetworkContext = field(default_factory=NetworkContext)
    collected_at: datetime = field(default_factory=datetime.now)
    details: dict[str, Any] = field(default_factory=dict)

    def format_summary(self) -> str:
        """Format an objective, factual summary of the environmental state."""
        return (
            f"Device State: {self.device_state.value} | "
            f"{self.network_context.format_summary()} | "
            f"Observed: {self.collected_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )


@dataclass
class EnvironmentalEvent:
    """Deterministic environmental transition or observation event."""

    event_type: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: EnvironmentalContext = field(default_factory=EnvironmentalContext)
    description: str = ""

    def format_summary(self) -> str:
        """Format objective summary of environmental event."""
        return (
            f"Environmental Event [{self.event_type}] at "
            f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}: {self.description}"
        )
