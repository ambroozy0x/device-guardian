"""Unit tests for Phase 4 Environmental Models."""

from __future__ import annotations

from datetime import datetime

from device_guardian.environment.models import (
    DeviceState,
    EnvironmentalContext,
    EnvironmentalEvent,
    NetworkContext,
    NetworkState,
)


def test_device_and_network_state_enums() -> None:
    """Verify enum members and string representations."""
    assert DeviceState.ACTIVE.value == "ACTIVE"
    assert DeviceState.IDLE.value == "IDLE"
    assert DeviceState.LOCKED.value == "LOCKED"
    assert DeviceState.UNKNOWN.value == "UNKNOWN"

    assert NetworkState.CONNECTED.value == "CONNECTED"
    assert NetworkState.DISCONNECTED.value == "DISCONNECTED"
    assert NetworkState.UNKNOWN.value == "UNKNOWN"


def test_network_context_defaults_and_summary() -> None:
    """Verify NetworkContext defaults and factual summary format."""
    net = NetworkContext(
        connected=True,
        state=NetworkState.CONNECTED,
        interface_count=2,
        network_identifier="net_192.168.1.0/24",
        is_private_network=True,
    )
    assert net.connected is True
    assert net.is_private_network is True
    summary = net.format_summary()
    assert "Network: CONNECTED" in summary
    assert "Interfaces: 2" in summary
    assert "ID: net_192.168.1.0/24" in summary


def test_environmental_context_defaults_and_summary() -> None:
    """Verify EnvironmentalContext composition and summary."""
    now = datetime(2026, 9, 26, 0, 15, 0)
    net = NetworkContext(connected=False, state=NetworkState.DISCONNECTED, interface_count=0)
    env = EnvironmentalContext(
        device_state=DeviceState.LOCKED,
        network_context=net,
        collected_at=now,
    )
    assert env.device_state == DeviceState.LOCKED
    summary = env.format_summary()
    assert "Device State: LOCKED" in summary
    assert "Network: DISCONNECTED" in summary
    assert "2026-09-26 00:15:00" in summary


def test_environmental_event_summary() -> None:
    """Verify EnvironmentalEvent creation and summary formatting."""
    now = datetime(2026, 9, 26, 0, 16, 0)
    event = EnvironmentalEvent(
        event_type="DEVICE_LOCKED",
        timestamp=now,
        description="Workstation entered locked desktop state",
    )
    summary = event.format_summary()
    assert "DEVICE_LOCKED" in summary
    assert "Workstation entered locked desktop state" in summary
