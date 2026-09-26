"""Unit tests for Environmental, Device, and Network detectors."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from device_guardian.environment.detector import EnvironmentalDetector
from device_guardian.environment.models import (
    DeviceState,
    NetworkContext,
    NetworkState,
)
from device_guardian.environment.network import NetworkDetector
from device_guardian.environment.session import DeviceStateDetector


def test_network_detector_connected() -> None:
    """Verify NetworkDetector with mocked active network interfaces."""
    resolver = MagicMock(return_value=["192.168.1.50"])
    connectivity = MagicMock(return_value="192.168.1.50")

    detector = NetworkDetector(resolver_hook=resolver, connectivity_hook=connectivity)
    ctx = detector.detect_network_context(include_network_id=True)

    assert ctx.connected is True
    assert ctx.state == NetworkState.CONNECTED
    assert ctx.interface_count == 1
    assert ctx.is_private_network is True
    assert ctx.network_identifier == "net_192.168.1.0/24"


def test_network_detector_disconnected() -> None:
    """Verify NetworkDetector when no network routes or interfaces are found."""
    resolver = MagicMock(return_value=[])
    connectivity = MagicMock(return_value=None)

    detector = NetworkDetector(resolver_hook=resolver, connectivity_hook=connectivity)
    ctx = detector.detect_network_context()

    assert ctx.connected is False
    assert ctx.state == NetworkState.DISCONNECTED
    assert ctx.interface_count == 0


def test_network_detector_exception_fallback() -> None:
    """Verify NetworkDetector returns UNKNOWN gracefully on unexpected exception."""
    resolver = MagicMock(side_effect=RuntimeError("Network stack unavailable"))

    detector = NetworkDetector(resolver_hook=resolver)
    ctx = detector.detect_network_context()

    assert ctx.connected is False
    assert ctx.state == NetworkState.UNKNOWN


def test_device_state_detector_custom_hook() -> None:
    """Verify DeviceStateDetector respects custom injected detector hook."""
    detector = DeviceStateDetector(platform_detector=lambda: DeviceState.LOCKED)
    assert detector.detect_device_state() == DeviceState.LOCKED


@patch("platform.system", return_value="Linux")
@patch("subprocess.run")
def test_device_state_detector_linux_locked(mock_run: MagicMock, mock_sys: MagicMock) -> None:
    """Verify Linux lock detection parsing loginctl output."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="LockedHint=yes\n",
        stderr="",
    )
    detector = DeviceStateDetector()
    assert detector.detect_device_state() == DeviceState.LOCKED


@patch("platform.system", return_value="Darwin")
@patch("subprocess.run")
def test_device_state_detector_macos_active(mock_run: MagicMock, mock_sys: MagicMock) -> None:
    """Verify macOS detection parsing active display."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="display is on",
        stderr="",
    )
    detector = DeviceStateDetector()
    assert detector.detect_device_state() == DeviceState.ACTIVE


def test_device_state_detector_unsupported_platform() -> None:
    """Verify unsupported platforms return UNKNOWN without crashing."""
    with patch("platform.system", return_value="FreeBSD"):
        detector = DeviceStateDetector()
        assert detector.detect_device_state() == DeviceState.UNKNOWN


def test_environmental_detector_transitions_and_bounded_history() -> None:
    """Verify EnvironmentalDetector records state transitions and bounds history."""
    dev_state_seq = [DeviceState.ACTIVE, DeviceState.LOCKED, DeviceState.LOCKED]
    net_state_seq = [
        NetworkContext(connected=True, state=NetworkState.CONNECTED, interface_count=1),
        NetworkContext(connected=False, state=NetworkState.DISCONNECTED, interface_count=0),
        NetworkContext(connected=False, state=NetworkState.DISCONNECTED, interface_count=0),
    ]

    mock_dev = MagicMock()
    mock_dev.detect_device_state.side_effect = dev_state_seq
    mock_net = MagicMock()
    mock_net.detect_network_context.side_effect = net_state_seq

    detector = EnvironmentalDetector(
        device_detector=mock_dev,
        network_detector=mock_net,
        max_history=5,
    )

    # First observation (initial baseline)
    ctx1 = detector.collect_context()
    assert ctx1.device_state == DeviceState.ACTIVE
    assert len(detector.get_recent_events()) == 0

    # Second observation (both device and network state transition)
    ctx2 = detector.collect_context()
    assert ctx2.device_state == DeviceState.LOCKED
    events = detector.get_recent_events()
    assert len(events) == 2
    types = [e.event_type for e in events]
    assert "DEVICE_LOCKED" in types
    assert "NETWORK_DISCONNECTED" in types

    # Third observation (no change)
    detector.collect_context()
    assert len(detector.get_recent_events()) == 2


def test_environmental_detector_disabled_features() -> None:
    """Verify disabling contexts returns UNKNOWN without querying underlying providers."""
    mock_dev = MagicMock()
    mock_net = MagicMock()

    detector = EnvironmentalDetector(
        device_detector=mock_dev,
        network_detector=mock_net,
        network_context_enabled=False,
        device_state_context_enabled=False,
    )

    ctx = detector.collect_context()
    assert ctx.device_state == DeviceState.UNKNOWN
    assert ctx.network_context.state == NetworkState.UNKNOWN
    mock_dev.detect_device_state.assert_not_called()
    mock_net.detect_network_context.assert_not_called()


def test_network_detector_packetless_udp_routing() -> None:
    """Verify primary IP query strictly uses connectionless UDP routing without packet transmission."""
    detector = NetworkDetector()

    mock_sock = MagicMock()
    mock_sock.getsockname.return_value = ("192.168.1.100", 54321)

    with patch("socket.socket", return_value=mock_sock) as mock_socket_ctor:
        ip = detector._default_query_primary_ip()

        # Socket was instantiated with AF_INET and SOCK_DGRAM (UDP)
        import socket
        mock_socket_ctor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)

        # connect() was called with RFC 5737 TEST-NET-1 (non-routable doc IP)
        mock_sock.connect.assert_called_once_with(("192.0.2.1", 80))

        # Absolute zero packet transmission calls
        mock_sock.send.assert_not_called()
        mock_sock.sendto.assert_not_called()
        mock_sock.sendall.assert_not_called()

        assert ip == "192.168.1.100"
        mock_sock.close.assert_called_once()


def test_environmental_detector_reverse_transitions() -> None:
    """Verify transitions to ACTIVE and CONNECTED create DEVICE_ACTIVE and NETWORK_CONNECTED."""
    dev_state_seq = [DeviceState.LOCKED, DeviceState.ACTIVE]
    net_state_seq = [
        NetworkContext(connected=False, state=NetworkState.DISCONNECTED, interface_count=0),
        NetworkContext(connected=True, state=NetworkState.CONNECTED, interface_count=1),
    ]

    mock_dev = MagicMock()
    mock_dev.detect_device_state.side_effect = dev_state_seq
    mock_net = MagicMock()
    mock_net.detect_network_context.side_effect = net_state_seq

    detector = EnvironmentalDetector(
        device_detector=mock_dev,
        network_detector=mock_net,
    )

    # Initial baseline: LOCKED and DISCONNECTED
    detector.collect_context()
    assert len(detector.get_recent_events()) == 0

    # Second step: ACTIVE and CONNECTED
    detector.collect_context()
    events = detector.get_recent_events()
    assert len(events) == 2
    types = [e.event_type for e in events]
    assert "DEVICE_ACTIVE" in types
    assert "NETWORK_CONNECTED" in types


def test_environmental_detector_auth_context_change_event() -> None:
    """Verify record_auth_context_change records AUTH_FAILURE_CONTEXT_CHANGE event."""
    detector = EnvironmentalDetector()
    ctx = detector.collect_context()

    event = detector.record_auth_context_change(
        "Authentication failure with context transition",
        ctx,
    )
    assert event.event_type == "AUTH_FAILURE_CONTEXT_CHANGE"
    assert "context transition" in event.description
    assert event in detector.get_recent_events()


def test_environmental_triggers_disabled_master_switch() -> None:
    """Verify environmental_triggers_enabled=False skips all queries and transitions."""
    mock_dev = MagicMock()
    mock_net = MagicMock()

    detector = EnvironmentalDetector(
        device_detector=mock_dev,
        network_detector=mock_net,
        environmental_triggers_enabled=False,
    )

    ctx = detector.collect_context()
    assert ctx.device_state == DeviceState.UNKNOWN
    assert ctx.network_context.state == NetworkState.UNKNOWN
    mock_dev.detect_device_state.assert_not_called()
    mock_net.detect_network_context.assert_not_called()
    assert len(detector.get_recent_events()) == 0


@patch("platform.system", return_value="Darwin")
@patch("subprocess.run")
def test_device_state_detector_macos_error_returns_unknown(mock_run: MagicMock, mock_sys: MagicMock) -> None:
    """Verify macOS detection returns UNKNOWN when command fails with non-zero exit code."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="ioreg: command failed",
    )
    detector = DeviceStateDetector()
    assert detector.detect_device_state() == DeviceState.UNKNOWN

