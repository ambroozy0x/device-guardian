"""Unified Environmental Detector coordinating device and network context.

Adheres strictly to Phase 4 memory safety:
- Retains only a bounded history of recent environmental observations.
- Re-evaluates context non-invasively without polling overhead.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Deque, Optional

from device_guardian.environment.models import (
    DeviceState,
    EnvironmentalContext,
    EnvironmentalEvent,
    NetworkContext,
    NetworkState,
)
from device_guardian.environment.network import NetworkDetector
from device_guardian.environment.session import DeviceStateDetector
from device_guardian.logger import get_logger

logger = get_logger("environment.detector")


class EnvironmentalDetector:
    """Orchestrates device state and network context detection."""

    def __init__(
        self,
        device_detector: Optional[DeviceStateDetector] = None,
        network_detector: Optional[NetworkDetector] = None,
        max_history: int = 50,
        network_context_enabled: bool = True,
        device_state_context_enabled: bool = True,
        environmental_triggers_enabled: bool = True,
    ) -> None:
        """Initialize environmental detector.

        Args:
            device_detector: Detector for workstation state.
            network_detector: Detector for network connectivity.
            max_history: Maximum number of environmental events to retain in memory.
            network_context_enabled: Whether to collect network telemetry.
            device_state_context_enabled: Whether to collect device state.
            environmental_triggers_enabled: Master switch for environmental telemetry collection.
        """
        self.device_detector = device_detector or DeviceStateDetector()
        self.network_detector = network_detector or NetworkDetector()
        self.network_context_enabled = network_context_enabled
        self.device_state_context_enabled = device_state_context_enabled
        self.environmental_triggers_enabled = environmental_triggers_enabled

        self._last_context: Optional[EnvironmentalContext] = None
        self._history: Deque[EnvironmentalEvent] = deque(maxlen=max_history)

    def collect_context(self) -> EnvironmentalContext:
        """Collect current environmental snapshot safely.

        Returns:
            EnvironmentalContext containing device and network status.
        """
        now = datetime.now()

        if not self.environmental_triggers_enabled:
            return EnvironmentalContext(
                device_state=DeviceState.UNKNOWN,
                network_context=NetworkContext(
                    connected=False,
                    state=NetworkState.UNKNOWN,
                    collected_at=now,
                ),
                collected_at=now,
                details={"environmental_triggers_enabled": False},
            )

        # Collect device state if enabled
        if self.device_state_context_enabled:
            device_state = self.device_detector.detect_device_state()
        else:
            device_state = DeviceState.UNKNOWN

        # Collect network context if enabled
        if self.network_context_enabled:
            network_context = self.network_detector.detect_network_context()
        else:
            network_context = NetworkContext(
                connected=False,
                state=NetworkState.UNKNOWN,
                collected_at=now,
            )

        current_context = EnvironmentalContext(
            device_state=device_state,
            network_context=network_context,
            collected_at=now,
            details={
                "network_context_enabled": self.network_context_enabled,
                "device_state_context_enabled": self.device_state_context_enabled,
            },
        )

        # Detect and record state transitions
        self._check_transitions(current_context)
        self._last_context = current_context

        logger.debug(
            "Environmental context collected: %s",
            current_context.format_summary(),
        )
        return current_context

    def _check_transitions(self, new_context: EnvironmentalContext) -> None:
        """Record meaningful environmental state transitions."""
        if self._last_context is None:
            return

        # Device state transition
        if new_context.device_state != self._last_context.device_state:
            event_type = f"DEVICE_{new_context.device_state.value}"
            desc = (
                f"Device state transitioned from {self._last_context.device_state.value} "
                f"to {new_context.device_state.value}"
            )
            event = EnvironmentalEvent(
                event_type=event_type,
                timestamp=new_context.collected_at,
                context=new_context,
                description=desc,
            )
            self._history.append(event)
            logger.info("Environmental transition: %s", desc)

        # Network state transition
        if new_context.network_context.state != self._last_context.network_context.state:
            event_type = f"NETWORK_{new_context.network_context.state.value}"
            desc = (
                f"Network state transitioned from {self._last_context.network_context.state.value} "
                f"to {new_context.network_context.state.value}"
            )
            event = EnvironmentalEvent(
                event_type=event_type,
                timestamp=new_context.collected_at,
                context=new_context,
                description=desc,
            )
            self._history.append(event)
            logger.info("Environmental transition: %s", desc)

    def get_recent_events(self) -> list[EnvironmentalEvent]:
        """Return a copy of recent environmental events."""
        return list(self._history)

    def get_last_context(self) -> Optional[EnvironmentalContext]:
        """Return the most recently collected environmental context."""
        return self._last_context

    def record_auth_context_change(
        self,
        description: str,
        context: EnvironmentalContext,
    ) -> EnvironmentalEvent:
        """Record an AUTH_FAILURE_CONTEXT_CHANGE environmental trigger event.

        Args:
            description: Objective description of the detected context change.
            context: The EnvironmentalContext snapshot at the time of the event.

        Returns:
            The recorded EnvironmentalEvent instance.
        """
        event = EnvironmentalEvent(
            event_type="AUTH_FAILURE_CONTEXT_CHANGE",
            timestamp=context.collected_at,
            context=context,
            description=description,
        )
        self._history.append(event)
        logger.info("Environmental trigger: %s", description)
        return event

