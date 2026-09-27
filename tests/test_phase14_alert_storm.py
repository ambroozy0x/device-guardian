"""Phase 14 Alert Storm Protection & Backpressure Tests for Device Guardian.

Verifies:
- Alert storm protection: bursts of 100 rapid failure events trigger controlled notifications.
- Bounded alert queue backpressure: priority-preserving eviction, drop tracking.
- Distinct events remain deliverable after cooldown window expires.
- Log and metric accounting under heavy event volume.
"""

from __future__ import annotations

from datetime import datetime
import time
from unittest.mock import MagicMock

import pytest

from device_guardian.alerts.pipeline import AlertResult
from device_guardian.alerts.queue import BoundedAlertQueue
from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.reliability.metrics import get_reliability_metrics, reset_reliability_metrics


class MockStormMonitor(BaseAuthenticationMonitor):
    def is_available(self) -> tuple[bool, str]:
        return True, "MockStormMonitor available"

    def get_source_name(self) -> str:
        return "MockStormMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list:
        return []


def test_alert_storm_burst_suppression() -> None:
    """Verify that an intense burst of 100 failure events produces controlled alerts via cooldown."""
    reset_reliability_metrics()
    metrics = get_reliability_metrics()

    cfg = AppConfig(
        telegram_alert_enabled=False,
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
        auth_failure_threshold=3,
        auth_failure_window_seconds=10.0,
        auth_alert_cooldown_seconds=5.0,
    )

    alert_dispatch_mock = MagicMock(return_value=AlertResult(success=True, reason="Storm Test"))
    det_mgr = DetectionManager(
        config=cfg,
        monitor=MockStormMonitor(),
        alert_dispatcher=alert_dispatch_mock,
    )

    # Inject 100 rapid events
    for i in range(1, 101):
        event = AuthenticationFailureEvent(
            timestamp=datetime.now(),
            platform="storm_test",
            source="MockStormMonitor",
            username=f"attacker_{i}",
            remote_address="192.168.1.100",
            authentication_type="ssh",
            details={"storm_index": i},
        )
        det_mgr.process_event(event)

    # Exactly 1 alert should have been dispatched; subsequent 97 events must not spam alerts
    assert alert_dispatch_mock.call_count == 1
    assert det_mgr.alerts_triggered == 1
    assert det_mgr.alerts_suppressed_by_cooldown > 0

    snap = metrics.snapshot()
    assert snap.events_processed == 100
    assert snap.alerts_delivered == 1
    assert snap.alerts_suppressed_cooldown == det_mgr.alerts_suppressed_by_cooldown


def test_distinct_events_deliverable_after_cooldown() -> None:
    """Verify that distinct security events can trigger alerts once cooldown has elapsed."""
    cfg = AppConfig(
        telegram_alert_enabled=False,
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
        auth_failure_threshold=2,
        auth_failure_window_seconds=10.0,
        auth_alert_cooldown_seconds=0.2,  # Short cooldown for test
    )

    alert_dispatch_mock = MagicMock(return_value=AlertResult(success=True, reason="Cooldown Test"))
    det_mgr = DetectionManager(
        config=cfg,
        monitor=MockStormMonitor(),
        alert_dispatcher=alert_dispatch_mock,
    )

    # Trigger first alert with 2 events
    for i in range(2):
        det_mgr.process_event(
            AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform="test",
                source="MockStormMonitor",
                username="user_a",
                remote_address="10.0.0.1",
                authentication_type="local",
            )
        )
    assert alert_dispatch_mock.call_count == 1

    # Wait for cooldown to expire
    time.sleep(0.25)

    # Trigger second alert with 2 new events
    for i in range(2):
        det_mgr.process_event(
            AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform="test",
                source="MockStormMonitor",
                username="user_b",
                remote_address="10.0.0.2",
                authentication_type="local",
            )
        )
    assert alert_dispatch_mock.call_count == 2
    assert det_mgr.alerts_triggered == 2


def test_bounded_alert_queue_backpressure_and_priority() -> None:
    """Verify BoundedAlertQueue enforces maxsize, tracks drops, and prioritizes urgent alerts."""
    reset_reliability_metrics()
    metrics = get_reliability_metrics()

    queue: BoundedAlertQueue[str] = BoundedAlertQueue(maxsize=3)

    # Push 3 standard priority items (priority=2)
    assert queue.push("item_1", priority=2) is True
    assert queue.push("item_2", priority=2) is True
    assert queue.push("item_3", priority=2) is True
    assert queue.is_full() is True

    # Pushing lower or equal priority item when full is dropped
    assert queue.push("low_item", priority=3) is False

    snap = metrics.snapshot()
    assert snap.queue_dropped_count == 1

    # Pushing higher priority item (priority=0, Critical) evicts a lower priority item
    assert queue.push("critical_item", priority=0) is True
    assert queue.qsize() == 3

    # Dequeue: highest priority (0) should be returned first
    popped = queue.pop(timeout=0.1)
    assert popped == "critical_item"

    queue.close()
    assert queue.is_closed is True
