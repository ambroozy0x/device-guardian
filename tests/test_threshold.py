"""Unit tests for SlidingWindowThresholdEngine."""

from __future__ import annotations

from datetime import datetime, timedelta
import pytest

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.detection.threshold import SlidingWindowThresholdEngine


def test_threshold_engine_validation() -> None:
    """Verify input validation on threshold and window parameters."""
    with pytest.raises(ValueError, match="Threshold must be at least 1"):
        SlidingWindowThresholdEngine(threshold=0)

    with pytest.raises(ValueError, match="Window seconds must be positive"):
        SlidingWindowThresholdEngine(threshold=3, window_seconds=0)

    engine = SlidingWindowThresholdEngine(threshold=3, window_seconds=60.0)
    assert engine.threshold == 3
    assert engine.window_seconds == 60.0


def test_threshold_engine_accumulates_events_and_triggers() -> None:
    """Verify events trigger when count reaches threshold within window."""
    engine = SlidingWindowThresholdEngine(threshold=3, window_seconds=60.0)
    base_time = datetime(2026, 9, 25, 12, 0, 0)

    ev1 = AuthenticationFailureEvent(timestamp=base_time, username="user1")
    reached1, count1, events1 = engine.record_event(ev1)
    assert not reached1
    assert count1 == 1

    ev2 = AuthenticationFailureEvent(timestamp=base_time + timedelta(seconds=10), username="user1")
    reached2, count2, events2 = engine.record_event(ev2)
    assert not reached2
    assert count2 == 2

    ev3 = AuthenticationFailureEvent(timestamp=base_time + timedelta(seconds=20), username="user1")
    reached3, count3, events3 = engine.record_event(ev3)
    assert reached3
    assert count3 == 3
    assert len(events3) == 3


def test_threshold_engine_slides_window_and_expires_old_events() -> None:
    """Verify events older than window_seconds are removed."""
    engine = SlidingWindowThresholdEngine(threshold=3, window_seconds=30.0)
    t0 = datetime(2026, 9, 25, 12, 0, 0)

    # Event 1 at t=0
    engine.record_event(AuthenticationFailureEvent(timestamp=t0, username="user1"))
    # Event 2 at t=10
    engine.record_event(AuthenticationFailureEvent(timestamp=t0 + timedelta(seconds=10), username="user1"))

    # Event 3 at t=40 (Event 1 at t=0 is 40s ago > 30s window, so it expires)
    reached, count, events = engine.record_event(
        AuthenticationFailureEvent(timestamp=t0 + timedelta(seconds=40), username="user1")
    )
    assert not reached
    assert count == 2
    assert len(events) == 2


def test_threshold_engine_reset() -> None:
    """Verify reset clears tracked events."""
    engine = SlidingWindowThresholdEngine(threshold=2, window_seconds=60.0)
    engine.record_event(AuthenticationFailureEvent(username="u1"))
    assert len(engine.current_events()) == 1

    engine.reset()
    assert len(engine.current_events()) == 0
