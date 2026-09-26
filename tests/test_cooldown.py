"""Unit tests for AlertCooldownManager."""

from __future__ import annotations

import pytest

from device_guardian.detection.cooldown import AlertCooldownManager


def test_cooldown_manager_validation() -> None:
    """Verify validation on cooldown duration."""
    with pytest.raises(ValueError, match="Cooldown seconds must be non-negative"):
        AlertCooldownManager(cooldown_seconds=-1.0)

    mgr = AlertCooldownManager(cooldown_seconds=300.0)
    assert mgr.cooldown_seconds == 300.0


def test_cooldown_lifecycle() -> None:
    """Verify state transitions before, during, and after cooldown window."""
    mgr = AlertCooldownManager(cooldown_seconds=100.0)

    # Initial state: can alert
    assert mgr.can_alert(current_time=1000.0)
    assert not mgr.is_in_cooldown(current_time=1000.0)
    assert mgr.time_remaining(current_time=1000.0) == 0.0

    # Record alert at t=1000
    mgr.record_alert(current_time=1000.0)

    # Inside cooldown window at t=1050 (50s elapsed < 100s)
    assert not mgr.can_alert(current_time=1050.0)
    assert mgr.is_in_cooldown(current_time=1050.0)
    assert mgr.time_remaining(current_time=1050.0) == 50.0

    # Outside cooldown window at t=1101 (101s elapsed > 100s)
    assert mgr.can_alert(current_time=1101.0)
    assert not mgr.is_in_cooldown(current_time=1101.0)
    assert mgr.time_remaining(current_time=1101.0) == 0.0


def test_cooldown_reset() -> None:
    """Verify reset clears cooldown timer immediately."""
    mgr = AlertCooldownManager(cooldown_seconds=100.0)
    mgr.record_alert(current_time=1000.0)
    assert mgr.is_in_cooldown(current_time=1050.0)

    mgr.reset()
    assert mgr.can_alert(current_time=1050.0)
    assert not mgr.is_in_cooldown(current_time=1050.0)
