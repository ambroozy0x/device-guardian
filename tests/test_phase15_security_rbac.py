"""Phase 15 Security Audit — Authorization and Operational RBAC Tests.

Verifies:
- Operational confirmation contracts prevent accidental or unauthorized destructive operations.
- Destructive data purge (--uninstall --remove-data) requires explicit consent.
- Filter rule authority hierarchy strictly enforces safety overrides.
- Operator inspection interfaces strictly mask secrets.
"""

from __future__ import annotations

import pytest

from device_guardian.config import AppConfig
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.models import EnvironmentalContext
from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.models import FilterContext, FilterDecision
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.security.secret import SecretValue
from device_guardian.ux.confirmations import confirm_action


def test_operator_confirmation_contract_rejects_empty_input(monkeypatch) -> None:
    """Verify confirm_action fails safe (rejects) when user inputs empty or negative response."""
    monkeypatch.setattr("builtins.input", lambda _: "")
    result = confirm_action(
        action_name="Uninstall Device Guardian",
        effect="All binaries will be removed.",
        preserved=["User configurations and credentials will be preserved."],
        changed=["Executable files will be deleted."],
        assume_yes=False,
    )
    assert result is False


def test_operator_confirmation_contract_accepts_explicit_yes(monkeypatch) -> None:
    """Verify confirm_action succeeds when explicit 'yes' is provided."""
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    result = confirm_action(
        action_name="Repair Installation",
        effect="Missing directories will be regenerated.",
        preserved=["User configurations and credentials will not be altered."],
        changed=["Runtime directories will be created."],
        assume_yes=False,
    )
    assert result is True


def test_operator_confirmation_bypass_requires_explicit_flag() -> None:
    """Verify assume_yes=True immediately authorizes operation without prompting."""
    result = confirm_action(
        action_name="Automated Script Repair",
        effect="Non-interactive maintenance.",
        preserved=["All data preserved."],
        changed=["Metadata refreshed."],
        assume_yes=True,
    )
    assert result is True


def test_filter_rule_hierarchy_safety_overrides_trusted_context() -> None:
    """Verify synthetic test rule (priority 30) overrides explicit trusted context (priority 40)."""
    engine = SmartFilterEngine(
        trusted_context=TrustedContext(trusted_users=["alice"]),
    )
    ev = AuthenticationFailureEvent(username="alice")
    context = FilterContext(
        event=ev,
        environmental_context=EnvironmentalContext(),
        is_synthetic=True,
        consecutive_failures=3,
        threshold=3,
    )
    decision = engine.evaluate(context)
    # Even though alice is a trusted user, the higher-priority synthetic test rule fires first
    assert decision.decision == FilterDecision.ALERT_ELIGIBLE
    assert decision.rule_id == "RULE_SYNTHETIC_TEST"


def test_operator_config_inspection_masks_all_credentials() -> None:
    """Verify config.to_sanitized_dict() and repr() mask sensitive credentials."""
    raw_token = "123456789:ABCdefGHI_jklMNOpqrsTUVwxyz12345"
    raw_chat = "987654321"
    config = AppConfig(
        telegram_bot_token=SecretValue(raw_token),
        telegram_chat_id=SecretValue(raw_chat),
    )
    sanitized = config.to_sanitized_dict()
    assert raw_token not in sanitized["telegram_bot_token"]
    assert raw_chat not in sanitized["telegram_chat_id"]
    assert "***" in sanitized["telegram_bot_token"]
    assert "***" in str(sanitized["telegram_chat_id"]) or "*****" in str(sanitized["telegram_chat_id"])

    repr_str = repr(config)
    assert raw_token not in repr_str
    assert raw_chat not in repr_str
