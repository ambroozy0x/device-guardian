"""Security invariant tests for Phase 10 UX and boundaries."""

from pathlib import Path
import pytest

from device_guardian.config import AppConfig
from device_guardian.recovery.health import HealthStatus
from device_guardian.ux.operator import get_operator_summary, format_operator_dashboard
from device_guardian.ux.status import assert_uncertainty_invariants, format_status_badge


FORBIDDEN_DEPENDENCIES = [
    "torch",
    "tensorflow",
    "keras",
    "sklearn",
    "openai",
    "transformers",
    "telemetry",
    "mixpanel",
    "segment",
]


def test_no_ml_or_telemetry_dependencies():
    """Verify that no AI/ML inference or third-party cloud telemetry packages are imported."""
    src_dir = Path("src/device_guardian")
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pkg in FORBIDDEN_DEPENDENCIES:
            assert f"import {pkg}" not in content, f"Forbidden import '{pkg}' detected in {py_file}"
            assert f"from {pkg}" not in content, f"Forbidden from-import '{pkg}' detected in {py_file}"


def test_no_inbound_network_listeners():
    """Verify no server listening sockets (socket.bind / socket.listen) are introduced."""
    src_dir = Path("src/device_guardian")
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        # Ensure no bind/listen calls that open listening server ports
        assert ".listen(" not in content or "pystray" in content or "test" in str(py_file), (
            f"Potential socket listener found in {py_file}"
        )


def test_no_predictive_threat_scoring_in_operator_surface():
    """Verify that operator status contains zero risk scores, danger levels, or threat probabilities."""
    summary = get_operator_summary()
    dashboard = format_operator_dashboard(summary)

    forbidden_scores = [
        "THREAT SCORE",
        "RISK SCORE",
        "DANGER LEVEL",
        "PROBABILITY OF ATTACK",
        "CRIMINALITY",
        "THREAT LEVEL:",
    ]
    for term in forbidden_scores:
        assert term not in dashboard.upper(), f"Forbidden scoring term '{term}' detected in dashboard"


def test_uncertainty_rules_prevent_false_certainty():
    """Verify that absence of information or configuration never creates false sense of security."""
    # UNKNOWN cannot be converted to SAFE
    with pytest.raises(ValueError, match="Uncertainty violation"):
        assert_uncertainty_invariants("UNKNOWN", "Subsystem is SAFE")

    # NOT_CONFIGURED cannot be converted to PROTECTED
    with pytest.raises(ValueError, match="Uncertainty violation"):
        assert_uncertainty_invariants("NOT_CONFIGURED", "System is PROTECTED")


def test_secret_redaction_in_ux_surfaces():
    """Verify that raw tokens or credentials never appear in operator output."""
    raw_token = "987654:XYZ-SECRET_TOKEN_VALUE_NEVER_LEAK"
    raw_chat = "9988776655"
    config = AppConfig(
        telegram_bot_token=raw_token,
        telegram_chat_id=raw_chat,
    )

    summary = get_operator_summary(config=config)
    dashboard = format_operator_dashboard(summary)

    assert raw_token not in dashboard
    assert raw_chat not in dashboard
    assert "XYZ-SECRET" not in dashboard
