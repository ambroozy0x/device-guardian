"""Configuration validation and diagnostic readiness reporting for Device Guardian (Phase 6).

Provides structured evaluation across all functional subsystems, distinguishing:
- VALID (healthy and operational)
- MISSING (required value or credential is absent)
- INVALID (syntax or format error)
- DISABLED (subsystem explicitly turned off by configuration)
- NOT_AVAILABLE (underlying OS or hardware dependency missing)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from device_guardian.config import AppConfig


class ValidationState(str, Enum):
    """Evaluation status for a subsystem configuration."""

    VALID = "VALID"
    MISSING = "MISSING"
    INVALID = "INVALID"
    DISABLED = "DISABLED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class SubsystemValidation:
    """Validation report for a single functional subsystem."""

    name: str
    state: ValidationState
    message: str
    is_critical: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_healthy(self) -> bool:
        """Evaluate if the subsystem state satisfies operational requirements."""
        return self.state in {ValidationState.VALID, ValidationState.DISABLED}


@dataclass
class ConfigValidationReport:
    """Comprehensive multi-subsystem configuration audit report."""

    subsystems: list[SubsystemValidation] = field(default_factory=list)
    action_guidance: list[str] = field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        """Check if all critical subsystems are valid or safely disabled."""
        return all(sub.is_healthy for sub in self.subsystems if sub.is_critical)

    @property
    def overall_status(self) -> str:
        """Human-readable overall status."""
        return "READY" if self.is_ready else "NOT READY"

    @property
    def recommended_action(self) -> Optional[str]:
        """Formatted recommendation for resolving configuration issues."""
        if self.action_guidance:
            return "\n".join(self.action_guidance)
        return None

    def format_report(self) -> str:
        """Produce a clean, professional, non-leaking diagnostic summary."""
        lines = [
            "Configuration Validation",
            "------------------------",
        ]
        for sub in self.subsystems:
            status_tag = sub.state.value
            if sub.state == ValidationState.VALID:
                status_display = "PASS"
            elif sub.state == ValidationState.DISABLED:
                status_display = "DISABLED"
            elif sub.state == ValidationState.MISSING:
                status_display = "MISSING"
            elif sub.state == ValidationState.INVALID:
                status_display = "INVALID"
            else:
                status_display = "NOT AVAILABLE"

            lines.append(f"{sub.name:<25}: {status_display} ({sub.message})")

        lines.append(f"\nOverall Status: {self.overall_status}")

        if self.action_guidance:
            lines.append("\nRecommended Action:")
            for action in self.action_guidance:
                lines.append(f"  * {action}")

        return "\n".join(lines)


def validate_subsystems(config: AppConfig) -> ConfigValidationReport:
    """Perform a structured, non-leaking audit across all Device Guardian subsystems.

    Args:
        config: The AppConfig instance to validate.

    Returns:
        ConfigValidationReport containing subsystem verdicts and actionable guidance.
    """
    report = ConfigValidationReport()

    # 1. Application & Paths
    report.subsystems.append(
        SubsystemValidation(
            name="Application",
            state=ValidationState.VALID,
            message="Base configuration parameters loaded",
            is_critical=True,
            details={"log_level": config.log_level},
        )
    )

    # 2. Runtime
    runtime_ok = (config.max_restart_attempts >= 0 and config.restart_backoff_seconds >= 0)
    report.subsystems.append(
        SubsystemValidation(
            name="Runtime",
            state=ValidationState.VALID if runtime_ok else ValidationState.INVALID,
            message="Restart recovery and single instance parameters valid" if runtime_ok else "Negative restart parameters",
            is_critical=True,
        )
    )

    # 3. Detection Engine & Thresholds
    threshold_ok = (config.auth_failure_threshold >= 1 and config.auth_failure_window_seconds > 0)
    report.subsystems.append(
        SubsystemValidation(
            name="Detection Engine",
            state=ValidationState.VALID if threshold_ok else ValidationState.INVALID,
            message=f"Threshold: {config.auth_failure_threshold} failures in {config.auth_failure_window_seconds:.0f}s" if threshold_ok else "Threshold must be >= 1",
            is_critical=True,
        )
    )

    # 4. Security & Smart Filtering
    filtering_enabled = config.smart_filtering_enabled
    report.subsystems.append(
        SubsystemValidation(
            name="Smart Filtering",
            state=ValidationState.VALID if filtering_enabled else ValidationState.DISABLED,
            message="Deterministic rules active" if filtering_enabled else "Filtering disabled",
            is_critical=False,
            details={"trusted_users_count": len(config.trusted_users)},
        )
    )

    # 5. Telegram Notifications & Credentials
    _PLACEHOLDERS = {
        "your_telegram_bot_token_here",
        "YOUR_BOT_TOKEN",
        "CHANGE_ME",
        "your_telegram_chat_id_here",
        "YOUR_CHAT_ID",
        "",
    }

    if not config.telegram_alert_enabled:
        report.subsystems.append(
            SubsystemValidation(
                name="Telegram Notifications",
                state=ValidationState.DISABLED,
                message="Alert dispatch to Telegram is explicitly disabled",
                is_critical=False,
            )
        )
    else:
        # Check token
        token_str = (
            config.telegram_bot_token.get_secret_value()
            if hasattr(config.telegram_bot_token, "get_secret_value")
            else str(config.telegram_bot_token or "")
        ).strip()

        chat_id_str = (
            config.telegram_chat_id.get_secret_value()
            if hasattr(config.telegram_chat_id, "get_secret_value")
            else str(config.telegram_chat_id or "")
        ).strip()

        token_missing = (not token_str or token_str in _PLACEHOLDERS)
        chat_missing = (not chat_id_str or chat_id_str in _PLACEHOLDERS)

        if token_missing or chat_missing:
            msg_parts = []
            if token_missing:
                msg_parts.append("bot token is missing")
            if chat_missing:
                msg_parts.append("chat ID is missing")
            report.subsystems.append(
                SubsystemValidation(
                    name="Telegram Credentials",
                    state=ValidationState.MISSING,
                    message=" and ".join(msg_parts).capitalize(),
                    is_critical=True,
                )
            )
            report.action_guidance.append(
                "Run 'device-guardian --setup' or configure TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env."
            )
        else:
            # Validate basic format
            # Telegram bot token format: <digits>:<alphanumeric>
            token_valid = ":" in token_str and len(token_str) > 20
            if not token_valid:
                report.subsystems.append(
                    SubsystemValidation(
                        name="Telegram Credentials",
                        state=ValidationState.INVALID,
                        message="Token format appears malformed (expected digits:alphanumeric).",
                        is_critical=True,
                    )
                )
                report.action_guidance.append(
                    "Obtain a valid HTTP API token from @BotFather on Telegram."
                )
            else:
                report.subsystems.append(
                    SubsystemValidation(
                        name="Telegram Credentials",
                        state=ValidationState.VALID,
                        message="Configured with valid format",
                        is_critical=True,
                    )
                )

    # 6. Hardware & Network Sensors
    if not getattr(config, "camera_alert_enabled", True):
        report.subsystems.append(
            SubsystemValidation(
                name="Hardware Camera",
                state=ValidationState.DISABLED,
                message="Camera alerts disabled in configuration",
                is_critical=False,
            )
        )
    else:
        cam_ok = (config.camera_index >= 0)
        report.subsystems.append(
            SubsystemValidation(
                name="Hardware Camera",
                state=ValidationState.VALID if cam_ok else ValidationState.INVALID,
                message=f"Configured camera device index: {config.camera_index}" if cam_ok else "Negative camera index",
                is_critical=False,
            )
        )

    if not getattr(config, "location_alert_enabled", True):
        report.subsystems.append(
            SubsystemValidation(
                name="Geolocation API",
                state=ValidationState.DISABLED,
                message="Location alerts disabled in configuration",
                is_critical=False,
            )
        )
    else:
        loc_url_ok = config.location_api_url.startswith(("http://", "https://"))
        report.subsystems.append(
            SubsystemValidation(
                name="Geolocation API",
                state=ValidationState.VALID if loc_url_ok else ValidationState.INVALID,
                message="Valid HTTP/HTTPS endpoint" if loc_url_ok else "Invalid API URL protocol",
                is_critical=False,
            )
        )

    return report
