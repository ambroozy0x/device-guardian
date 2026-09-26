"""Structured health model and diagnostic evaluation for Device Guardian (Phase 8).

Adheres strictly to Phase 8 principles:
- Deterministic subsystem states (HEALTHY, DEGRADED, FAILED, UNKNOWN, NOT_CONFIGURED).
- Strictly descriptive, non-predictive.
- NO threat scores, risk scores, danger levels, or predictive analytics.
- DEGRADED indicates limited functionality, NOT system compromise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import platform
import sys
from typing import Any, Optional

from device_guardian.config import AppConfig, load_config
from device_guardian.logger import get_logger
from device_guardian.runtime.models import RuntimeState
from device_guardian.runtime.paths import ApplicationPaths

logger = get_logger("recovery.health")


class HealthStatus(str, Enum):
    """Deterministic status states for subsystems."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    NOT_CONFIGURED = "NOT_CONFIGURED"


@dataclass
class SubsystemHealth:
    """Health evaluation for an individual subsystem."""

    name: str
    status: HealthStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemHealthReport:
    """Comprehensive system-wide health evaluation report."""

    subsystems: list[SubsystemHealth] = field(default_factory=list)
    timestamp: str = ""

    @property
    def overall_status(self) -> HealthStatus:
        """Derive overall system health deterministically without heuristic scoring."""
        statuses = {s.status for s in self.subsystems}
        if HealthStatus.FAILED in statuses:
            return HealthStatus.FAILED
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if HealthStatus.UNKNOWN in statuses:
            return HealthStatus.UNKNOWN
        if all(s == HealthStatus.NOT_CONFIGURED for s in statuses):
            return HealthStatus.NOT_CONFIGURED
        return HealthStatus.HEALTHY

    @property
    def status(self) -> HealthStatus:
        """Alias for overall_status."""
        return self.overall_status

    def format_report(self) -> str:
        """Produce a factual, human-readable health overview."""
        lines = [
            "=" * 65,
            "         DEVICE GUARDIAN - SUBSYSTEM HEALTH REPORT",
            "=" * 65,
            f"Overall System Health: {self.overall_status.value}",
            "-" * 65,
        ]
        for sub in self.subsystems:
            status_tag = f"[{sub.status.value}]".ljust(18)
            lines.append(f"{sub.name:<24} : {status_tag} {sub.message}")

        lines.append("-" * 65)
        lines.append("Note: Health reflects operational status. DEGRADED means functional")
        lines.append("fallback is active; it does not indicate system compromise.")
        lines.append("=" * 65)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON queries."""
        return {
            "status": self.overall_status.value,
            "overall_status": self.overall_status.value,
            "timestamp": self.timestamp,
            "subsystems": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "message": s.message,
                    "details": s.details,
                }
                for s in self.subsystems
            ],
        }


def assess_system_health(config: Optional[AppConfig] = None) -> SystemHealthReport:
    """Audit all core subsystems and construct a deterministic health report.

    Args:
        config: Optional loaded configuration.

    Returns:
        SystemHealthReport instance.
    """
    from datetime import datetime, timezone
    report = SystemHealthReport(timestamp=datetime.now(timezone.utc).isoformat())

    # 1. Configuration Subsystem
    cfg = config
    if cfg is None:
        try:
            cfg = load_config()
        except Exception as exc:
            report.subsystems.append(
                SubsystemHealth(
                    name="Configuration",
                    status=HealthStatus.FAILED,
                    message=f"Configuration error: {exc}",
                )
            )
            cfg = None

    if cfg is not None:
        val_rep = cfg.validate_readiness()
        if val_rep.is_ready:
            report.subsystems.append(
                SubsystemHealth(
                    name="Configuration",
                    status=HealthStatus.HEALTHY,
                    message="Configuration loaded and validated cleanly.",
                )
            )
        else:
            unhealthy = [s.name for s in val_rep.subsystems if not s.is_healthy]
            report.subsystems.append(
                SubsystemHealth(
                    name="Configuration",
                    status=HealthStatus.DEGRADED,
                    message=f"Configuration issues detected in {len(unhealthy)} subsystem(s): {', '.join(unhealthy)}.",
                )
            )

    # 2. Secret Storage Subsystem
    try:
        from device_guardian.security.store import create_default_secret_store
        sec_store = create_default_secret_store()
        backend = sec_store.get_backend_name()
        has_token = sec_store.has_secret("telegram_bot_token")
        report.subsystems.append(
            SubsystemHealth(
                name="Secret Store",
                status=HealthStatus.HEALTHY,
                message=f"Active backend: {backend}",
                details={"backend": backend, "has_token": has_token},
            )
        )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Secret Store",
                status=HealthStatus.DEGRADED,
                message=f"Storage backend degraded: {exc}",
            )
        )

    # 3. Detection Monitor Subsystem
    try:
        from device_guardian.detection.manager import DetectionManager
        from device_guardian.detection.models import DetectionStatus
        det_mgr = DetectionManager(config=cfg)
        mon_stat, mon_msg = det_mgr.get_monitor_status()
        if mon_stat == DetectionStatus.READY:
            report.subsystems.append(
                SubsystemHealth(
                    name="Detection Monitor",
                    status=HealthStatus.HEALTHY,
                    message=f"Active log monitor: {det_mgr.monitor.get_source_name()}",
                )
            )
        else:
            report.subsystems.append(
                SubsystemHealth(
                    name="Detection Monitor",
                    status=HealthStatus.DEGRADED,
                    message=f"Monitor unavailable ({mon_msg})",
                )
            )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Detection Monitor",
                status=HealthStatus.FAILED,
                message=f"Detection subsystem error: {exc}",
            )
        )

    # 4. Camera Sensor Subsystem
    try:
        import cv2
        idx = cfg.camera_index if cfg else 0
        cap = cv2.VideoCapture(idx)
        if cap.isOpened():
            cap.release()
            report.subsystems.append(
                SubsystemHealth(
                    name="Camera Sensor",
                    status=HealthStatus.HEALTHY,
                    message=f"Camera index {idx} accessible.",
                )
            )
        else:
            report.subsystems.append(
                SubsystemHealth(
                    name="Camera Sensor",
                    status=HealthStatus.DEGRADED,
                    message=f"Camera index {idx} unavailable or in use.",
                )
            )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Camera Sensor",
                status=HealthStatus.UNKNOWN,
                message=f"Camera check error: {exc}",
            )
        )

    # 5. Geolocation Sensor Subsystem
    try:
        from device_guardian.location.geolocation import get_approximate_location
        loc_url = cfg.location_api_url if cfg else "https://ipapi.co/json/"
        loc = get_approximate_location(api_url=loc_url, timeout=3.0)
        if loc.is_available:
            report.subsystems.append(
                SubsystemHealth(
                    name="Geolocation Sensor",
                    status=HealthStatus.HEALTHY,
                    message=f"IP location reachable ({loc.city}, {loc.country}).",
                )
            )
        else:
            report.subsystems.append(
                SubsystemHealth(
                    name="Geolocation Sensor",
                    status=HealthStatus.UNKNOWN,
                    message="Geolocation service unreachable or returned no data.",
                )
            )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Geolocation Sensor",
                status=HealthStatus.UNKNOWN,
                message=f"Geolocation query error: {exc}",
            )
        )

    # 6. Telegram Channel Subsystem
    if cfg and cfg.telegram_bot_token and cfg.telegram_chat_id:
        try:
            from device_guardian.telegram.bot import TelegramClient
            tg = TelegramClient(cfg.telegram_bot_token, cfg.telegram_chat_id, timeout=3.0)
            verify_resp = tg.verify_credentials()
            if verify_resp.success:
                report.subsystems.append(
                    SubsystemHealth(
                        name="Telegram Channel",
                        status=HealthStatus.HEALTHY,
                        message="Telegram Bot credentials verified.",
                    )
                )
            else:
                report.subsystems.append(
                    SubsystemHealth(
                        name="Telegram Channel",
                        status=HealthStatus.DEGRADED,
                        message=f"Telegram API rejected: {verify_resp.error_message}",
                    )
                )
        except Exception as exc:
            report.subsystems.append(
                SubsystemHealth(
                    name="Telegram Channel",
                    status=HealthStatus.DEGRADED,
                    message=f"Telegram connection error: {exc}",
                )
            )
    else:
        report.subsystems.append(
            SubsystemHealth(
                name="Telegram Channel",
                status=HealthStatus.NOT_CONFIGURED,
                message="Telegram bot token or chat ID not configured.",
            )
        )

    # 7. Update Subsystem
    try:
        from device_guardian.updates.installer import UpdateInstaller
        from device_guardian.updates.transaction import TransactionState, UpdateTransaction
        txn = UpdateTransaction.load()
        if txn.state == TransactionState.ROLLBACK_REQUIRED:
            report.subsystems.append(
                SubsystemHealth(
                    name="Update Subsystem",
                    status=HealthStatus.DEGRADED,
                    message="Interrupted transaction detected: Rollback required.",
                )
            )
        elif txn.state in {TransactionState.INSTALL_FAILED, TransactionState.VERIFICATION_FAILED}:
            report.subsystems.append(
                SubsystemHealth(
                    name="Update Subsystem",
                    status=HealthStatus.DEGRADED,
                    message=f"Previous update failed: {txn.error_message or txn.state.value}",
                )
            )
        else:
            report.subsystems.append(
                SubsystemHealth(
                    name="Update Subsystem",
                    status=HealthStatus.HEALTHY,
                    message=f"Transaction state: {txn.state.value}",
                )
            )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Update Subsystem",
                status=HealthStatus.UNKNOWN,
                message=f"Could not inspect update subsystem: {exc}",
            )
        )

    # 8. Single Instance Coordination
    try:
        from device_guardian.runtime.single_instance import SingleInstanceLock
        lock = SingleInstanceLock()
        is_locked = lock.is_locked()
        pid = lock.get_active_pid()
        report.subsystems.append(
            SubsystemHealth(
                name="Single Instance Lock",
                status=HealthStatus.HEALTHY,
                message=f"Lock operational ({'Active PID ' + str(pid) if is_locked else 'Unlocked'}).",
            )
        )
    except Exception as exc:
        report.subsystems.append(
            SubsystemHealth(
                name="Single Instance Lock",
                status=HealthStatus.DEGRADED,
                message=f"Lock inspection error: {exc}",
            )
        )

    return report
