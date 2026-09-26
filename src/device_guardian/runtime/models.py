"""Runtime state and status models for Device Guardian (Phase 5).

Represents explicit execution states, health metadata, and lifecycle telemetry.
Adheres strictly to Phase 5 safety:
- Deterministic state transitions.
- No sensitive data or credentials in status representations.
- Thread-safe and process-safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class RuntimeState(str, Enum):
    """Explicit lifecycle states for the background runtime."""

    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    FAILED = "FAILED"


@dataclass
class RuntimeStatus:
    """Detailed operational status of the Device Guardian runtime."""

    state: RuntimeState = RuntimeState.STOPPED
    pid: Optional[int] = None
    started_at: Optional[datetime] = None
    last_detection_cycle: Optional[datetime] = None
    total_events_processed: int = 0
    alerts_triggered: int = 0
    alerts_suppressed_by_cooldown: int = 0
    alerts_suppressed_by_filter: int = 0
    restart_count: int = 0
    last_error: Optional[str] = None
    startup_enabled: bool = False
    single_instance_active: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def uptime_seconds(self) -> float:
        """Calculate runtime uptime in seconds."""
        if self.started_at is None or self.state not in {RuntimeState.RUNNING, RuntimeState.STOPPING}:
            return 0.0
        return (datetime.now() - self.started_at).total_seconds()

    @property
    def formatted_uptime(self) -> str:
        """Format uptime into human-readable HH:MM:SS."""
        total_seconds = int(self.uptime_seconds)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def is_running(self) -> bool:
        """Check if runtime is in active running state."""
        return self.state == RuntimeState.RUNNING

    def format_human_readable(self) -> str:
        """Produce a clean, factual, human-readable status overview."""
        cycle_str = (
            self.last_detection_cycle.isoformat()
            if self.last_detection_cycle
            else "Never"
        )
        pid_str = str(self.pid) if self.pid else "None"
        health_str = "HEALTHY" if self.state == RuntimeState.RUNNING else self.state.value

        lines = [
            "Device Guardian Runtime Status",
            "==============================",
            f"Runtime State:        {self.state.value}",
            f"Process PID:          {pid_str}",
            f"Uptime:               {self.formatted_uptime}",
            f"Health:               {health_str}",
            f"Startup Enabled:      {'YES' if self.startup_enabled else 'NO'}",
            f"Instance Locked:      {'YES' if self.single_instance_active else 'NO'}",
            f"Restarts Count:       {self.restart_count}",
            f"Last Detection Cycle: {cycle_str}",
            f"Events Processed:     {self.total_events_processed}",
            f"Alerts Dispatched:    {self.alerts_triggered}",
            f"Alerts Filtered:      {self.alerts_suppressed_by_filter}",
            f"Cooldown Suppressed:  {self.alerts_suppressed_by_cooldown}",
        ]
        if self.last_error:
            lines.append(f"Last Error:           {self.last_error}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize status for machine-readable queries."""
        return {
            "state": self.state.value,
            "pid": self.pid,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": self.uptime_seconds,
            "formatted_uptime": self.formatted_uptime,
            "last_detection_cycle": self.last_detection_cycle.isoformat() if self.last_detection_cycle else None,
            "total_events_processed": self.total_events_processed,
            "alerts_triggered": self.alerts_triggered,
            "alerts_suppressed_by_filter": self.alerts_suppressed_by_filter,
            "alerts_suppressed_by_cooldown": self.alerts_suppressed_by_cooldown,
            "restart_count": self.restart_count,
            "last_error": self.last_error,
            "startup_enabled": self.startup_enabled,
            "single_instance_active": self.single_instance_active,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeStatus:
        """Construct RuntimeStatus safely from a dictionary."""
        if not isinstance(data, dict):
            return cls(state=RuntimeState.STOPPED, last_error="Corrupted status data recovered.")

        raw_state = data.get("state", RuntimeState.STOPPED.value)
        try:
            state = RuntimeState(raw_state)
        except ValueError:
            state = RuntimeState.STOPPED

        started_at = None
        if data.get("started_at"):
            try:
                started_at = datetime.fromisoformat(data["started_at"])
            except Exception:
                pass

        last_cycle = None
        if data.get("last_detection_cycle"):
            try:
                last_cycle = datetime.fromisoformat(data["last_detection_cycle"])
            except Exception:
                pass

        return cls(
            state=state,
            pid=data.get("pid"),
            started_at=started_at,
            last_detection_cycle=last_cycle,
            total_events_processed=data.get("total_events_processed", 0),
            alerts_triggered=data.get("alerts_triggered", 0),
            alerts_suppressed_by_filter=data.get("alerts_suppressed_by_filter", 0),
            alerts_suppressed_by_cooldown=data.get("alerts_suppressed_by_cooldown", 0),
            restart_count=data.get("restart_count", 0),
            last_error=data.get("last_error"),
            startup_enabled=data.get("startup_enabled", False),
            single_instance_active=data.get("single_instance_active", False),
            details=data.get("details", {}),
        )

    @classmethod
    def load(cls, file_path: Optional[Any] = None) -> RuntimeStatus:
        """Load RuntimeStatus from disk using crash-resilient atomic safe read."""
        from device_guardian.recovery.persistence import AtomicPersistence
        from device_guardian.runtime.paths import ApplicationPaths

        path = file_path or ApplicationPaths.get_status_file_path()
        data, recovered, err = AtomicPersistence.safe_read_json(
            file_path=path,
            default={"state": RuntimeState.STOPPED.value},
            allow_backup_fallback=True,
        )
        status = cls.from_dict(data)
        if err and not recovered:
            status.last_error = f"Status file recovery notice: {err}"
        return status
