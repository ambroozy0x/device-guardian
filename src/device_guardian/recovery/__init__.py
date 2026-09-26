"""Disaster recovery, resilience, and operational hardening package for Device Guardian (Phase 8)."""

from device_guardian.recovery.health import (
    HealthStatus,
    SubsystemHealth,
    SystemHealthReport,
    assess_system_health,
)
from device_guardian.recovery.persistence import (
    AtomicPersistence,
    CorruptedStateError,
    PersistenceError,
)
from device_guardian.recovery.repair import (
    get_recovery_status,
    repair_state_files,
    verify_installation_integrity,
)

__all__ = [
    "AtomicPersistence",
    "PersistenceError",
    "CorruptedStateError",
    "HealthStatus",
    "SubsystemHealth",
    "SystemHealthReport",
    "assess_system_health",
    "verify_installation_integrity",
    "repair_state_files",
    "get_recovery_status",
]
