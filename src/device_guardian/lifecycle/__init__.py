"""Lifecycle and installer package for Device Guardian (Phase 12).

Provides application installation, upgrade, migration, repair, uninstallation,
and persistent schema versioning.
"""

from .models import (
    InstallationHealth,
    InstallationMetadata,
    LifecycleOperationType,
    LifecycleRecord,
    LifecycleState,
)
from .migration import (
    CURRENT_STATE_SCHEMA_VERSION,
    MigrationManager,
    MigrationResult,
)
from .installer import (
    LifecycleInstaller,
    LifecycleResult,
)

__all__ = [
    "InstallationHealth",
    "InstallationMetadata",
    "LifecycleOperationType",
    "LifecycleRecord",
    "LifecycleState",
    "CURRENT_STATE_SCHEMA_VERSION",
    "MigrationManager",
    "MigrationResult",
    "LifecycleInstaller",
    "LifecycleResult",
]
