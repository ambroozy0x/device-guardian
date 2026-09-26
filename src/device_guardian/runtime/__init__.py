"""Device Guardian runtime package (Phase 5).

Provides background worker lifecycle management, explicit state modeling,
single-instance coordination, and path abstraction.
"""

from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState, RuntimeStatus
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock

__all__ = [
    "ApplicationPaths",
    "GuardianRuntime",
    "RuntimeState",
    "RuntimeStatus",
    "SingleInstanceLock",
]
