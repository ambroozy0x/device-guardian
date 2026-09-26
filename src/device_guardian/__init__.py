"""Device Guardian - Core PC Alert Pipeline.

A zero-cost, personal-use anti-theft & intrusion alert system for PC and Android.
Phase 1: PC Core Alert Pipeline.
"""

from device_guardian.platform_compat import (
    Architecture,
    OperatingSystem,
    PlatformInfo,
    PlatformSupportTier,
    get_platform_info,
)
from device_guardian.version import (
    SemanticVersion,
    VersionInfo,
    __version__,
    get_version_info,
)

__all__ = [
    "Architecture",
    "OperatingSystem",
    "PlatformInfo",
    "PlatformSupportTier",
    "SemanticVersion",
    "VersionInfo",
    "__version__",
    "get_platform_info",
    "get_version_info",
]
