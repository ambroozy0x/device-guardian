"""Centralized authoritative version and release metadata for Device Guardian (Phase 7).

This is the single source of truth for the application version.
Build tooling, release manifests, packaging specs, and CLI commands derive
version information from this module.
"""

from __future__ import annotations

from dataclasses import dataclass
import platform
import re
import sys
from typing import Optional

__version__ = "0.1.0"

_SEMVER_PATTERN = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<buildmetadata>[0-9A-Za-z.-]+))?$"
)


@dataclass(frozen=True)
class SemanticVersion:
    """Represents a validated Semantic Version 2.0.0."""

    major: int
    minor: int
    patch: int
    prerelease: Optional[str] = None
    raw: str = ""

    @classmethod
    def parse(cls, version_str: str) -> SemanticVersion:
        """Parse a semantic version string (e.g. '0.1.0', '1.2.3-rc1').

        Args:
            version_str: Version string to parse (leading 'v' is stripped).

        Raises:
            ValueError: If the version string does not conform to semver.
        """
        clean = version_str.strip().lstrip("v")
        match = _SEMVER_PATTERN.match(clean)
        if not match:
            raise ValueError(f"Invalid semantic version string: '{version_str}'")

        groups = match.groupdict()
        return cls(
            major=int(groups["major"]),
            minor=int(groups["minor"]),
            patch=int(groups["patch"]),
            prerelease=groups["prerelease"],
            raw=version_str.strip(),
        )

    def _sort_key(self) -> tuple:
        """Generate sort key for semantic version comparison."""
        # Prerelease versions have lower precedence than normal releases (RFC 2.0.0 §11)
        # Empty string indicates normal release (sorts after any prerelease)
        has_prerelease = 0 if self.prerelease is not None else 1
        return (self.major, self.minor, self.patch, has_prerelease, self.prerelease or "")

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._sort_key() <= other._sort_key()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._sort_key() > other._sort_key()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._sort_key() >= other._sort_key()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SemanticVersion):
            return (self.major, self.minor, self.patch, self.prerelease) == (
                other.major,
                other.minor,
                other.patch,
                other.prerelease,
            )
        if isinstance(other, str):
            try:
                parsed = SemanticVersion.parse(other)
                return self == parsed
            except ValueError:
                return False
        return False

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += f"-{self.prerelease}"
        return base

    def is_downgrade_from(self, installed: SemanticVersion) -> bool:
        """Check if this version represents a downgrade compared to installed version."""
        return self < installed


@dataclass(frozen=True)
class VersionInfo:
    """Non-telemetric, structured release information model."""

    version: str
    release_id: str
    build_id: str
    build_timestamp: str
    platform: str
    architecture: str
    packaging_format: str
    git_commit: Optional[str] = None

    def to_dict(self) -> dict[str, str]:
        """Convert version info to dictionary for manifests or diagnostic output."""
        data = {
            "version": self.version,
            "release_id": self.release_id,
            "build_id": self.build_id,
            "build_timestamp": self.build_timestamp,
            "platform": self.platform,
            "architecture": self.architecture,
            "packaging_format": self.packaging_format,
        }
        if self.git_commit:
            data["git_commit"] = self.git_commit
        return data


def current_version() -> str:
    """Return the authoritative application version string."""
    return __version__


def parse_version(version_str: str) -> SemanticVersion:
    """Parse a semantic version string into a SemanticVersion instance."""
    return SemanticVersion.parse(version_str)


def compare_versions(v1: str | SemanticVersion, v2: str | SemanticVersion) -> int:
    """Compare two semantic versions strictly.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    sv1 = v1 if isinstance(v1, SemanticVersion) else SemanticVersion.parse(v1)
    sv2 = v2 if isinstance(v2, SemanticVersion) else SemanticVersion.parse(v2)
    if sv1 < sv2:
        return -1
    elif sv1 > sv2:
        return 1
    return 0


def get_current_semantic_version() -> SemanticVersion:
    """Get the current application semantic version."""
    return SemanticVersion.parse(__version__)



def get_version_info(
    build_timestamp: Optional[str] = None,
    git_commit: Optional[str] = None,
) -> VersionInfo:
    """Construct structured VersionInfo for current runtime environment.

    Does NOT collect user identifiers, hostnames, IP addresses, or telemetry.
    """
    is_frozen = getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
    packaging_format = "PyInstaller Standalone Executable" if is_frozen else "Python Source Package"

    # Normalized platform and architecture
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        arch = machine

    release_id = f"DG-{__version__}-{sys_name}-{arch}"
    build_id = f"bld-{__version__}"

    return VersionInfo(
        version=__version__,
        release_id=release_id,
        build_id=build_id,
        build_timestamp=build_timestamp or "2026-09-26T00:00:00Z",
        platform=sys_name,
        architecture=arch,
        packaging_format=packaging_format,
        git_commit=git_commit,
    )
