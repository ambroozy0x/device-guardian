"""Cross-platform compatibility and system abstraction layer for Device Guardian (Phase 13).

Provides centralized, deterministic platform and architecture identification,
support evaluation, and execution environment characterization:
- Native detection for Windows, Linux, and macOS.
- Unified Architecture detection (x64, arm64, x86).
- Platform support tier classification (Tier 1 Verified vs Tier 2 Compatible vs Unsupported).
- Deterministic override mechanisms for cross-platform simulation and testing.
- Platform capabilities introspection (secrets, locking, startup, sensors, logging).
- POSIX and Windows filesystem permission verification and hardening helpers.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import platform
import stat
import sys
from typing import Any, Generator, Optional, Union

from device_guardian.logger import get_logger

logger = get_logger("platform_compat")


class OperatingSystem(str, Enum):
    """Supported operating systems."""

    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    UNSUPPORTED = "unsupported"

    @classmethod
    def from_string(cls, val: Optional[str]) -> OperatingSystem:
        """Parse arbitrary OS string into standard OperatingSystem enum."""
        if not val:
            return cls.UNSUPPORTED
        normalized = val.strip().lower()
        if "darwin" in normalized or "mac" in normalized or "osx" in normalized:
            return cls.MACOS
        elif normalized in {"windows", "win32", "win64", "win"} or normalized.startswith("win"):
            return cls.WINDOWS
        elif "linux" in normalized:
            return cls.LINUX
        return cls.UNSUPPORTED


class Architecture(str, Enum):
    """Processor architectures."""

    X64 = "x64"
    ARM64 = "arm64"
    X86 = "x86"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, val: Optional[str]) -> Architecture:
        """Parse machine/processor architecture string into Architecture enum."""
        if not val:
            return cls.UNKNOWN
        normalized = val.strip().lower()
        if normalized in {"x86_64", "amd64", "x64", "em64t"}:
            return cls.X64
        elif normalized in {"aarch64", "arm64", "armv8l", "armv9l"}:
            return cls.ARM64
        elif normalized in {"i386", "i686", "x86", "i86pc"}:
            return cls.X86
        return cls.UNKNOWN


class PlatformSupportTier(str, Enum):
    """Support and verification tiers for operating systems."""

    TIER_1_PRIMARY = "Tier 1 (Host Verified: Windows 11 x64)"
    TIER_2_COMPATIBLE = "Tier 2 (Simulated / Spec Compatible: Linux x64/arm64)"
    TIER_2_MACOS = "Tier 2 (Simulated / Spec Compatible: macOS x64/arm64)"
    UNSUPPORTED = "Unsupported Platform"


@dataclass(frozen=True)
class PlatformInfo:
    """Immutable snapshot of the platform execution environment."""

    os: OperatingSystem
    os_name: str
    release: str
    version: str
    arch: Architecture
    machine: str
    python_version: str
    is_frozen: bool
    is_windows: bool
    is_linux: bool
    is_macos: bool
    is_supported: bool
    executable_name: str
    support_tier: PlatformSupportTier

    def to_dict(self) -> dict[str, Any]:
        """Convert platform info to structured dictionary."""
        return {
            "os": self.os.value,
            "os_name": self.os_name,
            "release": self.release,
            "version": self.version,
            "arch": self.arch.value,
            "machine": self.machine,
            "python_version": self.python_version,
            "is_frozen": self.is_frozen,
            "is_windows": self.is_windows,
            "is_linux": self.is_linux,
            "is_macos": self.is_macos,
            "is_supported": self.is_supported,
            "executable_name": self.executable_name,
            "support_tier": self.support_tier.value,
        }


# Global test overrides
_os_override: Optional[OperatingSystem] = None
_arch_override: Optional[Architecture] = None


def set_platform_override(os_type: Optional[Union[OperatingSystem, str]]) -> None:
    """Override current operating system for test isolation. Pass None to reset."""
    global _os_override
    if os_type is None:
        _os_override = None
    elif isinstance(os_type, OperatingSystem):
        _os_override = os_type
    else:
        _os_override = OperatingSystem.from_string(os_type)


def set_arch_override(arch_type: Optional[Union[Architecture, str]]) -> None:
    """Override current architecture for test isolation. Pass None to reset."""
    global _arch_override
    if arch_type is None:
        _arch_override = None
    elif isinstance(arch_type, Architecture):
        _arch_override = arch_type
    else:
        _arch_override = Architecture.from_string(arch_type)


def reset_platform_overrides() -> None:
    """Reset all active platform and architecture test overrides."""
    global _os_override, _arch_override
    _os_override = None
    _arch_override = None


@contextmanager
def platform_override(
    os_type: Optional[Union[OperatingSystem, str]] = None,
    arch_type: Optional[Union[Architecture, str]] = None,
) -> Generator[None, None, None]:
    """Context manager for temporary platform and architecture overrides in tests."""
    global _os_override, _arch_override
    prev_os = _os_override
    prev_arch = _arch_override
    try:
        set_platform_override(os_type)
        if arch_type is not None:
            set_arch_override(arch_type)
        yield
    finally:
        _os_override = prev_os
        _arch_override = prev_arch


def get_current_os() -> OperatingSystem:
    """Return the active OperatingSystem enum, respecting test overrides."""
    if _os_override is not None:
        return _os_override
    return OperatingSystem.from_string(platform.system())


def get_current_arch() -> Architecture:
    """Return the active Architecture enum, respecting test overrides."""
    if _arch_override is not None:
        return _arch_override
    return Architecture.from_string(platform.machine())


def is_windows() -> bool:
    """Check if the active OS is Windows."""
    return get_current_os() == OperatingSystem.WINDOWS


def is_linux() -> bool:
    """Check if the active OS is Linux."""
    return get_current_os() == OperatingSystem.LINUX


def is_macos() -> bool:
    """Check if the active OS is macOS."""
    return get_current_os() == OperatingSystem.MACOS


def is_supported_platform() -> bool:
    """Check if the active OS is supported by Device Guardian."""
    return get_current_os() in {
        OperatingSystem.WINDOWS,
        OperatingSystem.LINUX,
        OperatingSystem.MACOS,
    }


def get_executable_name(os_type: Optional[OperatingSystem] = None) -> str:
    """Return standard binary executable name for the specified or current OS."""
    target_os = os_type or get_current_os()
    if target_os == OperatingSystem.WINDOWS:
        return "device-guardian.exe"
    return "device-guardian"


def get_platform_support_tier(os_type: Optional[OperatingSystem] = None) -> PlatformSupportTier:
    """Evaluate support tier for the specified or current OS."""
    target_os = os_type or get_current_os()
    if target_os == OperatingSystem.WINDOWS:
        return PlatformSupportTier.TIER_1_PRIMARY
    elif target_os == OperatingSystem.LINUX:
        return PlatformSupportTier.TIER_2_COMPATIBLE
    elif target_os == OperatingSystem.MACOS:
        return PlatformSupportTier.TIER_2_MACOS
    return PlatformSupportTier.UNSUPPORTED


def is_frozen_executable() -> bool:
    """Check if running as a packaged PyInstaller binary."""
    return getattr(sys, "frozen", False) and (
        hasattr(sys, "_MEIPASS") or getattr(sys, "executable", "").lower().endswith(".exe")
    )


def get_platform_info() -> PlatformInfo:
    """Obtain a comprehensive PlatformInfo instance describing the execution host."""
    curr_os = get_current_os()
    curr_arch = get_current_arch()
    frozen = is_frozen_executable()
    tier = get_platform_support_tier(curr_os)

    return PlatformInfo(
        os=curr_os,
        os_name=curr_os.value,
        release=platform.release() if _os_override is None else "simulated",
        version=platform.version() if _os_override is None else "1.0",
        arch=curr_arch,
        machine=platform.machine() if _arch_override is None else curr_arch.value,
        python_version=sys.version.split()[0],
        is_frozen=frozen,
        is_windows=(curr_os == OperatingSystem.WINDOWS),
        is_linux=(curr_os == OperatingSystem.LINUX),
        is_macos=(curr_os == OperatingSystem.MACOS),
        is_supported=is_supported_platform(),
        executable_name=get_executable_name(curr_os),
        support_tier=tier,
    )


def get_platform_capabilities() -> dict[str, Any]:
    """Return structured capabilities breakdown for current platform."""
    info = get_platform_info()

    if info.is_windows:
        secrets_backend = "Windows DPAPI (CryptProtectData User-Bound Encryption)"
        single_instance = "Win32 Named Mutex ('Local\\DeviceGuardianSingleInstanceMutex') + PID validation"
        startup = "Windows Registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        detection_source = "Windows Security Event Log (Event ID 4625 via wevtutil)"
        tray = "pystray (System Tray Notification Area)"
    elif info.is_linux:
        secrets_backend = "FileSecretStore (Owner-only 0600 restrictive permissions)"
        single_instance = "POSIX file lock (flock/fcntl) + /proc liveliness check"
        startup = "XDG Autostart Desktop Entry (~/.config/autostart/device-guardian.desktop)"
        detection_source = "Linux Authentication Log (/var/log/auth.log or /var/log/secure)"
        tray = "pystray (Requires X11/Wayland display; degrades to headless CLI)"
    elif info.is_macos:
        secrets_backend = "FileSecretStore (Owner-only 0600 restrictive permissions)"
        single_instance = "POSIX file lock (flock/fcntl) + process liveliness check"
        startup = "macOS LaunchAgent (~/Library/LaunchAgents/com.deviceguardian.app.plist)"
        detection_source = "macOS Unified Logging System ('log show --predicate')"
        tray = "pystray (Requires macOS WindowServer; degrades to headless CLI)"
    else:
        secrets_backend = "Unsupported"
        single_instance = "Generic Lockfile"
        startup = "Unsupported"
        detection_source = "Null Monitor"
        tray = "Unsupported"

    return {
        "platform_info": info.to_dict(),
        "capabilities": {
            "secrets_backend": secrets_backend,
            "single_instance_mechanism": single_instance,
            "startup_mechanism": startup,
            "detection_source": detection_source,
            "tray_support": tray,
            "camera_support": "OpenCV VideoCapture (Degrades to UNAVAILABLE if missing)",
            "geolocation_support": "IP-API Geolocation (Degrades to UNKNOWN if offline)",
            "offline_voice_support": "pyttsx3 / Windows SAPI / NSSpeech / espeak",
        },
    }


def set_posix_permissions(path: Union[Path, str], mode: int = 0o600) -> bool:
    """Set restrictive POSIX file permissions (e.g. 0600 for secrets, 0700 for dirs, 0755 for exes).

    On Windows, attempts standard chmod (which controls read-only attribute).
    On POSIX, applies standard octal permission bits.

    Returns:
        True if permissions were set or host is Windows without errors, False on error.
    """
    try:
        p = Path(path).resolve()
        if not p.exists():
            return False
        os.chmod(str(p), mode)
        return True
    except OSError as exc:
        logger.debug("Failed to set permissions 0o%o on %s: %s", mode, path, exc)
        return False


def verify_file_permissions(
    path: Union[Path, str],
    expected_mode: int = 0o600,
) -> tuple[bool, str]:
    """Verify that a sensitive file does not grant excessive group or other permissions on POSIX.

    On Windows, returns (True, "Windows ACLs active") as DPAPI / NTFS ACLs govern security.
    On POSIX systems, verifies that group and other permissions are zeroed out for expected_mode 0600.

    Returns:
        Tuple of (is_valid, explanation_message).
    """
    p = Path(path).resolve()
    if not p.is_file():
        return False, f"File does not exist: {p}"

    curr_os = get_current_os()
    if curr_os == OperatingSystem.WINDOWS:
        return True, "Windows host: NTFS ACLs and user-bound DPAPI manage credential access."

    try:
        st = p.stat()
        file_mode = stat.S_IMODE(st.st_mode)

        # For secrets (expected 0600), verify that group and world have 0 permissions
        if expected_mode == 0o600:
            group_world = file_mode & 0o077
            if group_world != 0:
                return (
                    False,
                    f"Insecure permissions 0o{oct(file_mode)[2:]}: Group or world access permitted on sensitive file.",
                )
            return True, f"Permissions 0o{oct(file_mode)[2:]} verified: Owner-only access."

        # For executables (expected 0755), ensure owner execute is set
        if expected_mode == 0o755:
            if not (file_mode & stat.S_IXUSR):
                return False, f"Executable permission missing for owner: 0o{oct(file_mode)[2:]}"
            return True, f"Executable permissions 0o{oct(file_mode)[2:]} verified."

        return True, f"File permissions: 0o{oct(file_mode)[2:]}"
    except OSError as exc:
        return False, f"Failed to check permissions: {exc}"


def check_directory_permissions(
    path: Union[Path, str],
    expected_mode: int = 0o700,
) -> tuple[bool, str]:
    """Verify that a directory conforms to expected permission constraints on POSIX."""
    p = Path(path).resolve()
    if not p.is_dir():
        return False, f"Directory does not exist: {p}"

    curr_os = get_current_os()
    if curr_os == OperatingSystem.WINDOWS:
        return True, "Windows host: NTFS ACLs govern directory access."

    try:
        st = p.stat()
        dir_mode = stat.S_IMODE(st.st_mode)
        if expected_mode == 0o700:
            group_world = dir_mode & 0o077
            if group_world != 0:
                return (
                    False,
                    f"Insecure directory permissions 0o{oct(dir_mode)[2:]}: Group/world access permitted.",
                )
        return True, f"Directory permissions 0o{oct(dir_mode)[2:]} verified."
    except OSError as exc:
        return False, f"Failed to inspect directory permissions: {exc}"
