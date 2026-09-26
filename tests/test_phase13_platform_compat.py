"""Phase 13 tests: Platform Compatibility, OS & Architecture Abstraction, and Capability Matrix.

Verifies:
- OperatingSystem enum parsing, normalization, and unsupported OS handling.
- Architecture enum parsing, normalization across x64, arm64, x86, unknown.
- PlatformSupportTier classification (Tier 1 vs Tier 2 vs Unsupported).
- PlatformInfo dataclass snapshot, immutability, and to_dict() serialization.
- Dynamic test overrides (set_platform_override, set_arch_override, platform_override context manager).
- get_executable_name() resolution across platforms.
- get_platform_capabilities() matrix structure and completeness.
- POSIX permission checking and hardening helpers.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from device_guardian.platform_compat import (
    Architecture,
    OperatingSystem,
    PlatformInfo,
    PlatformSupportTier,
    check_directory_permissions,
    get_current_arch,
    get_current_os,
    get_executable_name,
    get_platform_capabilities,
    get_platform_info,
    get_platform_support_tier,
    is_frozen_executable,
    is_linux,
    is_macos,
    is_supported_platform,
    is_windows,
    platform_override,
    reset_platform_overrides,
    set_arch_override,
    set_platform_override,
    set_posix_permissions,
    verify_file_permissions,
)


@pytest.fixture(autouse=True)
def clean_platform_overrides():
    """Ensure platform overrides are reset before and after every test."""
    reset_platform_overrides()
    yield
    reset_platform_overrides()


def test_operating_system_enum_parsing():
    """Verify robust parsing of various OS strings into standard enum values."""
    assert OperatingSystem.from_string("Windows") == OperatingSystem.WINDOWS
    assert OperatingSystem.from_string("windows") == OperatingSystem.WINDOWS
    assert OperatingSystem.from_string("win32") == OperatingSystem.WINDOWS
    assert OperatingSystem.from_string("Darwin") == OperatingSystem.MACOS
    assert OperatingSystem.from_string("darwin") == OperatingSystem.MACOS
    assert OperatingSystem.from_string("macOS") == OperatingSystem.MACOS
    assert OperatingSystem.from_string("osx") == OperatingSystem.MACOS
    assert OperatingSystem.from_string("Linux") == OperatingSystem.LINUX
    assert OperatingSystem.from_string("linux") == OperatingSystem.LINUX
    assert OperatingSystem.from_string("FreeBSD") == OperatingSystem.UNSUPPORTED
    assert OperatingSystem.from_string("Solaris") == OperatingSystem.UNSUPPORTED
    assert OperatingSystem.from_string("") == OperatingSystem.UNSUPPORTED
    assert OperatingSystem.from_string(None) == OperatingSystem.UNSUPPORTED


def test_architecture_enum_parsing():
    """Verify processor architecture normalization across standard naming conventions."""
    assert Architecture.from_string("x86_64") == Architecture.X64
    assert Architecture.from_string("AMD64") == Architecture.X64
    assert Architecture.from_string("amd64") == Architecture.X64
    assert Architecture.from_string("x64") == Architecture.X64
    assert Architecture.from_string("arm64") == Architecture.ARM64
    assert Architecture.from_string("aarch64") == Architecture.ARM64
    assert Architecture.from_string("ARM64") == Architecture.ARM64
    assert Architecture.from_string("i386") == Architecture.X86
    assert Architecture.from_string("i686") == Architecture.X86
    assert Architecture.from_string("x86") == Architecture.X86
    assert Architecture.from_string("mips") == Architecture.UNKNOWN
    assert Architecture.from_string("") == Architecture.UNKNOWN
    assert Architecture.from_string(None) == Architecture.UNKNOWN


def test_platform_support_tiers():
    """Verify support tier assignment accurately reflects host verification vs simulation."""
    assert get_platform_support_tier(OperatingSystem.WINDOWS) == PlatformSupportTier.TIER_1_PRIMARY
    assert get_platform_support_tier(OperatingSystem.LINUX) == PlatformSupportTier.TIER_2_COMPATIBLE
    assert get_platform_support_tier(OperatingSystem.MACOS) == PlatformSupportTier.TIER_2_MACOS
    assert get_platform_support_tier(OperatingSystem.UNSUPPORTED) == PlatformSupportTier.UNSUPPORTED


def test_executable_naming_by_platform():
    """Verify Windows binaries require .exe while POSIX binaries use bare name."""
    assert get_executable_name(OperatingSystem.WINDOWS) == "device-guardian.exe"
    assert get_executable_name(OperatingSystem.LINUX) == "device-guardian"
    assert get_executable_name(OperatingSystem.MACOS) == "device-guardian"
    assert get_executable_name(OperatingSystem.UNSUPPORTED) == "device-guardian"


def test_platform_override_context_manager():
    """Verify deterministic simulation of different operating systems via context manager."""
    original_os = get_current_os()

    with platform_override(OperatingSystem.LINUX, Architecture.ARM64):
        assert get_current_os() == OperatingSystem.LINUX
        assert get_current_arch() == Architecture.ARM64
        assert is_linux() is True
        assert is_windows() is False
        assert is_macos() is False
        assert is_supported_platform() is True
        assert get_executable_name() == "device-guardian"
        assert get_platform_support_tier() == PlatformSupportTier.TIER_2_COMPATIBLE

    with platform_override(OperatingSystem.MACOS, Architecture.X64):
        assert get_current_os() == OperatingSystem.MACOS
        assert is_macos() is True
        assert is_linux() is False
        assert is_windows() is False
        assert get_executable_name() == "device-guardian"
        assert get_platform_support_tier() == PlatformSupportTier.TIER_2_MACOS

    with platform_override(OperatingSystem.UNSUPPORTED):
        assert is_supported_platform() is False
        assert get_platform_support_tier() == PlatformSupportTier.UNSUPPORTED

    # Ensure restoration to original
    assert get_current_os() == original_os


def test_platform_info_dataclass():
    """Verify PlatformInfo generates complete, valid, and immutable diagnostic records."""
    with platform_override(OperatingSystem.LINUX, Architecture.X64):
        info = get_platform_info()
        assert isinstance(info, PlatformInfo)
        assert info.os == OperatingSystem.LINUX
        assert info.os_name == "Linux"
        assert info.arch == Architecture.X64
        assert info.is_linux is True
        assert info.is_windows is False
        assert info.is_macos is False
        assert info.is_supported is True
        assert info.executable_name == "device-guardian"
        assert info.support_tier == PlatformSupportTier.TIER_2_COMPATIBLE

        dct = info.to_dict()
        assert dct["os"] == "Linux"
        assert dct["arch"] == "x64"
        assert dct["is_supported"] is True
        assert "executable_name" in dct
        assert "python_version" in dct


def test_platform_capabilities_matrix_windows():
    """Verify capabilities breakdown for Windows host."""
    with platform_override(OperatingSystem.WINDOWS):
        caps = get_platform_capabilities()
        assert "platform_info" in caps
        c = caps["capabilities"]
        assert "DPAPI" in c["secrets_backend"]
        assert "Mutex" in c["single_instance_mechanism"]
        assert "HKCU" in c["startup_mechanism"]
        assert "Event ID 4625" in c["detection_source"]
        assert "pystray" in c["tray_support"]


def test_platform_capabilities_matrix_linux():
    """Verify capabilities breakdown for Linux host."""
    with platform_override(OperatingSystem.LINUX):
        caps = get_platform_capabilities()
        c = caps["capabilities"]
        assert "0600" in c["secrets_backend"]
        assert "flock" in c["single_instance_mechanism"]
        assert "XDG" in c["startup_mechanism"]
        assert "auth.log" in c["detection_source"]


def test_platform_capabilities_matrix_macos():
    """Verify capabilities breakdown for macOS host."""
    with platform_override(OperatingSystem.MACOS):
        caps = get_platform_capabilities()
        c = caps["capabilities"]
        assert "0600" in c["secrets_backend"]
        assert "flock" in c["single_instance_mechanism"]
        assert "LaunchAgent" in c["startup_mechanism"]
        assert "Unified Logging" in c["detection_source"]


def test_permission_helpers(tmp_path):
    """Verify POSIX and Windows permission helper functions."""
    test_file = tmp_path / "test_secret.txt"
    test_file.write_text("secret_data", encoding="utf-8")

    # Set permissions
    res = set_posix_permissions(test_file, 0o600)
    assert res is True

    # Check non-existent file
    assert set_posix_permissions(tmp_path / "non_existent.txt") is False

    # Verify file permissions
    valid, msg = verify_file_permissions(test_file, 0o600)
    assert valid is True
    assert msg != ""

    # Check directory permissions
    valid_dir, dir_msg = check_directory_permissions(tmp_path, 0o700)
    assert valid_dir is True
    assert dir_msg != ""

    # Check non-existent directory
    missing_dir, missing_msg = check_directory_permissions(tmp_path / "ghost_dir")
    assert missing_dir is False
    assert "does not exist" in missing_msg
