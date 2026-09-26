"""Tests for Phase 7 semantic versioning and release metadata."""

import pytest

from device_guardian.version import (
    SemanticVersion,
    VersionInfo,
    get_current_semantic_version,
    get_version_info,
    __version__,
)


def test_semver_parse_valid():
    """Verify parsing valid semantic version strings."""
    v1 = SemanticVersion.parse("0.1.0")
    assert v1.major == 0
    assert v1.minor == 1
    assert v1.patch == 0
    assert v1.prerelease is None
    assert str(v1) == "0.1.0"

    v2 = SemanticVersion.parse("v1.2.3")
    assert v2.major == 1
    assert v2.minor == 2
    assert v2.patch == 3
    assert str(v2) == "1.2.3"

    v3 = SemanticVersion.parse("2.0.0-rc.1")
    assert v3.major == 2
    assert v3.minor == 0
    assert v3.patch == 0
    assert v3.prerelease == "rc.1"
    assert str(v3) == "2.0.0-rc.1"


def test_semver_parse_invalid():
    """Verify invalid version strings raise ValueError."""
    for invalid in ["", "not_a_version", "1.0", "1.2.3.4", "v1.2.3.4"]:
        with pytest.raises(ValueError):
            SemanticVersion.parse(invalid)


def test_semver_comparison():
    """Verify semantic version precedence and comparison."""
    v0_1_0 = SemanticVersion.parse("0.1.0")
    v0_1_1 = SemanticVersion.parse("0.1.1")
    v0_2_0 = SemanticVersion.parse("0.2.0")
    v1_0_0 = SemanticVersion.parse("1.0.0")
    v1_0_0_alpha = SemanticVersion.parse("1.0.0-alpha")

    assert v0_1_0 < v0_1_1
    assert v0_1_1 < v0_2_0
    assert v0_2_0 < v1_0_0
    assert v1_0_0_alpha < v1_0_0
    assert v0_1_0 == SemanticVersion.parse("0.1.0")
    assert v0_1_0 == "0.1.0"
    assert v0_1_0 <= v0_1_0
    assert v0_2_0 > v0_1_0
    assert v0_2_0 >= v0_1_0


def test_semver_downgrade_detection():
    """Verify downgrade detection against installed version."""
    installed = SemanticVersion.parse("1.2.0")
    older = SemanticVersion.parse("1.1.9")
    newer = SemanticVersion.parse("1.2.1")
    same = SemanticVersion.parse("1.2.0")

    assert older.is_downgrade_from(installed) is True
    assert newer.is_downgrade_from(installed) is False
    assert same.is_downgrade_from(installed) is False


def test_version_info_construction():
    """Verify structured, non-telemetric version info."""
    v_info = get_version_info(build_timestamp="2026-09-26T12:00:00Z")
    assert v_info.version == __version__
    assert v_info.build_timestamp == "2026-09-26T12:00:00Z"
    assert v_info.release_id.startswith(f"DG-{__version__}-")
    assert v_info.platform in {"windows", "linux", "darwin"}
    assert v_info.architecture in {"x64", "arm64", "x86"}

    info_dict = v_info.to_dict()
    assert "version" in info_dict
    assert "platform" in info_dict
    assert "architecture" in info_dict
    # Verify no privacy leakage
    for key in ["ip", "mac", "hostname", "username"]:
        assert key not in info_dict


def test_get_current_semantic_version():
    """Verify get_current_semantic_version returns valid SemanticVersion."""
    cur = get_current_semantic_version()
    assert isinstance(cur, SemanticVersion)
    assert str(cur) == __version__
