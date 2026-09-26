"""Tests for Phase 9 Local Filesystem Defense and Reparse-Point Hardening."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import pytest

from device_guardian.security.filesystem import (
    SecurityPathError,
    is_symlink_or_reparse_point,
    secure_create_temp_file,
    validate_safe_path,
)


def test_validate_safe_path_valid(tmp_path: Path):
    """Verify normal valid path passes validation and resolves."""
    valid_file = tmp_path / "valid.txt"
    valid_file.write_text("content", encoding="utf-8")

    resolved = validate_safe_path(valid_file)
    assert resolved == valid_file.resolve()


def test_validate_safe_path_none_or_empty():
    """Verify None or empty path raises SecurityPathError."""
    with pytest.raises(SecurityPathError) as exc_none:
        validate_safe_path(None)  # type: ignore
    assert "none" in str(exc_none.value).lower()

    with pytest.raises(SecurityPathError) as exc_empty:
        validate_safe_path("   ")
    assert "empty" in str(exc_empty.value).lower()


def test_validate_safe_path_null_byte_injection():
    """Verify null byte in path raises SecurityPathError."""
    with pytest.raises(SecurityPathError) as exc:
        validate_safe_path("valid_file.txt\0.exe")
    assert "null byte" in str(exc.value).lower()


def test_validate_safe_path_unc_rejected():
    """Verify UNC network paths are rejected."""
    unc_paths = [
        r"\\attacker-server\share\file.exe",
        "//attacker-server/share/file.exe",
        r"\\192.168.1.1\c$\payload.zip",
    ]
    for unc in unc_paths:
        with pytest.raises(SecurityPathError) as exc:
            validate_safe_path(unc, allow_unc=False)
        assert "unc" in str(exc.value).lower()


def test_validate_safe_path_ntfs_alternate_data_stream():
    """Verify NTFS Alternate Data Streams (ADS) are rejected on Windows."""
    if platform.system() != "Windows":
        pytest.skip("NTFS Alternate Data Stream check is Windows-specific")

    ads_paths = [
        "C:\\normal_file.txt:hidden_stream",
        "update.zip:zone.identifier",
        "file.exe:$DATA",
    ]
    for ads in ads_paths:
        with pytest.raises(SecurityPathError) as exc:
            validate_safe_path(ads)
        assert "alternate data stream" in str(exc.value).lower()


def test_validate_safe_path_drive_relative_rejected():
    """Verify drive-relative paths (e.g. C:file.txt) are rejected on Windows."""
    if platform.system() != "Windows":
        pytest.skip("Drive-relative path check is Windows-specific")

    with pytest.raises(SecurityPathError) as exc:
        validate_safe_path("C:file.txt")
    assert "drive-relative" in str(exc.value).lower()


def test_validate_safe_path_path_traversal():
    """Verify path traversal segments ('..') are strictly rejected."""
    bad_paths = [
        "../outside.txt",
        "dir/../../escape.exe",
        "subdir/../something",
        "C:\\Users\\..\\Windows\\System32",
    ]
    for bad in bad_paths:
        with pytest.raises(SecurityPathError) as exc:
            validate_safe_path(bad)
        assert "traversal" in str(exc.value).lower()


def test_validate_safe_path_base_dir_containment(tmp_path: Path):
    """Verify path escaping base directory is rejected."""
    base_dir = tmp_path / "sandbox"
    base_dir.mkdir()

    inside_file = base_dir / "inside.txt"
    inside_file.write_text("inside", encoding="utf-8")

    # Allowed inside
    validated = validate_safe_path(inside_file, base_dir=base_dir)
    assert validated == inside_file.resolve()

    # Outside file
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")

    with pytest.raises(SecurityPathError) as exc:
        validate_safe_path(outside_file, base_dir=base_dir)
    assert "escapes" in str(exc.value).lower() or "containment" in str(exc.value).lower()


def test_validate_safe_path_absolute_prohibited():
    """Verify absolute paths are rejected when allow_absolute=False."""
    with pytest.raises(SecurityPathError) as exc:
        validate_safe_path(Path("/etc/passwd").resolve(), allow_absolute=False)
    assert "absolute" in str(exc.value).lower()


def test_is_symlink_or_reparse_point_normal_files(tmp_path: Path):
    """Verify normal files and directories are not reported as symlinks."""
    reg_file = tmp_path / "regular.txt"
    reg_file.write_text("hello", encoding="utf-8")
    assert is_symlink_or_reparse_point(reg_file) is False

    reg_dir = tmp_path / "regular_dir"
    reg_dir.mkdir()
    assert is_symlink_or_reparse_point(reg_dir) is False


def test_is_symlink_or_reparse_point_symlink(tmp_path: Path):
    """Verify created symbolic link is detected."""
    target = tmp_path / "real_target.txt"
    target.write_text("data", encoding="utf-8")

    link = tmp_path / "link_to_target.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires privileges or is not supported on this host")

    assert is_symlink_or_reparse_point(link) is True
    with pytest.raises(SecurityPathError):
        validate_safe_path(link, allow_symlinks=False)


def test_secure_create_temp_file(tmp_path: Path):
    """Verify secure_create_temp_file creates an exclusive non-symlink file."""
    temp_dir = tmp_path / "secure_tmp"
    temp_dir.mkdir()

    path = secure_create_temp_file(temp_dir, prefix="dg_sec_", suffix=".tmp")
    assert path.is_file()
    assert not is_symlink_or_reparse_point(path)
    assert path.parent.resolve() == temp_dir.resolve()
    path.unlink()
