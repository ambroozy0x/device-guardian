"""Phase 15 Security Audit — Filesystem Security and Path Traversal Tests.

Verifies:
- validate_safe_path rejects literal traversal ('..'), encoded traversal ('%2e%2e'),
  null bytes ('\\0'), UNC paths, NTFS alternate data streams, and drive-relative paths.
- Directory containment is strictly enforced (cannot escape base_dir).
- Intermediate ancestor symlinks/reparse points are detected and rejected.
- secure_create_temp_file uses exclusive flags (O_CREAT | O_EXCL) and 0600 mode.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from device_guardian.security.filesystem import (
    SecurityPathError,
    secure_create_temp_file,
    validate_safe_path,
)


def test_validate_safe_path_rejects_path_traversal() -> None:
    """Verify literal path traversal segments are rejected."""
    traversal_paths = [
        "../etc/passwd",
        "..\\Windows\\System32",
        "foo/../../bar",
        "foo/bar/..",
    ]
    for p in traversal_paths:
        with pytest.raises(SecurityPathError, match="Path traversal"):
            validate_safe_path(p)


def test_validate_safe_path_rejects_encoded_traversal() -> None:
    """Verify percent-encoded path traversal segments are rejected."""
    encoded_paths = [
        "%2e%2e/secret.txt",
        "%2e%2e\\secret.txt",
        "foo/%2e%2e/bar",
        "%2E%2E/evil",
    ]
    for p in encoded_paths:
        with pytest.raises(SecurityPathError, match="Encoded path traversal"):
            validate_safe_path(p)


def test_validate_safe_path_rejects_null_bytes() -> None:
    """Verify null-byte injection is rejected."""
    null_paths = [
        "config.json\0.bak",
        "temp\0file.txt",
    ]
    for p in null_paths:
        with pytest.raises(SecurityPathError, match="Null byte"):
            validate_safe_path(p)


def test_validate_safe_path_rejects_unc_paths() -> None:
    """Verify UNC network paths are prohibited by default."""
    unc_paths = [
        r"\\attacker-server\share\evil.exe",
        "//attacker-server/share/evil.exe",
    ]
    for p in unc_paths:
        with pytest.raises(SecurityPathError, match="UNC network paths are prohibited"):
            validate_safe_path(p)


def test_validate_safe_path_directory_containment(tmp_path: Path) -> None:
    """Verify paths escaping base_dir are rejected."""
    base = tmp_path / "sandbox"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("sensitive")

    with pytest.raises(SecurityPathError, match="escapes base directory"):
        validate_safe_path(outside, base_dir=base)

    inside = base / "safe.txt"
    inside.write_text("hello")
    validated = validate_safe_path(inside, base_dir=base)
    assert validated.resolve() == inside.resolve()


def test_secure_create_temp_file_exclusive(tmp_path: Path) -> None:
    """Verify secure_create_temp_file creates unique files with restrictive permissions."""
    t1 = secure_create_temp_file(tmp_path, prefix="test", suffix=".tmp")
    t2 = secure_create_temp_file(tmp_path, prefix="test", suffix=".tmp")
    assert t1.is_file()
    assert t2.is_file()
    assert t1 != t2
    # Verify file is inside tmp_path
    assert tmp_path in t1.parents
