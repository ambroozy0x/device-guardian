"""Tests for Phase 7 safe zip extraction and security boundaries."""

from pathlib import Path
import zipfile
import pytest

from device_guardian.updates.archive import ArchiveSecurityError, SafeZipExtractor


def test_safe_zip_extractor_valid_package(tmp_path: Path):
    """Verify standard valid archive extracts safely."""
    zip_path = tmp_path / "valid_update.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("release-manifest.json", '{"application": "Device Guardian"}')
        zf.writestr("device-guardian.exe", b"EXECUTABLE_BYTES_PAYLOAD")

    extracted = SafeZipExtractor.extract(zip_path, dest_dir)
    assert len(extracted) == 2
    assert (dest_dir / "release-manifest.json").is_file()
    assert (dest_dir / "device-guardian.exe").is_file()


def test_safe_zip_extractor_path_traversal_double_dot(tmp_path: Path):
    """Verify archive with directory traversal ('..') is blocked."""
    zip_path = tmp_path / "malicious_traversal.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.exe", b"MALICIOUS")

    with pytest.raises(ArchiveSecurityError, match="Path traversal detected"):
        SafeZipExtractor.extract(zip_path, dest_dir)


def test_safe_zip_extractor_path_traversal_absolute(tmp_path: Path):
    """Verify archive with absolute path is blocked."""
    zip_path = tmp_path / "malicious_abs.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("/evil.exe", b"MALICIOUS")

    with pytest.raises(ArchiveSecurityError):
        SafeZipExtractor.extract(zip_path, dest_dir)


def test_safe_zip_extractor_disallowed_extension(tmp_path: Path):
    """Verify files with dangerous unapproved extensions are blocked."""
    zip_path = tmp_path / "script_attack.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("script.bat", b"@echo off\nevil")

    with pytest.raises(ArchiveSecurityError, match="Prohibited file extension"):
        SafeZipExtractor.extract(zip_path, dest_dir)


def test_safe_zip_extractor_member_limit(tmp_path: Path):
    """Verify archive exceeding max member count is rejected."""
    zip_path = tmp_path / "too_many_files.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.txt", b"x")

    with pytest.raises(ArchiveSecurityError, match="exceeds maximum allowed"):
        SafeZipExtractor.extract(zip_path, dest_dir, max_members=10)
