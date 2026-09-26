"""Tests for Phase 9 Update System Hardening, Archive Security, and Update Serialization."""

from __future__ import annotations

import io
from pathlib import Path
import zipfile
import pytest

from device_guardian.updates.archive import ArchiveExtractionError, SafeZipExtractor
from device_guardian.updates.installer import _UpdateLockContext, UpdateInstaller


def test_update_lock_mutual_exclusion(tmp_path: Path):
    """Verify _UpdateLockContext prevents concurrent update operations."""
    lock_file = tmp_path / "update.lock"

    with _UpdateLockContext(lock_file) as lock1:
        assert lock1 is not None

        # Second lock attempt must fail
        with pytest.raises(RuntimeError) as exc:
            with _UpdateLockContext(lock_file):
                pass
        assert "in progress" in str(exc.value).lower()

    # Once exited, acquiring lock succeeds again
    with _UpdateLockContext(lock_file) as lock2:
        assert lock2 is not None


def test_safe_zip_extractor_rejects_path_traversal(tmp_path: Path):
    """Verify SafeZipExtractor rejects zip archive with path traversal ('..')."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil.exe", b"malicious binary")

    zip_file = tmp_path / "traversal.zip"
    zip_file.write_bytes(zip_buf.getvalue())

    dest_dir = tmp_path / "out"
    dest_dir.mkdir()

    with pytest.raises(ArchiveExtractionError) as exc:
        SafeZipExtractor.extract_archive(zip_file, dest_dir)
    assert "traversal" in str(exc.value).lower()


def test_safe_zip_extractor_rejects_absolute_path(tmp_path: Path):
    """Verify SafeZipExtractor rejects zip archive with absolute paths."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("/etc/evil.conf", b"malicious data")

    zip_file = tmp_path / "absolute.zip"
    zip_file.write_bytes(zip_buf.getvalue())

    dest_dir = tmp_path / "out"
    dest_dir.mkdir()

    with pytest.raises(ArchiveExtractionError) as exc:
        SafeZipExtractor.extract_archive(zip_file, dest_dir)
    assert "absolute" in str(exc.value).lower()


def test_safe_zip_extractor_rejects_duplicate_members(tmp_path: Path):
    """Verify SafeZipExtractor rejects archive containing identical member names."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.exe", b"version 1")
        zf.writestr("app.exe", b"version 2")

    zip_file = tmp_path / "duplicate.zip"
    zip_file.write_bytes(zip_buf.getvalue())

    dest_dir = tmp_path / "out"
    dest_dir.mkdir()

    with pytest.raises(ArchiveExtractionError) as exc:
        SafeZipExtractor.extract_archive(zip_file, dest_dir)
    assert "duplicate" in str(exc.value).lower() or "collision" in str(exc.value).lower()


def test_safe_zip_extractor_rejects_case_insensitive_collisions(tmp_path: Path):
    """Verify SafeZipExtractor rejects member names differing only by case."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("binary.exe", b"first")
        zf.writestr("BINARY.EXE", b"second")

    zip_file = tmp_path / "case_collision.zip"
    zip_file.write_bytes(zip_buf.getvalue())

    dest_dir = tmp_path / "out"
    dest_dir.mkdir()

    with pytest.raises(ArchiveExtractionError) as exc:
        SafeZipExtractor.extract_archive(zip_file, dest_dir)
    assert "collision" in str(exc.value).lower()


def test_safe_zip_extractor_rejects_oversized_member(tmp_path: Path):
    """Verify SafeZipExtractor rejects members exceeding max_single_file_size_bytes."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("large.bin", b"0" * 2000)

    zip_file = tmp_path / "oversized.zip"
    zip_file.write_bytes(zip_buf.getvalue())

    dest_dir = tmp_path / "out"
    dest_dir.mkdir()

    with pytest.raises(ArchiveExtractionError) as exc:
        SafeZipExtractor.extract_archive(zip_file, dest_dir, max_single_file_size_bytes=1000)
    assert "exceeds" in str(exc.value).lower()
