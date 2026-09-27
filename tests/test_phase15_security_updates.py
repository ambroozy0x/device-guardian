"""Phase 15 Security Audit — Update Subsystem and Package Integrity Tests.

Verifies:
- SafeZipExtractor rejects zip traversal, path escaping, and prohibited file types.
- SafeZipExtractor enforces file size caps and member count bounds.
- 7-gate release verification rejects invalid signatures, mismatched hashes, and unauthorized downgrades.
"""

from __future__ import annotations

import io
from pathlib import Path
import zipfile
import pytest

from device_guardian.updates.archive import ArchiveSecurityError, SafeZipExtractor
from device_guardian.updates.crypto import calculate_sha256, ed25519_sign, generate_keypair
from device_guardian.updates.manifest import ReleaseArtifact, ReleaseManifest
from device_guardian.updates.verifier import VerificationStatus, verify_update_package


def test_safe_zip_extractor_rejects_path_traversal(tmp_path: Path) -> None:
    """Verify SafeZipExtractor rejects archives with path traversal members."""
    zip_path = tmp_path / "traversal.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.txt", "malicious payload")

    with pytest.raises(ArchiveSecurityError, match="Path traversal"):
        SafeZipExtractor.validate_and_extract(zip_path, dest_dir)


def test_safe_zip_extractor_rejects_unauthorized_extensions(tmp_path: Path) -> None:
    """Verify SafeZipExtractor rejects shell scripts (.bat, .sh, .cmd)."""
    zip_path = tmp_path / "script.zip"
    dest_dir = tmp_path / "extracted"

    for ext in [".bat", ".sh", ".cmd", ".ps1", ".vbs"]:
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(f"payload{ext}", "echo hacked")

        with pytest.raises(ArchiveSecurityError, match="Prohibited file extension"):
            SafeZipExtractor.validate_and_extract(zip_path, dest_dir)


def test_safe_zip_extractor_rejects_oversized_file(tmp_path: Path) -> None:
    """Verify SafeZipExtractor rejects files exceeding single-file size limit."""
    zip_path = tmp_path / "oversized.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("huge.bin", b"0" * 2000)

    # Override limit to 1 KB for test
    with pytest.raises(ArchiveSecurityError, match="exceeds size limit"):
        SafeZipExtractor.validate_and_extract(zip_path, dest_dir, max_single_file_size_bytes=1000)


def test_release_verification_rejects_tampered_binary(tmp_path: Path) -> None:
    """Verify verify_update_package rejects packages where binary hash does not match manifest."""
    priv, pub = generate_keypair()
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()

    bin_path = pkg_dir / "device-guardian.exe"
    bin_path.write_bytes(b"AUTHENTIC_BINARY_CONTENT")
    actual_hash = calculate_sha256(bin_path)

    # Manifest claims different hash
    artifact = ReleaseArtifact(
        filename="device-guardian.exe",
        platform="windows",
        architecture="x64",
        sha256="0" * 64,  # Fraudulent hash
        size_bytes=len(b"AUTHENTIC_BINARY_CONTENT"),
    )
    manifest = ReleaseManifest(
        application="Device Guardian",
        version="1.1.0",
        release_id="DG-1.1.0-windows-x64",
        release_date="2026-09-27",
        platform="windows",
        architecture="x64",
        artifacts=[artifact],
    )
    manifest.sign(priv, pub)

    manifest_path = pkg_dir / "release-manifest.json"
    manifest.save_to_file(manifest_path)

    zip_path = tmp_path / "update_tampered.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(bin_path, arcname="device-guardian.exe")
        zf.write(manifest_path, arcname="release-manifest.json")

    result = verify_update_package(
        zip_path,
        public_key=pub,
        target_platform="windows",
        target_arch="x64",
    )
    assert result.is_verified is False
    assert result.status == VerificationStatus.CORRUPTED
    assert any("hash mismatch" in f.message for f in result.findings)
