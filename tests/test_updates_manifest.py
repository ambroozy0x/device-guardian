"""Tests for Phase 7 release manifest serialization, signing, and schema validation."""

from pathlib import Path
import pytest

from device_guardian.updates.crypto import generate_ed25519_keypair
from device_guardian.updates.manifest import (
    ManifestError,
    ReleaseArtifact,
    ReleaseManifest,
)


def test_release_artifact_validation():
    """Verify artifact validation rules."""
    valid = ReleaseArtifact(
        filename="device-guardian.exe",
        platform="windows",
        architecture="x64",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
    )
    d = valid.to_dict()
    assert d["filename"] == "device-guardian.exe"
    restored = ReleaseArtifact.from_dict(d)
    assert restored.sha256 == valid.sha256

    # Missing field
    with pytest.raises(ManifestError):
        ReleaseArtifact.from_dict({"filename": "test"})

    # Invalid SHA-256 (not 64 hex characters)
    with pytest.raises(ManifestError):
        ReleaseArtifact.from_dict({
            "filename": "test",
            "platform": "windows",
            "architecture": "x64",
            "sha256": "invalid_hash",
            "size_bytes": 100,
        })

    # Non-positive size
    with pytest.raises(ManifestError):
        ReleaseArtifact.from_dict({
            "filename": "test",
            "platform": "windows",
            "architecture": "x64",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": -5,
        })


def test_release_manifest_signing_and_verification(tmp_path: Path):
    """Verify digital signing and signature verification of ReleaseManifest."""
    priv, pub = generate_ed25519_keypair()

    artifact = ReleaseArtifact(
        filename="device-guardian.exe",
        platform="windows",
        architecture="x64",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=2048,
    )
    manifest = ReleaseManifest(
        version="0.2.0",
        release_id="DG-0.2.0-windows-x64",
        release_date="2026-09-26T12:00:00Z",
        platform="windows",
        architecture="x64",
        artifacts=[artifact],
    )

    # Initially unsigned
    assert manifest.signature is None
    assert manifest.verify_signature(pub) is False

    # Sign manifest
    sig = manifest.sign(priv)
    assert len(sig) == 128  # 64 bytes in hex
    assert manifest.verify_signature(pub) is True

    # Tampering with artifact hash invalidates signature
    manifest.artifacts[0].sha256 = "0" * 64
    assert manifest.verify_signature(pub) is False


def test_release_manifest_persistence(tmp_path: Path):
    """Verify saving and loading release manifest to/from disk."""
    priv, pub = generate_ed25519_keypair()
    artifact = ReleaseArtifact(
        filename="device-guardian",
        platform="linux",
        architecture="x64",
        sha256="a" * 64,
        size_bytes=4096,
    )
    manifest = ReleaseManifest(
        version="0.3.0",
        release_id="DG-0.3.0-linux-x64",
        release_date="2026-09-26T12:00:00Z",
        platform="linux",
        architecture="x64",
        artifacts=[artifact],
    )
    manifest.sign(priv)

    file_path = tmp_path / "release-manifest.json"
    manifest.save_to_file(file_path)

    loaded = ReleaseManifest.load_from_file(file_path)
    assert loaded.version == "0.3.0"
    assert loaded.release_id == "DG-0.3.0-linux-x64"
    assert len(loaded.artifacts) == 1
    assert loaded.verify_signature(pub) is True


def test_get_artifact_for_platform():
    """Verify platform artifact matching."""
    art_win = ReleaseArtifact("dg.exe", "windows", "x64", "1" * 64, 100)
    art_lin = ReleaseArtifact("dg", "linux", "x64", "2" * 64, 100)

    manifest = ReleaseManifest(
        version="0.2.0",
        release_id="DG-0.2.0",
        release_date="2026-09-26T12:00:00Z",
        platform="multi",
        architecture="multi",
        artifacts=[art_win, art_lin],
    )

    found_win = manifest.get_artifact_for_platform("windows", "x64")
    assert found_win is not None
    assert found_win.filename == "dg.exe"

    found_arm = manifest.get_artifact_for_platform("windows", "arm64")
    assert found_arm is None
