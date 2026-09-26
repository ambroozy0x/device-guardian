"""Tests for Phase 7 multi-gate update package verification."""

from pathlib import Path
import zipfile
import pytest

from device_guardian.updates.crypto import calculate_sha256, generate_ed25519_keypair
from device_guardian.updates.manifest import ReleaseArtifact, ReleaseManifest
from device_guardian.updates.verifier import VerificationStatus, verify_update_package
from device_guardian.version import __version__, get_version_info


def create_mock_update_package(
    tmp_path: Path,
    version: str = "0.2.0",
    corrupt_hash: bool = False,
    corrupt_signature: bool = False,
    unsigned: bool = False,
    signing_key: bytes = None,
    public_key: bytes = None,
) -> tuple[Path, bytes]:
    """Helper to create synthetic update packages for verification testing."""
    if signing_key is None:
        signing_key, public_key = generate_ed25519_keypair()

    v_info = get_version_info()
    binary_name = "device-guardian.exe" if v_info.platform == "windows" else "device-guardian"
    binary_content = b"GENUINE_DEVICE_GUARDIAN_NEW_RELEASE_BINARY"

    temp_dir = tmp_path / f"pkg_{version}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    binary_path = temp_dir / binary_name
    binary_path.write_bytes(binary_content)

    actual_sha = calculate_sha256(binary_path)
    manifest_sha = "0" * 64 if corrupt_hash else actual_sha

    artifact = ReleaseArtifact(
        filename=binary_name,
        platform=v_info.platform,
        architecture=v_info.architecture,
        sha256=manifest_sha,
        size_bytes=len(binary_content),
    )

    manifest = ReleaseManifest(
        version=version,
        release_id=f"DG-{version}-{v_info.platform}-{v_info.architecture}",
        release_date="2026-09-26T12:00:00Z",
        platform=v_info.platform,
        architecture=v_info.architecture,
        artifacts=[artifact],
    )

    if not unsigned:
        sig = manifest.sign(signing_key)
        if corrupt_signature:
            manifest.signature = "a" * 128

    manifest_path = temp_dir / "release-manifest.json"
    manifest.save_to_file(manifest_path)

    zip_file = tmp_path / f"update_{version}.zip"
    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.write(manifest_path, "release-manifest.json")
        zf.write(binary_path, binary_name)

    return zip_file, public_key


def test_verify_update_valid_package(tmp_path: Path):
    """Verify an authentic, signed update package passes all gates."""
    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="0.2.0")
    res = verify_update_package(zip_pkg, public_key=pub_key)

    assert res.is_verified is True
    assert res.status == VerificationStatus.VALID
    assert res.manifest is not None
    assert res.manifest.version == "0.2.0"
    assert res.artifact_path is not None
    assert res.artifact_path.is_file()


def test_verify_update_unsigned_package(tmp_path: Path):
    """Verify unsigned package is rejected as UNSIGNED."""
    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="0.2.0", unsigned=True)
    res = verify_update_package(zip_pkg, public_key=pub_key)

    assert res.is_verified is False
    assert res.status == VerificationStatus.UNSIGNED


def test_verify_update_untrusted_key(tmp_path: Path):
    """Verify package signed with different key is rejected as UNTRUSTED."""
    priv_attacker, _pub_attacker = generate_ed25519_keypair()
    _priv_trusted, pub_trusted = generate_ed25519_keypair()

    zip_pkg, _ = create_mock_update_package(tmp_path, version="0.2.0", signing_key=priv_attacker)
    res = verify_update_package(zip_pkg, public_key=pub_trusted)

    assert res.is_verified is False
    assert res.status == VerificationStatus.UNTRUSTED


def test_verify_update_corrupted_binary(tmp_path: Path):
    """Verify binary hash mismatch is rejected as CORRUPTED."""
    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="0.2.0", corrupt_hash=True)
    res = verify_update_package(zip_pkg, public_key=pub_key)

    assert res.is_verified is False
    assert res.status in {VerificationStatus.CORRUPTED, VerificationStatus.UNTRUSTED}


def test_verify_update_downgrade_rejected(tmp_path: Path):
    """Verify older version is rejected unless explicitly allowed."""
    zip_pkg, pub_key = create_mock_update_package(tmp_path, version="0.0.1")
    res = verify_update_package(zip_pkg, public_key=pub_key, allow_downgrade=False)

    assert res.is_verified is False
    assert res.status == VerificationStatus.INCOMPATIBLE

    # Allowed when allow_downgrade=True
    res_allowed = verify_update_package(zip_pkg, public_key=pub_key, allow_downgrade=True)
    assert res_allowed.is_verified is True
    assert res_allowed.status == VerificationStatus.VALID
