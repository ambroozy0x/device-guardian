"""Release verification pipeline for Device Guardian (Phase 7).

Verifies the integrity, authenticity, platform compatibility, and version validity
of candidate update packages prior to installation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import platform
import tempfile
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.updates.archive import ArchiveSecurityError, SafeZipExtractor
from device_guardian.updates.crypto import calculate_sha256, verify_sha256
from device_guardian.updates.keys import get_trusted_public_key
from device_guardian.updates.manifest import ManifestError, ReleaseArtifact, ReleaseManifest
from device_guardian.version import SemanticVersion, __version__, get_current_semantic_version

logger = get_logger("updates.verifier")


class VerificationStatus(str, Enum):
    """Evaluation status for a candidate update package."""

    VALID = "VALID"
    INVALID = "INVALID"
    MISSING = "MISSING"
    CORRUPTED = "CORRUPTED"
    UNSIGNED = "UNSIGNED"
    UNTRUSTED = "UNTRUSTED"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass
class VerificationFinding:
    """Individual verification check result."""

    category: str
    status: VerificationStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReleaseVerificationResult:
    """Structured report returned by the update verification pipeline."""

    status: VerificationStatus
    findings: list[VerificationFinding] = field(default_factory=list)
    manifest: Optional[ReleaseManifest] = None
    artifact_path: Optional[Path] = None
    extracted_dir: Optional[Path] = None

    @property
    def is_verified(self) -> bool:
        """True if the candidate package passed all integrity and authenticity gates."""
        return self.status == VerificationStatus.VALID

    def format_report(self) -> str:
        """Produce a non-leaking diagnostic summary of the verification result."""
        lines = [
            "Device Guardian Update Verification",
            "-----------------------------------",
        ]
        if self.manifest:
            lines.append(f"Application   : {self.manifest.application}")
            lines.append(f"Target Version: {self.manifest.version}")
            lines.append(f"Release ID    : {self.manifest.release_id}")
            lines.append(f"Platform/Arch : {self.manifest.platform}/{self.manifest.architecture}")
        if self.artifact_path:
            lines.append(f"Artifact File : {self.artifact_path.name}")

        lines.append("")
        for finding in self.findings:
            tag = finding.status.value
            lines.append(f"[{tag:<12}] {finding.category:<16}: {finding.message}")

        lines.append("")
        lines.append(f"Overall Result: {self.status.value}")
        if self.is_verified:
            lines.append("Status        : UPDATE PACKAGE VERIFIED (Ready for installation)")
        else:
            lines.append("Status        : REJECTED (Do not install)")

        return "\n".join(lines)


def verify_update_package(
    package_path: Path | str,
    public_key: Optional[bytes] = None,
    allow_downgrade: bool = False,
    target_platform: Optional[str] = None,
    target_arch: Optional[str] = None,
) -> ReleaseVerificationResult:
    """Execute the complete release verification pipeline against a candidate package.

    Args:
        package_path: Path to a .zip package, or directory containing manifest and binary.
        public_key: 32-byte Ed25519 verification key override (uses trusted key if None).
        allow_downgrade: If True, permits target versions lower than installed version.
        target_platform: Optional platform override (e.g. 'windows', 'linux', 'darwin').
        target_arch: Optional architecture override (e.g. 'x64', 'arm64').

    Returns:
        ReleaseVerificationResult with granular findings and overall status.
    """
    pkg = Path(package_path).resolve()
    result = ReleaseVerificationResult(status=VerificationStatus.INVALID)

    if not pkg.exists():
        result.status = VerificationStatus.MISSING
        result.findings.append(
            VerificationFinding(
                category="Package Location",
                status=VerificationStatus.MISSING,
                message=f"Update package does not exist: {pkg}",
            )
        )
        return result

    # Staging area for archive contents
    extracted_dir: Optional[Path] = None
    if pkg.is_file() and pkg.suffix.lower() == ".zip":
        staging_dir = ApplicationPaths.get_update_staging_dir() / pkg.stem
        try:
            SafeZipExtractor.validate_and_extract(pkg, staging_dir)
            extracted_dir = staging_dir
            search_dir = staging_dir
            result.findings.append(
                VerificationFinding(
                    category="Archive Security",
                    status=VerificationStatus.VALID,
                    message="ZIP archive structure and path safety verified",
                )
            )
        except ArchiveSecurityError as exc:
            result.status = VerificationStatus.CORRUPTED
            result.findings.append(
                VerificationFinding(
                    category="Archive Security",
                    status=VerificationStatus.CORRUPTED,
                    message=f"Archive validation rejected: {exc}",
                )
            )
            return result
    elif pkg.is_dir():
        search_dir = pkg
    else:
        # Single executable file without manifest
        result.status = VerificationStatus.MISSING
        result.findings.append(
            VerificationFinding(
                category="Package Format",
                status=VerificationStatus.MISSING,
                message="Expected .zip archive or directory containing release-manifest.json",
            )
        )
        return result

    result.extracted_dir = extracted_dir

    # 1. Locate release-manifest.json
    manifest_file = search_dir / "release-manifest.json"
    if not manifest_file.is_file():
        result.status = VerificationStatus.MISSING
        result.findings.append(
            VerificationFinding(
                category="Release Manifest",
                status=VerificationStatus.MISSING,
                message="release-manifest.json not found in package",
            )
        )
        return result

    # 2. Parse and validate manifest schema
    try:
        manifest = ReleaseManifest.from_file(manifest_file)
        result.manifest = manifest
        result.findings.append(
            VerificationFinding(
                category="Manifest Schema",
                status=VerificationStatus.VALID,
                message=f"Valid manifest schema (v{manifest.manifest_version})",
            )
        )
    except ManifestError as exc:
        result.status = VerificationStatus.INVALID
        result.findings.append(
            VerificationFinding(
                category="Manifest Schema",
                status=VerificationStatus.INVALID,
                message=f"Manifest schema validation failed: {exc}",
            )
        )
        return result

    # 3. Platform & Architecture Compatibility Check
    curr_platform = target_platform or platform.system().lower()
    curr_machine = target_arch or platform.machine().lower()
    norm_arch = "x64" if curr_machine in {"amd64", "x86_64"} else ("arm64" if curr_machine in {"arm64", "aarch64"} else curr_machine)

    if manifest.platform != curr_platform or manifest.architecture != norm_arch:
        result.status = VerificationStatus.INCOMPATIBLE
        result.findings.append(
            VerificationFinding(
                category="Compatibility",
                status=VerificationStatus.INCOMPATIBLE,
                message=f"Incompatible target: manifest specifies {manifest.platform}/{manifest.architecture}, current system is {curr_platform}/{norm_arch}",
            )
        )
        return result
    else:
        result.findings.append(
            VerificationFinding(
                category="Compatibility",
                status=VerificationStatus.VALID,
                message=f"Platform ({curr_platform}) and architecture ({norm_arch}) compatible",
            )
        )

    # 4. Version Check & Downgrade Prevention
    target_semver = SemanticVersion.parse(manifest.version)
    installed_semver = get_current_semantic_version()

    if target_semver < installed_semver and not allow_downgrade:
        result.status = VerificationStatus.INCOMPATIBLE
        result.findings.append(
            VerificationFinding(
                category="Version Ordering",
                status=VerificationStatus.INCOMPATIBLE,
                message=f"Target version {target_semver} is older than installed version {installed_semver}. Pass --allow-downgrade to proceed.",
            )
        )
        return result
    else:
        result.findings.append(
            VerificationFinding(
                category="Version Ordering",
                status=VerificationStatus.VALID,
                message=f"Target version {target_semver} acceptable relative to installed {installed_semver}",
            )
        )

    # 5. Locate binary artifact specified in manifest
    artifact_meta = manifest.get_artifact_for_platform(curr_platform, norm_arch)
    if not artifact_meta:
        result.status = VerificationStatus.INCOMPATIBLE
        result.findings.append(
            VerificationFinding(
                category="Artifact Resolution",
                status=VerificationStatus.INCOMPATIBLE,
                message=f"No artifact in manifest for platform {curr_platform}/{norm_arch}",
            )
        )
        return result

    artifact_file = search_dir / artifact_meta.filename
    if not artifact_file.is_file():
        result.status = VerificationStatus.MISSING
        result.findings.append(
            VerificationFinding(
                category="Artifact Presence",
                status=VerificationStatus.MISSING,
                message=f"Specified artifact binary not found: '{artifact_meta.filename}'",
            )
        )
        return result

    result.artifact_path = artifact_file

    # 6. SHA-256 Hash Integrity Verification
    if not verify_sha256(artifact_file, artifact_meta.sha256):
        actual_sha = calculate_sha256(artifact_file)
        result.status = VerificationStatus.CORRUPTED
        result.findings.append(
            VerificationFinding(
                category="Artifact Integrity",
                status=VerificationStatus.CORRUPTED,
                message=f"SHA-256 hash mismatch: expected {artifact_meta.sha256[:16]}..., got {actual_sha[:16]}...",
            )
        )
        return result
    else:
        result.findings.append(
            VerificationFinding(
                category="Artifact Integrity",
                status=VerificationStatus.VALID,
                message=f"SHA-256 hash verified ({artifact_meta.sha256[:16]}...)",
            )
        )

    # 7. Authenticity: Digital Signature Verification
    active_key = public_key or get_trusted_public_key()
    if not manifest.signature:
        result.status = VerificationStatus.UNSIGNED
        result.findings.append(
            VerificationFinding(
                category="Authenticity",
                status=VerificationStatus.UNSIGNED,
                message="Release manifest contains no digital signature",
            )
        )
        return result

    if not manifest.verify_signature(active_key):
        result.status = VerificationStatus.UNTRUSTED
        result.findings.append(
            VerificationFinding(
                category="Authenticity",
                status=VerificationStatus.UNTRUSTED,
                message="Digital signature verification failed (untrusted or modified manifest)",
            )
        )
        return result
    else:
        result.findings.append(
            VerificationFinding(
                category="Authenticity",
                status=VerificationStatus.VALID,
                message="Ed25519 digital signature verified against trusted public key",
            )
        )

    # All gates passed successfully!
    result.status = VerificationStatus.VALID
    return result
