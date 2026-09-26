"""Release manifest data model and schema validation for Device Guardian (Phase 7).

Represents release-manifest.json, containing artifact metadata, hashes,
platform specifications, and digital signatures.
"""

from __future__ import annotations

import binascii
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Optional

from device_guardian.updates.crypto import canonicalize_json, sign_ed25519, verify_ed25519
from device_guardian.version import SemanticVersion


class ManifestError(Exception):
    """Raised when a release manifest is invalid, corrupted, or unsupported."""
    pass


@dataclass
class ReleaseArtifact:
    """Metadata describing a single distribution artifact."""

    filename: str
    platform: str
    architecture: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "platform": self.platform,
            "architecture": self.architecture,
            "sha256": self.sha256.lower(),
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReleaseArtifact:
        required = {"filename", "platform", "architecture", "sha256", "size_bytes"}
        missing = required - set(data.keys())
        if missing:
            raise ManifestError(f"Artifact missing required fields: {', '.join(sorted(missing))}")

        sha = str(data["sha256"]).strip().lower()
        if len(sha) != 64 or not re.match(r"^[0-9a-f]{64}$", sha):
            raise ManifestError(f"Artifact has invalid SHA-256 hash: '{data['sha256']}'")

        try:
            size = int(data["size_bytes"])
            if size <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            raise ManifestError(f"Artifact has invalid size_bytes: '{data.get('size_bytes')}'")

        return cls(
            filename=str(data["filename"]).strip(),
            platform=str(data["platform"]).strip().lower(),
            architecture=str(data["architecture"]).strip().lower(),
            sha256=sha,
            size_bytes=size,
        )


@dataclass
class ReleaseManifest:
    """Authoritative release manifest schema for Device Guardian updates."""

    version: str
    release_id: str
    release_date: str
    platform: str
    architecture: str
    artifacts: list[ReleaseArtifact]
    application: str = "Device Guardian"
    manifest_version: str = "1.0"
    signature: Optional[str] = None

    def get_canonical_payload(self) -> bytes:
        """Produce canonical JSON representation of the manifest excluding the signature."""
        data = {
            "application": self.application,
            "manifest_version": self.manifest_version,
            "version": self.version,
            "release_id": self.release_id,
            "release_date": self.release_date,
            "platform": self.platform,
            "architecture": self.architecture,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }
        return canonicalize_json(data)

    def sign(self, private_key: bytes) -> str:
        """Sign this manifest with an Ed25519 private key seed.

        Args:
            private_key: 32-byte Ed25519 private seed.

        Returns:
            Hex-encoded 64-byte Ed25519 digital signature.
        """
        payload = self.get_canonical_payload()
        sig_bytes = sign_ed25519(payload, private_key)
        self.signature = binascii.hexlify(sig_bytes).decode("ascii")
        return self.signature

    def verify_signature(self, public_key: bytes) -> bool:
        """Verify the digital signature of this manifest.

        Args:
            public_key: 32-byte Ed25519 trusted public verification key.

        Returns:
            True if signature is present and cryptographically authentic, False otherwise.
        """
        if not self.signature:
            return False
        try:
            sig_bytes = binascii.unhexlify(self.signature.strip())
            payload = self.get_canonical_payload()
            return verify_ed25519(payload, sig_bytes, public_key)
        except Exception:
            return False

    def get_artifact_for_platform(
        self,
        platform_name: str,
        arch_name: str,
    ) -> Optional[ReleaseArtifact]:
        """Find the matching artifact for the specified OS platform and architecture."""
        norm_plat = platform_name.strip().lower()
        norm_arch = arch_name.strip().lower()
        for art in self.artifacts:
            if art.platform == norm_plat and art.architecture == norm_arch:
                return art
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to serializable dictionary."""
        data = {
            "application": self.application,
            "manifest_version": self.manifest_version,
            "version": self.version,
            "release_id": self.release_id,
            "release_date": self.release_date,
            "platform": self.platform,
            "architecture": self.architecture,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }
        if self.signature:
            data["signature"] = self.signature
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serialize manifest to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, path: Path | str) -> Path:
        """Save manifest atomically to disk."""
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_target = target.with_suffix(".tmp")
        tmp_target.write_text(self.to_json(), encoding="utf-8")
        tmp_target.replace(target)
        return target

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReleaseManifest:
        """Construct and validate ReleaseManifest from a dictionary.

        Raises:
            ManifestError: If schema validation fails.
        """
        if not isinstance(data, dict):
            raise ManifestError("Manifest root must be a JSON object.")

        required_keys = {"version", "release_id", "platform", "architecture", "artifacts"}
        missing = required_keys - set(data.keys())
        if missing:
            raise ManifestError(f"Manifest missing required keys: {', '.join(sorted(missing))}")

        # Validate semver
        version_str = str(data["version"]).strip()
        try:
            SemanticVersion.parse(version_str)
        except ValueError as exc:
            raise ManifestError(f"Manifest version is invalid semver: {exc}")

        raw_artifacts = data.get("artifacts")
        if not isinstance(raw_artifacts, list) or len(raw_artifacts) == 0:
            raise ManifestError("Manifest 'artifacts' must be a non-empty list.")

        artifacts = [ReleaseArtifact.from_dict(item) for item in raw_artifacts]

        return cls(
            application=str(data.get("application", "Device Guardian")).strip(),
            manifest_version=str(data.get("manifest_version", "1.0")).strip(),
            version=version_str,
            release_id=str(data["release_id"]).strip(),
            release_date=str(data.get("release_date", "")).strip(),
            platform=str(data["platform"]).strip().lower(),
            architecture=str(data["architecture"]).strip().lower(),
            artifacts=artifacts,
            signature=data.get("signature"),
        )

    @classmethod
    def from_file(cls, path: Path | str) -> ReleaseManifest:
        """Load and validate manifest from a file.

        Raises:
            ManifestError: If file not found or contains invalid JSON.
        """
        target = Path(path).resolve()
        if not target.is_file():
            raise ManifestError(f"Release manifest file not found: {target}")
        try:
            content = target.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"Release manifest contains malformed JSON: {exc}")
        except Exception as exc:
            raise ManifestError(f"Failed to read release manifest: {exc}")

        return cls.from_dict(data)

    load_from_file = from_file
