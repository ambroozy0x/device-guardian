"""Device Guardian secure updates, release integrity, and rollback package (Phase 7).

Provides:
- Deterministic release metadata & release-manifest.json schema.
- Streaming SHA-256 integrity calculation and verification.
- RFC 8032 Ed25519 digital signature generation and verification.
- Path-traversal-resistant ZIP archive validation and extraction.
- Multi-gate release verification pipeline.
- Atomic update transaction state machine and crash recovery.
- Safe installation and verified rollback management.
"""

from device_guardian.updates.archive import ArchiveSecurityError, SafeZipExtractor
from device_guardian.updates.crypto import (
    calculate_sha256,
    canonicalize_json,
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
    verify_sha256,
)
from device_guardian.updates.installer import InstallationResult, UpdateInstaller
from device_guardian.updates.keys import (
    get_key_fingerprint,
    get_trusted_public_key,
    set_trusted_public_key_override,
)
from device_guardian.updates.manifest import ManifestError, ReleaseArtifact, ReleaseManifest
from device_guardian.updates.transaction import (
    TransactionState,
    UpdateTransaction,
    check_and_recover_interrupted_transaction,
)
from device_guardian.updates.verifier import (
    ReleaseVerificationResult,
    VerificationFinding,
    VerificationStatus,
    verify_update_package,
)

__all__ = [
    "ArchiveSecurityError",
    "InstallationResult",
    "ManifestError",
    "ReleaseArtifact",
    "ReleaseManifest",
    "ReleaseVerificationResult",
    "SafeZipExtractor",
    "TransactionState",
    "UpdateInstaller",
    "UpdateTransaction",
    "VerificationFinding",
    "VerificationStatus",
    "calculate_sha256",
    "canonicalize_json",
    "check_and_recover_interrupted_transaction",
    "generate_ed25519_keypair",
    "get_key_fingerprint",
    "get_trusted_public_key",
    "set_trusted_public_key_override",
    "sign_ed25519",
    "verify_ed25519",
    "verify_sha256",
    "verify_update_package",
]
