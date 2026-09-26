"""Trusted public key management for release authenticity verification (Phase 7).

Manages the trusted Ed25519 public verification key used to validate official release manifests.
The public key is version-controlled and auditable.
CRITICAL: Private signing keys are NEVER committed or bundled in this repository.
"""

from __future__ import annotations

import binascii
import hashlib
import os
from typing import Optional

# Official Device Guardian Root Release Verification Public Key (Ed25519, 32-byte hex)
# Corresponds to official release authority "Device Guardian Official Builds (2026)"
# Note: For test suites, key override functions allow ephemeral test keypairs.
DEFAULT_TRUSTED_PUBLIC_KEY_HEX = (
    "e5c3e8e2b8655c65a443a9b736b442b58832a89d0fef39c2d1b7147e8523c14a"
)

_trusted_public_key_override: Optional[bytes] = None


def set_trusted_public_key_override(key_bytes: Optional[bytes]) -> None:
    """Override the trusted public key for test suite isolation."""
    global _trusted_public_key_override
    _trusted_public_key_override = key_bytes


def get_trusted_public_key() -> bytes:
    """Obtain the active 32-byte Ed25519 trusted public verification key.

    Priority:
    1. Programmatic override (tests/fixtures)
    2. DEVICE_GUARDIAN_PUBLIC_KEY environment variable (hex encoded)
    3. Built-in default trusted public key
    """
    if _trusted_public_key_override is not None:
        return _trusted_public_key_override

    env_key = os.environ.get("DEVICE_GUARDIAN_PUBLIC_KEY")
    if env_key:
        try:
            parsed = binascii.unhexlify(env_key.strip())
            if len(parsed) == 32:
                return parsed
        except Exception:
            pass

    return binascii.unhexlify(DEFAULT_TRUSTED_PUBLIC_KEY_HEX)


def get_key_fingerprint(public_key: bytes) -> str:
    """Generate human-readable SHA-256 fingerprint for a public key (e.g. 'SHA256:abcd...')."""
    digest = hashlib.sha256(public_key).hexdigest()
    return f"SHA256:{digest[:16].upper()}"
