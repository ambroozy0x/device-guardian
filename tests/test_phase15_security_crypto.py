"""Phase 15 Security Audit — Cryptographic Security Tests.

Verifies:
- RFC 8032 Ed25519 digital signature generation and verification.
- Tampered or corrupted signatures strictly fail closed.
- Canonical JSON deterministic serialization prevents signature malleability.
- Streaming SHA-256 chunked calculation detects single-byte modifications.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from device_guardian.updates.crypto import (
    calculate_sha256,
    canonicalize_json,
    ed25519_sign,
    ed25519_verify,
    generate_keypair,
    verify_sha256,
)


def test_ed25519_signature_verification_authentic() -> None:
    """Verify authentic Ed25519 signatures verify successfully."""
    priv, pub = generate_keypair()
    message = b"Device Guardian Release Payload v0.1.0"
    sig = ed25519_sign(message, priv, pub)
    assert len(sig) == 64
    assert ed25519_verify(message, sig, pub) is True


def test_ed25519_signature_verification_rejects_tampered_message() -> None:
    """Verify any modification to signed message fails verification."""
    priv, pub = generate_keypair()
    message = b"Authentic update content"
    sig = ed25519_sign(message, priv, pub)

    tampered_message = b"Tampered update content"
    assert ed25519_verify(tampered_message, sig, pub) is False


def test_ed25519_signature_verification_rejects_tampered_signature() -> None:
    """Verify any modification to signature bytes fails verification."""
    priv, pub = generate_keypair()
    message = b"Test message payload"
    sig = bytearray(ed25519_sign(message, priv, pub))
    sig[0] ^= 0xFF  # Flip bits
    assert ed25519_verify(message, bytes(sig), pub) is False


def test_canonicalize_json_deterministic() -> None:
    """Verify JSON canonicalization is sorted, compact, and deterministic."""
    dict1 = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    dict2 = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}
    c1 = canonicalize_json(dict1)
    c2 = canonicalize_json(dict2)
    assert c1 == c2
    assert c1 == b'{"a":1,"b":2,"nested":{"y":8,"z":9}}'


def test_streaming_sha256_detects_single_byte_change(tmp_path: Path) -> None:
    """Verify calculate_sha256 and verify_sha256 detect single byte corruptions."""
    target_file = tmp_path / "binary.bin"
    target_file.write_bytes(b"A" * 100000)

    original_hash = calculate_sha256(target_file)
    assert verify_sha256(target_file, original_hash) is True

    # Modify single byte
    corrupted_data = b"A" * 50000 + b"B" + b"A" * 49999
    target_file.write_bytes(corrupted_data)
    assert verify_sha256(target_file, original_hash) is False
