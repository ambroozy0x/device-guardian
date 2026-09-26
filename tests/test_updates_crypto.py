"""Tests for Phase 7 cryptographic primitives (SHA-256 and pure-Python Ed25519)."""

import hashlib
from pathlib import Path
import pytest

from device_guardian.updates.crypto import (
    calculate_sha256,
    canonicalize_json,
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
    verify_sha256,
)


def test_sha256_streaming(tmp_path: Path):
    """Verify streaming SHA-256 calculation matches standard hashlib."""
    test_file = tmp_path / "sample_binary.bin"
    # Write 256KB of pseudorandom/pattern data
    content = b"DEVICE_GUARDIAN_RELEASE_PAYLOAD" * 8192
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    computed = calculate_sha256(test_file)

    assert computed == expected
    assert len(computed) == 64
    assert verify_sha256(test_file, expected) is True
    assert verify_sha256(test_file, "0" * 64) is False


def test_canonicalize_json():
    """Verify deterministic canonical JSON serialization."""
    data1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    data2 = {"a": 1, "c": [3, 2, 1], "b": 2}

    canon1 = canonicalize_json(data1)
    canon2 = canonicalize_json(data2)

    assert canon1 == canon2
    # Verify no trailing spaces, compact separators
    assert b" " not in canon1 or b'" "' in canon1


def test_ed25519_keypair_generation():
    """Verify generating Ed25519 keypair produces valid 32-byte keys."""
    priv, pub = generate_ed25519_keypair()
    assert isinstance(priv, bytes)
    assert isinstance(pub, bytes)
    assert len(priv) == 32
    assert len(pub) == 32
    assert priv != pub


def test_ed25519_sign_and_verify_valid():
    """Verify signing and verifying an authentic message with Ed25519."""
    priv, pub = generate_ed25519_keypair()
    message = b"Device Guardian Release Manifest v0.1.0"

    signature = sign_ed25519(message, priv)
    assert isinstance(signature, bytes)
    assert len(signature) == 64

    is_valid = verify_ed25519(message, signature, pub)
    assert is_valid is True


def test_ed25519_tampered_message_rejection():
    """Verify signature verification fails if message is modified."""
    priv, pub = generate_ed25519_keypair()
    message = b"Legitimate Update Manifest"
    tampered = b"Malicious Modified Manifest"

    signature = sign_ed25519(message, priv)
    assert verify_ed25519(tampered, signature, pub) is False


def test_ed25519_tampered_signature_rejection():
    """Verify verification fails if signature bytes are corrupted."""
    priv, pub = generate_ed25519_keypair()
    message = b"Device Guardian Release Payload"

    signature = bytearray(sign_ed25519(message, priv))
    # Flip one byte
    signature[10] ^= 0xFF

    assert verify_ed25519(message, bytes(signature), pub) is False


def test_ed25519_wrong_key_rejection():
    """Verify verification fails with a different public key."""
    priv1, pub1 = generate_ed25519_keypair()
    _priv2, pub2 = generate_ed25519_keypair()
    message = b"Device Guardian Update"

    signature = sign_ed25519(message, priv1)
    assert verify_ed25519(message, signature, pub2) is False
