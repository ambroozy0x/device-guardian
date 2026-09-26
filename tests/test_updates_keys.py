"""Tests for Phase 7 trusted public key management."""

import pytest

from device_guardian.updates.crypto import generate_ed25519_keypair
from device_guardian.updates.keys import (
    get_key_fingerprint,
    get_trusted_public_key,
    set_trusted_public_key_override,
)


def test_trusted_public_key_default():
    """Verify default embedded public key is 32 bytes."""
    set_trusted_public_key_override(None)
    key = get_trusted_public_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_set_trusted_public_key_override():
    """Verify setting test key override and reverting."""
    priv, pub = generate_ed25519_keypair()
    try:
        set_trusted_public_key_override(pub)
        assert get_trusted_public_key() == pub
    finally:
        set_trusted_public_key_override(None)


def test_key_fingerprint_format():
    """Verify key fingerprint generates consistent SHA256 prefix."""
    priv, pub = generate_ed25519_keypair()
    fp = get_key_fingerprint(pub)
    assert fp.startswith("SHA256:")
    assert len(fp) == 7 + 16  # "SHA256:" + 16 hex chars
