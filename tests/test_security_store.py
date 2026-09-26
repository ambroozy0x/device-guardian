"""Tests for SecretStore implementations: FileSecretStore and WindowsDPAPISecretStore (Phase 6)."""

import os
from pathlib import Path
import platform
import pytest

from device_guardian.security.secret import SecretValue
from device_guardian.security.store import (
    FileSecretStore,
    WindowsDPAPISecretStore,
    create_default_secret_store,
)


def test_file_secret_store_lifecycle(tmp_path):
    """Verify FileSecretStore CRUD operations."""
    store_file = tmp_path / "test_secrets.json"
    store = FileSecretStore(file_path=store_file)

    assert store.get_backend_name() == "Filesystem (Restricted Permissions)"
    assert store.list_secret_names() == []
    assert not store.has_secret("telegram_token")

    # Set secret
    assert store.set_secret("telegram_token", "secret_value_12345")
    assert store.has_secret("telegram_token")
    assert "telegram_token" in store.list_secret_names()

    # Get secret
    retrieved = store.get_secret("telegram_token")
    assert retrieved is not None
    assert isinstance(retrieved, SecretValue)
    assert retrieved.get_secret_value() == "secret_value_12345"

    # Set secret using SecretValue
    store.set_secret("chat_id", SecretValue("987654321"))
    assert store.get_secret("chat_id") == "987654321"

    # Delete secret
    assert store.delete_secret("telegram_token")
    assert not store.has_secret("telegram_token")
    assert store.get_secret("telegram_token") is None

    # Delete non-existent (idempotent success)
    assert store.delete_secret("non_existent") is True


def test_file_secret_store_permissions(tmp_path):
    """Verify stored file exists and has restricted access permissions."""
    store_file = tmp_path / "perm_secrets.json"
    store = FileSecretStore(file_path=store_file)
    store.set_secret("key", "value")

    assert store_file.is_file()
    # On non-Windows platforms, verify 0600 mode
    if platform.system() != "Windows":
        mode = oct(store_file.stat().st_mode & 0o777)
        assert mode == "0o600"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows DPAPI requires Windows OS")
def test_windows_dpapi_secret_store(tmp_path):
    """Verify Windows DPAPI encrypts and decrypts secrets natively."""
    store_file = tmp_path / "dpapi_secrets.dat"
    store = WindowsDPAPISecretStore(file_path=store_file)

    assert "Windows DPAPI" in store.get_backend_name()

    token_secret = "123456789:ABC_DPAPI_SECRET_TOKEN"
    assert store.set_secret("TELEGRAM_BOT_TOKEN", token_secret)

    # Verify physical file on disk contains encrypted ciphertext, NOT plaintext
    raw_file_bytes = store_file.read_bytes()
    assert token_secret.encode("utf-8") not in raw_file_bytes

    # Retrieve and decrypt
    retrieved = store.get_secret("TELEGRAM_BOT_TOKEN")
    assert retrieved is not None
    assert retrieved.get_secret_value() == token_secret

    # List secret keys
    keys = store.list_secret_names()
    assert "TELEGRAM_BOT_TOKEN" in keys

    # Delete secret
    assert store.delete_secret("TELEGRAM_BOT_TOKEN")
    assert store.get_secret("TELEGRAM_BOT_TOKEN") is None


def test_create_default_secret_store_factory():
    """Verify create_default_secret_store returns appropriate backend for current platform."""
    store = create_default_secret_store()
    if platform.system() == "Windows":
        assert isinstance(store, WindowsDPAPISecretStore)
    else:
        assert isinstance(store, FileSecretStore)
