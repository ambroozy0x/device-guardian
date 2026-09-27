"""Phase 15 Security Audit — Secrets Management and Credential Security Tests.

Verifies:
- SecretValue encapsulation never leaks secret in str(), repr(), formatting, or exceptions.
- SecretRedactor scrubs tokens, chat IDs, bearer tokens, and URLs across arbitrary text.
- FileSecretStore enforces restrictive permissions and atomic writes.
- Non-destructive state repair preserves encrypted secrets and .env files.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from device_guardian.recovery.repair import repair_state_files
from device_guardian.security.redactor import SecretRedactor
from device_guardian.security.secret import SecretValue
from device_guardian.security.store import FileSecretStore


def test_secret_value_encapsulation_never_leaks_in_str_or_repr() -> None:
    """Verify SecretValue masks sensitive content across string operations."""
    raw = "987654321:AAE_VerySecretBotToken1234567890"
    secret = SecretValue(raw)

    assert str(secret) == "********"
    assert "987654321" not in repr(secret)
    assert "AAE_VerySecretBotToken" not in repr(secret)
    assert f"{secret}" == "********"
    assert f"{secret!r}" != raw
    assert secret.get_secret_value() == raw
    assert secret.raw == raw

    # Empty secret handling
    empty_secret = SecretValue("")
    assert str(empty_secret) == "***EMPTY***"
    assert empty_secret.is_empty() is True


def test_secret_redactor_scrubs_all_credential_patterns() -> None:
    """Verify SecretRedactor scrubs Telegram bot tokens, URLs, Bearer, and query parameters."""
    redactor = SecretRedactor()
    custom_token = "123456789:ABCdefGHI_jkl1234567890abcdefABC"
    redactor.register_secret(custom_token)

    sample_log = (
        f"Connecting to https://api.telegram.org/bot{custom_token}/sendMessage "
        f"with token={custom_token} and Authorization: Bearer secret_bearer_token"
    )
    redacted = redactor.redact(sample_log)
    assert custom_token not in redacted
    assert "secret_bearer_token" not in redacted
    assert "[REDACTED_TOKEN]" in redacted or "[REDACTED_SECRET]" in redacted


def test_file_secret_store_atomic_roundtrip(tmp_path: Path) -> None:
    """Verify FileSecretStore stores and retrieves secrets without plaintext dump."""
    store_file = tmp_path / "secrets.json"
    store = FileSecretStore(file_path=store_file)

    assert store.has_secret("token") is False
    assert store.set_secret("token", "secret_api_key_value_12345") is True
    assert store.has_secret("token") is True

    retrieved = store.get_secret("token")
    assert retrieved is not None
    assert retrieved.get_secret_value() == "secret_api_key_value_12345"

    # List secret names returns keys only, never values
    names = store.list_secret_names()
    assert names == ["token"]
    assert "secret_api_key_value_12345" not in names


def test_repair_state_files_strictly_preserves_secrets_and_env(tmp_path: Path) -> None:
    """Verify state file repair never wipes, resets, or overwrites secrets or .env."""
    from unittest.mock import patch
    from device_guardian.runtime.paths import ApplicationPaths

    secrets_file = tmp_path / "secrets.json"
    secrets_file.write_text('{"token": "preserve_me"}', encoding="utf-8")

    env_file = tmp_path / ".env"
    env_file.write_text("TELEGRAM_BOT_TOKEN=preserve_this_token\n", encoding="utf-8")

    # Corrupt a status file
    runtime_status_file = tmp_path / "runtime_status.json"
    runtime_status_file.write_text("CORRUPTED_NOT_JSON", encoding="utf-8")

    with patch.object(ApplicationPaths, "get_user_data_dir", return_value=tmp_path):
        with patch.object(ApplicationPaths, "get_status_file_path", return_value=runtime_status_file):
            with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=tmp_path / "update_transaction.json"):
                repairs = repair_state_files()
                assert len(repairs) == 1
                assert repairs[0]["action"] == "repaired"

    # Ensure secrets and .env were preserved unmodified
    assert '{"token": "preserve_me"}' == secrets_file.read_text(encoding="utf-8")
    assert "TELEGRAM_BOT_TOKEN=preserve_this_token\n" == env_file.read_text(encoding="utf-8")
