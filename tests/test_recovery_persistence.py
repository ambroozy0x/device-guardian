"""Unit tests for Phase 8 atomic persistence and corruption recovery."""

import json
import os
from pathlib import Path
import pytest

from device_guardian.recovery.persistence import (
    AtomicPersistence,
    CorruptedStateError,
    PersistenceError,
)
from tests.failure_injection import inject_filesystem_error


def test_atomic_write_creates_file(tmp_path: Path):
    """Verify atomic_write successfully creates target file."""
    target = tmp_path / "test_file.txt"
    written = AtomicPersistence.atomic_write(target, "Hello World", backup=False)

    assert written == target
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == "Hello World"


def test_atomic_write_creates_backup(tmp_path: Path):
    """Verify atomic_write creates a .bak backup of previous content when backup=True."""
    target = tmp_path / "test_file.txt"
    backup = tmp_path / "test_file.txt.bak"

    # Initial write
    AtomicPersistence.atomic_write(target, "Version 1", backup=True)
    assert not backup.exists()  # No backup on very first write

    # Second write
    AtomicPersistence.atomic_write(target, "Version 2", backup=True)
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == "Version 1"
    assert target.read_text(encoding="utf-8") == "Version 2"


def test_atomic_write_json_roundtrip(tmp_path: Path):
    """Verify atomic_write_json writes and formats valid JSON."""
    target = tmp_path / "test_data.json"
    data = {"name": "Guardian", "count": 42, "items": ["a", "b"]}

    AtomicPersistence.atomic_write_json(target, data, backup=True)
    assert target.is_file()

    read_back = json.loads(target.read_text(encoding="utf-8"))
    assert read_back == data


def test_atomic_write_cleans_up_temp_on_failure(tmp_path: Path):
    """Verify temporary files are unlinked if atomic replacement fails."""
    target = tmp_path / "target.txt"
    target.write_text("Original Content")

    with inject_filesystem_error("os.replace", OSError, "Disk I/O error"):
        with pytest.raises(PersistenceError):
            AtomicPersistence.atomic_write(target, "New Content", backup=True)

    # Original content preserved
    assert target.read_text() == "Original Content"
    # No temporary files left behind
    temp_files = list(tmp_path.glob("target.txt.tmp.*"))
    assert len(temp_files) == 0


def test_safe_read_json_valid_file(tmp_path: Path):
    """Verify safe_read_json returns parsed dictionary from healthy file."""
    target = tmp_path / "valid.json"
    target.write_text(json.dumps({"key": "value", "num": 10}))

    data, recovered, err = AtomicPersistence.safe_read_json(target)
    assert data == {"key": "value", "num": 10}
    assert recovered is False
    assert err is None


def test_safe_read_json_fallback_to_backup(tmp_path: Path):
    """Verify safe_read_json recovers cleanly from .bak when primary file is corrupted."""
    target = tmp_path / "corrupt.json"
    backup = tmp_path / "corrupt.json.bak"

    # Write corrupt data to primary and valid data to backup
    target.write_text("{broken json: missing", encoding="utf-8")
    backup_data = {"recovered": True, "state": "healthy"}
    backup.write_text(json.dumps(backup_data), encoding="utf-8")

    data, recovered, err = AtomicPersistence.safe_read_json(target, allow_backup_fallback=True)
    assert data == backup_data
    assert recovered is True
    assert err is not None
    assert "Recovered from backup" in err


def test_safe_read_json_fallback_when_empty(tmp_path: Path):
    """Verify zero-byte primary file falls back to backup."""
    target = tmp_path / "empty.json"
    backup = tmp_path / "empty.json.bak"

    target.write_text("", encoding="utf-8")
    backup_data = {"source": "backup"}
    backup.write_text(json.dumps(backup_data), encoding="utf-8")

    data, recovered, err = AtomicPersistence.safe_read_json(target, allow_backup_fallback=True)
    assert data == backup_data
    assert recovered is True


def test_safe_read_json_unrecoverable_returns_default(tmp_path: Path):
    """Verify unrecoverable missing or corrupted file returns supplied default."""
    target = tmp_path / "unrecoverable.json"
    backup = tmp_path / "unrecoverable.json.bak"

    target.write_text("corrupted", encoding="utf-8")
    backup.write_text("also_corrupted", encoding="utf-8")

    default_val = {"default": True}
    data, recovered, err = AtomicPersistence.safe_read_json(target, default=default_val)
    assert data == default_val
    assert recovered is False
    assert err is not None


def test_safe_read_json_schema_validation_rejection(tmp_path: Path):
    """Verify schema validator rejects data and triggers backup recovery."""
    target = tmp_path / "schema_test.json"
    backup = tmp_path / "schema_test.json.bak"

    # Target has invalid schema (missing required key)
    target.write_text(json.dumps({"wrong_key": 123}))
    backup.write_text(json.dumps({"required_key": 456}))

    def validator(d: dict) -> bool:
        return isinstance(d, dict) and "required_key" in d

    data, recovered, err = AtomicPersistence.safe_read_json(
        target,
        schema_validator=validator,
        allow_backup_fallback=True,
    )
    assert data == {"required_key": 456}
    assert recovered is True
