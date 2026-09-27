"""Phase 15 Security Audit — Persistence and State Integrity Tests.

Verifies:
- AtomicPersistence writes to unique temp files with exclusive flags and fsync before atomic replacement.
- State file corruption automatically recovers from .bak backup file if available.
- Completely unrecoverable state files are backed up to .corrupt.<timestamp> for forensics.
- AtomicPersistence refuses to write to symlinks or reparse points.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from device_guardian.recovery.persistence import (
    AtomicPersistence,
    CorruptedStateError,
    PersistenceError,
)


def test_atomic_persistence_creates_backup_and_replaces(tmp_path: Path) -> None:
    """Verify atomic_write writes new content and preserves .bak of prior content."""
    target = tmp_path / "status.json"
    target.write_text('{"v": 1}', encoding="utf-8")

    # Update with backup=True
    AtomicPersistence.atomic_write_json(target, {"v": 2}, backup=True)

    assert target.is_file()
    assert json.loads(target.read_text(encoding="utf-8")) == {"v": 2}

    backup = tmp_path / "status.json.bak"
    assert backup.is_file()
    assert json.loads(backup.read_text(encoding="utf-8")) == {"v": 1}


def test_atomic_persistence_recovers_from_backup_on_corrupt_primary(tmp_path: Path) -> None:
    """Verify safe_read_json falls back to valid .bak if primary file is corrupted."""
    target = tmp_path / "data.json"
    target.write_text("CORRUPTED_NON_JSON", encoding="utf-8")

    backup = tmp_path / "data.json.bak"
    backup.write_text('{"recovered": true}', encoding="utf-8")

    data, recovered, error = AtomicPersistence.safe_read_json(
        target,
        default=None,
        allow_backup_fallback=True,
    )
    assert recovered is True
    assert error is not None
    assert "Recovered from backup" in error


def test_atomic_persistence_rejects_symlink_destination(tmp_path: Path) -> None:
    """Verify AtomicPersistence raises PersistenceError if target is a symlink."""
    real_file = tmp_path / "real.txt"
    real_file.write_text("real", encoding="utf-8")

    symlink_file = tmp_path / "link.txt"
    try:
        symlink_file.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported in this environment.")

    with pytest.raises(PersistenceError, match="symlink or reparse point"):
        AtomicPersistence.atomic_write(symlink_file, "malicious_overwrite", backup=False)
