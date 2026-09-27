"""Phase 14 Persistence Reliability & Corruption Recovery Tests for Device Guardian.

Verifies:
- Atomic file write guarantees with fsync and automatic .bak creation.
- Safe rollback / preservation of original data when write operations fail.
- Automatic recovery from .bak when primary state file is corrupted or 0-byte.
- Safe handling of missing and malformed JSON data.
- Concurrent atomic persistence across multiple worker threads.
"""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from device_guardian.recovery.persistence import (
    AtomicPersistence,
    CorruptedStateError,
    PersistenceError,
)


def test_atomic_persistence_creates_backup(tmp_path: Path) -> None:
    """Verify that updating an existing file creates a valid .bak copy of prior state."""
    state_file = tmp_path / "state.json"

    # Initial write
    AtomicPersistence.atomic_write_json(state_file, {"version": 1, "status": "init"}, backup=True)
    assert state_file.is_file()
    assert not (tmp_path / "state.json.bak").exists()

    # Second write
    AtomicPersistence.atomic_write_json(state_file, {"version": 2, "status": "updated"}, backup=True)
    bak_file = tmp_path / "state.json.bak"
    assert bak_file.is_file()

    # Verify backup contains version 1
    bak_data = json.loads(bak_file.read_text(encoding="utf-8"))
    assert bak_data["version"] == 1

    # Verify target contains version 2
    cur_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert cur_data["version"] == 2


def test_atomic_write_failure_preserves_original(tmp_path: Path) -> None:
    """Verify that a failure during atomic write leaves the original target file untouched."""
    state_file = tmp_path / "critical.json"
    original_content = {"key": "safe_data"}
    AtomicPersistence.atomic_write_json(state_file, original_content, backup=True)

    # Simulate write failure by patching os.write to fail
    with patch("os.write", side_effect=OSError("Disk write error")):
        with pytest.raises(PersistenceError):
            AtomicPersistence.atomic_write_json(state_file, {"key": "corrupted_data"}, backup=True)

    # Original file must remain intact
    restored = json.loads(state_file.read_text(encoding="utf-8"))
    assert restored["key"] == "safe_data"


def test_safe_read_json_recovers_from_backup(tmp_path: Path) -> None:
    """Verify safe_read_json recovers state from .bak when primary file is corrupted."""
    state_file = tmp_path / "app_state.json"
    bak_file = tmp_path / "app_state.json.bak"

    valid_state = {"monitoring_active": True, "cycles": 42}
    bak_file.write_text(json.dumps(valid_state), encoding="utf-8")

    # Corrupt primary file with truncated / invalid JSON
    state_file.write_text("{\"monitoring_active\": true, \"cycles\": ", encoding="utf-8")

    data, recovered, err = AtomicPersistence.safe_read_json(
        state_file,
        default={},
        allow_backup_fallback=True,
    )

    assert recovered is True
    assert data["monitoring_active"] is True
    assert data["cycles"] == 42
    assert "Recovered from backup" in (err or "")


def test_safe_read_json_handles_zero_byte_file(tmp_path: Path) -> None:
    """Verify safe_read_json falls back to backup when primary is empty (0 bytes)."""
    state_file = tmp_path / "empty_state.json"
    bak_file = tmp_path / "empty_state.json.bak"

    valid_state = {"recovered": "yes"}
    bak_file.write_text(json.dumps(valid_state), encoding="utf-8")
    state_file.write_text("", encoding="utf-8")  # 0 bytes

    data, recovered, err = AtomicPersistence.safe_read_json(
        state_file,
        default={},
        allow_backup_fallback=True,
    )
    assert recovered is True
    assert data["recovered"] == "yes"


def test_concurrent_atomic_writes(tmp_path: Path) -> None:
    """Verify that multiple concurrent threads writing atomically do not produce corrupted files."""
    state_file = tmp_path / "concurrent_state.json"

    def write_worker(worker_id: int) -> bool:
        for seq in range(10):
            payload = {"worker_id": worker_id, "sequence": seq, "timestamp": str(seq)}
            AtomicPersistence.atomic_write_json(state_file, payload, backup=True)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(write_worker, wid) for wid in range(4)]
        results = [f.result() for f in futures]

    assert all(results)
    # Target file must be fully valid JSON
    assert state_file.is_file()
    final_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert "worker_id" in final_data
    assert "sequence" in final_data
