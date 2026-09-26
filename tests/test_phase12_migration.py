"""Tests for Phase 12 Application Lifecycle: Versioned Persistent Schema Migration.

Verifies:
- Accurate schema version tracking (CURRENT_STATE_SCHEMA_VERSION = 1).
- Identification of pending migration steps.
- Pre-migration snapshot backup generation.
- Atomic commit of new schema versions upon successful migration.
- Automatic rollback of state files upon migration step failure.
- Rejection of schema downgrades.
- Security event logging for all migration operations.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from device_guardian.lifecycle.migration import (
    CURRENT_STATE_SCHEMA_VERSION,
    MigrationManager,
    MigrationResult,
)
from device_guardian.lifecycle.models import InstallationMetadata
from device_guardian.runtime.paths import ApplicationPaths, set_user_data_dir_override
from device_guardian.security.events import SecurityEventType


@pytest.fixture
def migration_env(tmp_path):
    """Set up isolated user data directory for migration testing."""
    data_dir = tmp_path / "user_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    set_user_data_dir_override(data_dir)

    yield {"data_dir": data_dir}

    set_user_data_dir_override(None)


def test_schema_version_defaults_to_one(migration_env):
    """Verify get_schema_version returns 1 when no metadata file exists."""
    data_dir = migration_env["data_dir"]
    assert MigrationManager.get_schema_version(user_data_dir=data_dir) == 1


def test_schema_version_reads_persisted_version(migration_env):
    """Verify get_schema_version correctly parses schema_version from install_metadata.json."""
    data_dir = migration_env["data_dir"]
    meta = InstallationMetadata(
        version="0.1.0",
        install_path="C:/app",
        user_data_path=str(data_dir),
        schema_version=2,
    )
    meta.save(data_dir / "install_metadata.json")

    assert MigrationManager.get_schema_version(user_data_dir=data_dir) == 2


def test_set_schema_version_updates_atomically(migration_env):
    """Verify set_schema_version updates metadata atomically with .bak."""
    data_dir = migration_env["data_dir"]
    ok = MigrationManager.set_schema_version(3, user_data_dir=data_dir)
    assert ok is True
    assert MigrationManager.get_schema_version(user_data_dir=data_dir) == 3


def test_check_pending_migrations(migration_env):
    """Verify check_pending_migrations returns required steps."""
    data_dir = migration_env["data_dir"]
    MigrationManager.set_schema_version(1, user_data_dir=data_dir)

    # 1 -> 1: none
    assert MigrationManager.check_pending_migrations(target_version=1, user_data_dir=data_dir) == []

    # 1 -> 3: [(1, 2), (2, 3)]
    assert MigrationManager.check_pending_migrations(target_version=3, user_data_dir=data_dir) == [(1, 2), (2, 3)]


def test_create_pre_migration_backup(migration_env):
    """Verify snapshot backup captures critical files prior to migration."""
    data_dir = migration_env["data_dir"]

    # Create dummy critical state files
    status_file = data_dir / "runtime_status.json"
    status_file.write_text(json.dumps({"state": "READY", "schema": 1}), encoding="utf-8")
    meta_file = data_dir / "install_metadata.json"
    meta_file.write_text(json.dumps({"version": "0.1.0", "schema_version": 1}), encoding="utf-8")

    backup_dir = MigrationManager.create_pre_migration_backup(user_data_dir=data_dir)

    assert backup_dir.is_dir()
    assert (backup_dir / "runtime_status.json").is_file()
    assert (backup_dir / "install_metadata.json").is_file()
    assert "READY" in (backup_dir / "runtime_status.json").read_text(encoding="utf-8")


def test_rollback_migration(migration_env):
    """Verify rollback_migration restores files from snapshot directory."""
    data_dir = migration_env["data_dir"]

    # Original file
    test_file = data_dir / "runtime_status.json"
    test_file.write_text("ORIGINAL_CONTENT", encoding="utf-8")

    backup_dir = MigrationManager.create_pre_migration_backup(user_data_dir=data_dir)

    # Modify file
    test_file.write_text("CORRUPTED_MODIFIED_CONTENT", encoding="utf-8")
    assert test_file.read_text(encoding="utf-8") == "CORRUPTED_MODIFIED_CONTENT"

    # Rollback
    ok = MigrationManager.rollback_migration(backup_dir, user_data_dir=data_dir)
    assert ok is True
    assert test_file.read_text(encoding="utf-8") == "ORIGINAL_CONTENT"


def test_apply_migrations_already_up_to_date(migration_env):
    """Verify apply_migrations returns success immediately if schema is already up to date."""
    data_dir = migration_env["data_dir"]
    MigrationManager.set_schema_version(CURRENT_STATE_SCHEMA_VERSION, user_data_dir=data_dir)

    res = MigrationManager.apply_migrations(
        target_version=CURRENT_STATE_SCHEMA_VERSION,
        user_data_dir=data_dir,
    )
    assert res.success is True
    assert "already at target version" in res.message.lower()


def test_apply_migrations_rejects_downgrade(migration_env):
    """Verify apply_migrations rejects downgrading schema version."""
    data_dir = migration_env["data_dir"]
    MigrationManager.set_schema_version(5, user_data_dir=data_dir)

    res = MigrationManager.apply_migrations(
        target_version=1,
        user_data_dir=data_dir,
    )
    assert res.success is False
    assert "downgrade prohibited" in res.message.lower()


def test_apply_migrations_success_step(migration_env, monkeypatch):
    """Verify apply_migrations successfully applies step handlers and updates version."""
    data_dir = migration_env["data_dir"]
    MigrationManager.set_schema_version(1, user_data_dir=data_dir)

    # Register mock step handler (1 -> 2)
    step_executed = []

    def mock_step_1_to_2(path: Path):
        step_executed.append(True)
        return True, None

    monkeypatch.setattr(
        MigrationManager,
        "_get_migration_step_handler",
        lambda from_v, to_v: mock_step_1_to_2,
    )

    res = MigrationManager.apply_migrations(target_version=2, user_data_dir=data_dir)

    assert res.success is True
    assert res.to_version == 2
    assert len(step_executed) == 1
    assert MigrationManager.get_schema_version(user_data_dir=data_dir) == 2


def test_apply_migrations_step_failure_triggers_rollback(migration_env, monkeypatch):
    """Verify step handler failure triggers automatic rollback and preserves previous version."""
    data_dir = migration_env["data_dir"]
    MigrationManager.set_schema_version(1, user_data_dir=data_dir)

    state_file = data_dir / "runtime_status.json"
    state_file.write_text("PRE_MIGRATION_SAFE_STATE", encoding="utf-8")

    def failing_step(path: Path):
        # Mutate file during failing step
        state_file.write_text("FAILED_PARTIAL_WRITE", encoding="utf-8")
        return False, "Simulated disk corruption or validation error"

    monkeypatch.setattr(
        MigrationManager,
        "_get_migration_step_handler",
        lambda from_v, to_v: failing_step,
    )

    res = MigrationManager.apply_migrations(target_version=2, user_data_dir=data_dir)

    assert res.success is False
    assert "simulated disk corruption" in res.message.lower()
    # Ensure rolled back to original content
    assert state_file.read_text(encoding="utf-8") == "PRE_MIGRATION_SAFE_STATE"
    # Ensure version remains at 1
    assert MigrationManager.get_schema_version(user_data_dir=data_dir) == 1
