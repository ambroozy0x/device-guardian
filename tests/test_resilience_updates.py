"""Resilience and interruption recovery tests for the update subsystem (Phase 8)."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.updates.installer import UpdateInstaller
from device_guardian.updates.transaction import (
    TransactionState,
    UpdateTransaction,
    check_and_recover_interrupted_transaction,
)


def test_interrupted_transaction_in_installing_state(tmp_path: Path):
    """Verify transaction interrupted in INSTALLING transitions to ROLLBACK_REQUIRED on recovery check."""
    txn_file = tmp_path / "update_transaction.json"

    with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=txn_file):
        txn = UpdateTransaction(
            state=TransactionState.INSTALLING,
            target_version="0.3.0",
            previous_version="0.2.0",
        )
        txn.save()

        recovery_info = check_and_recover_interrupted_transaction()
        assert recovery_info["status"] == "interrupted"
        assert "interrupted update transaction" in recovery_info["message"].lower()

        reloaded = UpdateTransaction.load()
        assert reloaded.state == TransactionState.ROLLBACK_REQUIRED


def test_interrupted_transaction_in_idle_or_completed_state(tmp_path: Path):
    """Verify clean transaction state requires no recovery action."""
    txn_file = tmp_path / "update_transaction.json"

    with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=txn_file):
        txn = UpdateTransaction(state=TransactionState.COMPLETED)
        txn.save()

        recovery_info = check_and_recover_interrupted_transaction()
        assert recovery_info["status"] == "clean"
        assert "no active or interrupted transactions" in recovery_info["message"].lower()


def test_corrupted_transaction_state_recovers_cleanly(tmp_path: Path):
    """Verify corrupted update transaction file falls back safely to default IDLE state."""
    txn_file = tmp_path / "update_transaction.json"
    txn_file.write_text("{corrupt json bytes", encoding="utf-8")

    with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=txn_file):
        txn = UpdateTransaction.load()
        assert txn.state == TransactionState.IDLE


def test_interrupted_transaction_in_verifying_state(tmp_path: Path):
    """Verify crash during package verification cleanly resets to INSTALL_FAILED."""
    txn_file = tmp_path / "update_transaction.json"

    with patch.object(ApplicationPaths, "get_update_transaction_file_path", return_value=txn_file):
        txn = UpdateTransaction(
            state=TransactionState.VERIFYING,
            target_version="0.3.0",
            previous_version="0.2.0",
        )
        txn.save()

        recovery_info = check_and_recover_interrupted_transaction()
        assert recovery_info["status"] == "interrupted"
        assert recovery_info["action"] == "staging_aborted"

        reloaded = UpdateTransaction.load()
        assert reloaded.state == TransactionState.INSTALL_FAILED
