"""Tests for Phase 7 update transaction lifecycle and crash recovery."""

from pathlib import Path
import pytest

from device_guardian.updates.transaction import (
    TransactionState,
    UpdateTransaction,
    check_and_recover_interrupted_transaction,
)


def test_transaction_lifecycle_persistence(tmp_path: Path):
    """Verify transaction status persists to disk and reloads cleanly."""
    txn = UpdateTransaction(
        state=TransactionState.VERIFYING,
        target_version="0.2.0",
        previous_version="0.1.0",
    )
    txn.save()

    loaded = UpdateTransaction.load()
    assert loaded.state == TransactionState.VERIFYING
    assert loaded.target_version == "0.2.0"
    assert loaded.previous_version == "0.1.0"

    # Transition to completed
    loaded.transition_to(TransactionState.COMPLETED)
    reloaded = UpdateTransaction.load()
    assert reloaded.state == TransactionState.COMPLETED


def test_startup_recovery_interrupted_install():
    """Verify crash during installation triggers ROLLBACK_REQUIRED state."""
    # Simulate a crash during INSTALLING
    txn = UpdateTransaction(
        state=TransactionState.INSTALLING,
        target_version="0.2.0",
        previous_version="0.1.0",
    )
    txn.save()

    recovery = check_and_recover_interrupted_transaction()
    assert recovery["status"] == "interrupted"
    assert recovery["action"] == "rollback_required"

    current = UpdateTransaction.load()
    assert current.state == TransactionState.ROLLBACK_REQUIRED


def test_startup_recovery_clean_state():
    """Verify completed or idle transactions pass startup check with no action needed."""
    txn = UpdateTransaction(state=TransactionState.IDLE)
    txn.save()

    recovery = check_and_recover_interrupted_transaction()
    assert recovery["status"] == "clean"
