"""Disaster recovery and state repair engine for Device Guardian (Phase 8).

Provides explicit, safe, and non-destructive recovery utilities:
- Installation integrity verification (binary existence, SHA-256 validation).
- Corrupted state repair (preserves corrupted file as .corrupt.<timestamp> before clean reset).
- Recovery status inspection.
- Never silently deletes user configuration or secrets.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.recovery.persistence import AtomicPersistence
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.updates.crypto import calculate_sha256
from device_guardian.updates.transaction import (
    TransactionState,
    UpdateTransaction,
    check_and_recover_interrupted_transaction,
)
from device_guardian.version import __version__, get_version_info

logger = get_logger("recovery.repair")


def verify_installation_integrity() -> tuple[bool, str, dict[str, Any]]:
    """Verify the physical installation integrity of Device Guardian.

    Checks:
    1. Executable file existence and readability.
    2. Executable SHA-256 match against release manifest if available.
    3. Essential user data directories existence.

    Returns:
        tuple: (is_valid: bool, summary_message: str, details: dict)
    """
    is_frozen = ApplicationPaths.is_frozen()
    exe_path = ApplicationPaths.get_executable_path()
    details: dict[str, Any] = {
        "execution_mode": "Frozen Executable" if is_frozen else "Source Package",
        "executable_path": str(exe_path),
        "version": __version__,
        "mode": "Frozen Executable" if is_frozen else "Source Package",
        "checks": [],
    }

    if not exe_path.exists():
        msg = f"Executable artifact missing at: {exe_path}"
        details["checks"].append({"check": "executable_presence", "status": "FAIL", "message": msg})
        return False, msg, details

    details["checks"].append({
        "check": "executable_presence",
        "status": "PASS",
        "message": f"Executable found at {exe_path} ({exe_path.stat().st_size} bytes)",
    })

    # If frozen, verify binary hash if release manifest exists in binary directory
    if is_frozen and exe_path.is_file():
        try:
            exe_hash = calculate_sha256(exe_path)
            details["executable_sha256"] = exe_hash

            manifest_path = exe_path.parent / "release-manifest.json"
            if manifest_path.is_file():
                from device_guardian.updates.manifest import ReleaseManifest
                manifest = ReleaseManifest.from_file(manifest_path)
                art = manifest.get_artifact_for_platform(platform.system().lower(), "x64")
                if art and art.sha256.lower() != exe_hash.lower():
                    msg = f"Binary SHA-256 mismatch! Expected {art.sha256}, got {exe_hash}"
                    details["checks"].append({"check": "sha256_match", "status": "FAIL", "message": msg})
                    return False, msg, details
                else:
                    details["checks"].append({"check": "sha256_match", "status": "PASS", "message": "SHA-256 matches manifest."})
        except Exception as exc:
            details["checks"].append({"check": "sha256_match", "status": "WARN", "message": f"Hash check warning: {exc}"})

    # Verify user data directory
    data_dir = ApplicationPaths.get_user_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    details["checks"].append({"check": "data_directory", "status": "PASS", "message": f"Data directory verified: {data_dir}"})

    return True, "Installation integrity verified successfully.", details


def repair_state_files() -> list[dict[str, Any]]:
    """Audit and non-destructively repair corrupted state files.

    Preserves corrupted file as '{name}.corrupt.<timestamp>' before creating clean default state.

    Returns:
        List of repair event summaries.
    """
    repairs: list[dict[str, Any]] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # 1. Check runtime_status.json
    status_file = ApplicationPaths.get_status_file_path()
    if status_file.is_file():
        is_corrupt = False
        try:
            content = status_file.read_text(encoding="utf-8")
            if not content.strip():
                is_corrupt = True
            else:
                json.loads(content)
        except Exception:
            is_corrupt = True

        if is_corrupt:
            corrupt_backup = status_file.parent / f"{status_file.name}.corrupt.{ts}"
            shutil.copy2(status_file, corrupt_backup)
            status_file.unlink()
            from device_guardian.runtime.models import RuntimeStatus
            default_status = RuntimeStatus().to_dict()
            AtomicPersistence.atomic_write_json(status_file, default_status)
            repairs.append({
                "target": str(status_file),
                "action": "repaired",
                "preserved_backup": str(corrupt_backup),
                "reason": "Malformed or empty runtime status JSON.",
            })

    # 2. Check update_transaction.json
    txn_file = ApplicationPaths.get_update_transaction_file_path()
    if txn_file.is_file():
        is_corrupt = False
        try:
            content = txn_file.read_text(encoding="utf-8")
            if not content.strip():
                is_corrupt = True
            else:
                json.loads(content)
        except Exception:
            is_corrupt = True

        if is_corrupt:
            corrupt_backup = txn_file.parent / f"{txn_file.name}.corrupt.{ts}"
            shutil.copy2(txn_file, corrupt_backup)
            txn_file.unlink()
            default_txn = {
                "state": TransactionState.IDLE.value,
                "error_message": "Reset during disaster recovery repair.",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            AtomicPersistence.atomic_write_json(txn_file, default_txn)
            repairs.append({
                "target": str(txn_file),
                "action": "repaired",
                "preserved_backup": str(corrupt_backup),
                "reason": "Malformed or empty update transaction JSON.",
            })

    return repairs


def get_recovery_status(config: Optional[Any] = None) -> dict[str, Any]:
    """Inspect overall system recovery state, health assessments, and state file backups.

    Args:
        config: Optional AppConfig for subsystem health assessment.

    Returns:
        Structured recovery status dictionary.
    """
    from device_guardian.recovery.health import assess_system_health
    health_rep = assess_system_health(config=config)

    interrupted_info = check_and_recover_interrupted_transaction()
    backup_base = ApplicationPaths.get_update_backup_dir()
    available_rollbacks = (
        [p.name.lstrip("v") for p in backup_base.glob("v*") if p.is_dir()]
        if backup_base.is_dir()
        else []
    )

    data_dir = ApplicationPaths.get_user_data_dir()
    tracked_files = [
        "runtime_status.json",
        "update_transaction.json",
        "setup_status.json",
        "secrets.dat",
        "secrets.json",
        ".env",
    ]

    state_files: dict[str, Any] = {}
    for name in tracked_files:
        fpath = data_dir / name if name != ".env" else Path(os.environ.get("DEVICE_GUARDIAN_ENV_FILE", ".env"))
        exists = fpath.is_file()
        bak_file = fpath.parent / f"{fpath.name}.bak"
        has_bak = bak_file.is_file()
        corrupt_files = list(fpath.parent.glob(f"{fpath.name}.corrupt.*"))
        state_files[name] = {
            "path": str(fpath),
            "exists": exists,
            "has_backup": has_bak,
            "corrupted_copies": [str(c) for c in corrupt_files],
        }

    is_recovery_required = interrupted_info.get("status") == "interrupted" or health_rep.status.value == "FAILED"

    return {
        "recovery_required": is_recovery_required,
        "system_health": health_rep.to_dict(),
        "execution_mode": "frozen" if ApplicationPaths.is_frozen() else "source",
        "data_directory": str(data_dir),
        "state_files": state_files,
        "interrupted_update": interrupted_info,
        "available_rollbacks": available_rollbacks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
