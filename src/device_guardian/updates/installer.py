"""Secure update installation and rollback management for Device Guardian (Phase 7).

Coordinates explicit, transactional updates and rollback operations:
- Pre-install package verification gate.
- Graceful runtime shutdown coordination.
- Verifiable rollback backup creation.
- Atomic/resilient executable replacement.
- Post-install binary hash validation.
- Rollback restoration preserving configuration and secret stores.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Optional

from device_guardian.logger import get_logger
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point, validate_safe_path
from device_guardian.updates.crypto import calculate_sha256, verify_sha256
from device_guardian.updates.manifest import ReleaseManifest
from device_guardian.updates.transaction import TransactionState, UpdateTransaction
from device_guardian.updates.verifier import VerificationStatus, verify_update_package
from device_guardian.version import SemanticVersion, __version__

logger = get_logger("updates.installer")


class _UpdateLockContext:
    """Provides exclusive process-level serialization for update and rollback operations."""

    def __init__(self, lock_file: Path) -> None:
        self.lock_file = lock_file
        self._acquired = False

    def __enter__(self) -> _UpdateLockContext:
        if self.lock_file.is_file():
            # Check if active or stale (> 300s)
            try:
                mtime = self.lock_file.stat().st_mtime
                if (time.time() - mtime) < 300.0:
                    raise RuntimeError("Another update or rollback operation is currently in progress.")
                else:
                    self.lock_file.unlink()
            except OSError:
                pass

        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.lock_file.write_text(str(os.getpid()), encoding="utf-8")
            self._acquired = True
        except OSError as exc:
            raise RuntimeError(f"Could not acquire update lock: {exc}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._acquired and self.lock_file.is_file():
            try:
                self.lock_file.unlink()
            except OSError:
                pass


@dataclass
class InstallationResult:
    """Outcome of an update installation or rollback operation."""

    success: bool
    installed_version: str
    previous_version: str
    message: str
    backup_path: Optional[Path] = None
    transaction_state: TransactionState = TransactionState.IDLE


class UpdateInstaller:
    """Orchestrates secure deployment and rollback of verified releases."""

    @classmethod
    def install_update(
        cls,
        package_path: Path | str,
        allow_downgrade: bool = False,
        public_key: Optional[bytes] = None,
        target_executable_override: Optional[Path | str] = None,
    ) -> InstallationResult:
        """Install a verified update package under explicit user control.

        Args:
            package_path: Path to candidate .zip package or release directory.
            allow_downgrade: Permit installing older versions if True.
            public_key: Optional Ed25519 public key override for verification.
            target_executable_override: Path override for target executable.

        Returns:
            InstallationResult indicating success or failure with diagnostic details.
        """
        lock_file = ApplicationPaths.get_updates_dir() / "update.lock"
        try:
            with _UpdateLockContext(lock_file):
                return cls._execute_install_update(
                    package_path=package_path,
                    allow_downgrade=allow_downgrade,
                    public_key=public_key,
                    target_executable_override=target_executable_override,
                )
        except RuntimeError as lock_err:
            log_security_event(
                SecurityEventType.SECURITY_LOCK_CONFLICT,
                subsystem="updates.installer",
                message=f"Update lock conflict: {lock_err}",
            )
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=str(lock_err),
                transaction_state=TransactionState.IDLE,
            )

    @classmethod
    def _execute_install_update(
        cls,
        package_path: Path | str,
        allow_downgrade: bool = False,
        public_key: Optional[bytes] = None,
        target_executable_override: Optional[Path | str] = None,
    ) -> InstallationResult:
        pkg_path = Path(package_path).resolve()
        logger.info("Initiating explicit update deployment from: %s", pkg_path)

        # 1. Initialize and persist transaction
        txn = UpdateTransaction(
            state=TransactionState.VERIFYING,
            package_path=str(pkg_path),
            previous_version=__version__,
        )
        txn.save()

        # 2. Gate 1: Verification Pipeline
        ver_result = verify_update_package(
            package_path=pkg_path,
            public_key=public_key,
            allow_downgrade=allow_downgrade,
        )

        if not ver_result.is_verified or not ver_result.manifest or not ver_result.artifact_path:
            txn.transition_to(
                TransactionState.VERIFICATION_FAILED,
                error_message=f"Update verification rejected: {ver_result.status.value}",
            )
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=f"Update rejected by verification gate: {ver_result.status.value}\n{ver_result.format_report()}",
                transaction_state=txn.state,
            )

        manifest = ver_result.manifest
        verified_artifact = ver_result.artifact_path
        target_version = manifest.version

        txn.target_version = target_version
        txn.release_id = manifest.release_id
        txn.transition_to(TransactionState.VERIFIED)

        # 3. Gate 2: Stop running background runtime safely
        cls._request_runtime_stop()

        # Determine target binary path
        target_exe = (
            Path(target_executable_override).resolve()
            if target_executable_override
            else ApplicationPaths.get_executable_path()
        )
        txn.target_executable_path = str(target_exe)

        # 4. Gate 3: Create Rollback Backup
        txn.transition_to(TransactionState.BACKING_UP)
        backup_path: Optional[Path] = None
        if target_exe.is_file():
            backup_dir = ApplicationPaths.get_update_backup_dir() / f"v{__version__}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_exe = backup_dir / target_exe.name
            try:
                shutil.copy2(target_exe, backup_exe)
                # Store backup metadata
                meta_file = backup_dir / "backup_metadata.json"
                meta_file.write_text(
                    ReleaseManifest(
                        version=__version__,
                        release_id=f"BACKUP-{__version__}",
                        release_date=datetime.now(timezone.utc).isoformat(),
                        platform=manifest.platform,
                        architecture=manifest.architecture,
                        artifacts=[],
                    ).to_json(),
                    encoding="utf-8",
                )
                backup_path = backup_exe
                txn.backup_path = str(backup_exe)
                logger.info("Rollback backup established at: %s", backup_exe)
            except Exception as exc:
                txn.transition_to(
                    TransactionState.BACKUP_FAILED,
                    error_message=f"Failed to create rollback backup: {exc}",
                )
                return InstallationResult(
                    success=False,
                    installed_version=__version__,
                    previous_version=__version__,
                    message=f"Update aborted: Failed to establish verified rollback backup ({exc})",
                    transaction_state=txn.state,
                )

        # 5. Gate 4: Stage verified artifact
        txn.transition_to(TransactionState.STAGING)
        stage_dir = ApplicationPaths.get_update_verified_dir() / f"v{target_version}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged_exe = stage_dir / verified_artifact.name
        try:
            shutil.copy2(verified_artifact, staged_exe)
            txn.staging_path = str(staged_exe)
        except Exception as exc:
            txn.transition_to(
                TransactionState.STAGING_FAILED,
                error_message=f"Failed to stage verified artifact: {exc}",
            )
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=f"Update aborted: Staging copy failed ({exc})",
                transaction_state=txn.state,
            )

        # 6. Gate 5: Perform executable replacement
        txn.transition_to(TransactionState.INSTALLING)
        try:
            target_exe.parent.mkdir(parents=True, exist_ok=True)
            if is_symlink_or_reparse_point(target_exe):
                log_security_event(
                    SecurityEventType.SECURITY_PATH_REJECTED,
                    subsystem="updates.installer",
                    message="Target executable is an unauthorized symlink/reparse point. Aborting replacement.",
                    details={"target_exe": str(target_exe)},
                )
                raise OSError(f"Target executable is a symlink or reparse point: {target_exe}")

            if target_exe.is_file():
                # On Windows, rename active executable to .old before writing new
                old_exe = target_exe.with_suffix(".exe.old" if sys.platform == "win32" else ".old")
                if is_symlink_or_reparse_point(old_exe):
                    raise OSError(f"Old executable backup path is a symlink or reparse point: {old_exe}")
                if old_exe.exists():
                    try:
                        old_exe.unlink()
                    except OSError:
                        pass
                try:
                    target_exe.rename(old_exe)
                except OSError:
                    # Fallback if rename fails
                    shutil.copy2(staged_exe, target_exe)

            # Copy staged binary into target location
            shutil.copy2(staged_exe, target_exe)
        except Exception as exc:
            txn.transition_to(
                TransactionState.INSTALL_FAILED,
                error_message=f"Executable replacement failed: {exc}",
            )
            # Attempt immediate rollback if backup exists
            if backup_path and backup_path.is_file():
                cls._restore_file(backup_path, target_exe)
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=f"Update failed during file replacement: {exc}",
                transaction_state=txn.state,
            )

        # 7. Gate 6: Post-installation Validation
        txn.transition_to(TransactionState.VALIDATING)
        expected_sha = calculate_sha256(staged_exe)
        if not target_exe.is_file() or not verify_sha256(target_exe, expected_sha):
            txn.transition_to(
                TransactionState.VALIDATION_FAILED,
                error_message="Installed binary hash does not match staged verified artifact.",
            )
            # Automatic rollback
            if backup_path and backup_path.is_file():
                cls._restore_file(backup_path, target_exe)
                txn.transition_to(TransactionState.ROLLED_BACK)
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message="Post-install hash validation failed! Installed binary rolled back.",
                transaction_state=txn.state,
            )

        # 8. Complete Transaction Successfully
        txn.transition_to(TransactionState.COMPLETED)
        logger.info("Successfully updated Device Guardian to version %s", target_version)

        return InstallationResult(
            success=True,
            installed_version=target_version,
            previous_version=__version__,
            message=f"Device Guardian successfully updated to version {target_version}.",
            backup_path=backup_path,
            transaction_state=TransactionState.COMPLETED,
        )

    @classmethod
    def rollback(
        cls,
        target_version: Optional[str] = None,
        target_executable_override: Optional[Path | str] = None,
    ) -> InstallationResult:
        """Perform rollback to a previous verified backup.

        Preserves .env configuration, secret stores, logs, and user preferences.
        """
        lock_file = ApplicationPaths.get_updates_dir() / "update.lock"
        try:
            with _UpdateLockContext(lock_file):
                return cls._execute_rollback(
                    target_version=target_version,
                    target_executable_override=target_executable_override,
                )
        except RuntimeError as lock_err:
            log_security_event(
                SecurityEventType.SECURITY_LOCK_CONFLICT,
                subsystem="updates.installer",
                message=f"Rollback lock conflict: {lock_err}",
            )
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=str(lock_err),
                transaction_state=TransactionState.IDLE,
            )

    @classmethod
    def _execute_rollback(
        cls,
        target_version: Optional[str] = None,
        target_executable_override: Optional[Path | str] = None,
    ) -> InstallationResult:
        logger.info("Initiating explicit rollback request...")
        backup_base = ApplicationPaths.get_update_backup_dir()

        # Find available backups
        backups = [p for p in backup_base.glob("v*") if p.is_dir()]
        if not backups:
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message="Rollback aborted: No previous version backups exist.",
                transaction_state=TransactionState.IDLE,
            )

        if target_version:
            target_dir = backup_base / f"v{target_version.lstrip('v')}"
            if not target_dir.is_dir():
                return InstallationResult(
                    success=False,
                    installed_version=__version__,
                    previous_version=__version__,
                    message=f"Rollback aborted: Backup for version '{target_version}' does not exist.",
                    transaction_state=TransactionState.IDLE,
                )
            latest_backup_dir = target_dir
            backup_version = target_version.lstrip("v")
        else:
            # Sort by modification time, newest first
            backups.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            latest_backup_dir = backups[0]
            backup_version = latest_backup_dir.name.lstrip("v")

        target_exe = (
            Path(target_executable_override).resolve()
            if target_executable_override
            else ApplicationPaths.get_executable_path()
        )

        binary_name = target_exe.name
        backup_exe = latest_backup_dir / binary_name
        if not backup_exe.is_file():
            # Try finding any executable in the backup dir
            exes = [p for p in latest_backup_dir.iterdir() if p.suffix.lower() in {"", ".exe", ".bin"}]
            if exes:
                backup_exe = exes[0]
            else:
                return InstallationResult(
                    success=False,
                    installed_version=__version__,
                    previous_version=__version__,
                    message=f"Rollback aborted: Backup directory '{latest_backup_dir}' contains no binary artifact.",
                    transaction_state=TransactionState.IDLE,
                )

        cls._request_runtime_stop()

        try:
            cls._restore_file(backup_exe, target_exe)
        except Exception as exc:
            return InstallationResult(
                success=False,
                installed_version=__version__,
                previous_version=__version__,
                message=f"Rollback failed during file restoration: {exc}",
                transaction_state=TransactionState.ROLLBACK_REQUIRED,
            )

        txn = UpdateTransaction(
            state=TransactionState.ROLLED_BACK,
            target_version=backup_version,
            previous_version=__version__,
            backup_path=str(backup_exe),
        )
        txn.save()

        logger.info("Rollback completed successfully to version: %s", backup_version)
        return InstallationResult(
            success=True,
            installed_version=backup_version,
            previous_version=__version__,
            message=f"Successfully rolled back Device Guardian to version {backup_version}.",
            backup_path=backup_exe,
            transaction_state=TransactionState.ROLLED_BACK,
        )

    @classmethod
    def get_update_status_summary(cls) -> dict:
        """Obtain safe diagnostic summary of update and rollback status."""
        txn = UpdateTransaction.load()
        backup_base = ApplicationPaths.get_update_backup_dir()
        backup_dirs = [p.name.lstrip("v") for p in backup_base.glob("v*") if p.is_dir()] if backup_base.is_dir() else []
        verified_dir = ApplicationPaths.get_update_verified_dir()
        verified_artifacts = [p.name for p in verified_dir.iterdir() if p.is_file()] if verified_dir.is_dir() else []

        return {
            "installed_version": __version__,
            "last_verified_version": txn.target_version or __version__,
            "transaction_state": txn.state.value,
            "has_rollback_backup": bool(backup_dirs),
            "available_rollbacks": backup_dirs,
            "verified_artifacts": verified_artifacts,
            "backup_path": txn.backup_path,
            "error_message": txn.error_message,
            "last_updated": txn.updated_at,
        }

    @classmethod
    def _request_runtime_stop(cls) -> None:
        """Signal running background instance to stop cleanly before file modifications."""
        try:
            lock = SingleInstanceLock()
            if lock.is_locked():
                lock.signal_stop()
                # Give worker a moment to stop
                time.sleep(0.5)
        except Exception:
            pass

    @classmethod
    def _restore_file(cls, source: Path, destination: Path) -> None:
        """Atomically or safely restore file to destination."""
        if is_symlink_or_reparse_point(destination):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="updates.installer",
                message="Rollback destination is an unauthorized symlink/reparse point. Aborting restore.",
                details={"destination": str(destination)},
            )
            raise OSError(f"Rollback destination is a symlink or reparse point: {destination}")

        if destination.exists():
            old = destination.with_suffix(".bak.old")
            try:
                destination.replace(old)
            except OSError:
                pass
        shutil.copy2(source, destination)
