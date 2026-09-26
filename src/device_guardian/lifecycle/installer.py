"""Lifecycle installer, upgrader, repair, and uninstaller for Device Guardian (Phase 12).

Orchestrates deterministic application lifecycle workflows:
- Fresh installation with clean separation of INSTALL_ROOT and USER_DATA.
- Safe transactional upgrades with pre-upgrade verification and backup.
- Non-destructive repair workflows preserving user configurations and secrets.
- Transparent uninstallation distinguishing application binaries from user data.
- Bounded rollback on failure and interruption recovery.
- Strict audit logging across all lifecycle operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.recovery.persistence import AtomicPersistence
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point, validate_safe_path
from device_guardian.startup import create_startup_manager
from device_guardian.updates.crypto import calculate_sha256
from device_guardian.updates.installer import _UpdateLockContext
from device_guardian.version import SemanticVersion, __version__, compare_versions
from device_guardian.lifecycle.migration import CURRENT_STATE_SCHEMA_VERSION, MigrationManager
from device_guardian.lifecycle.models import (
    InstallationHealth,
    InstallationMetadata,
    LifecycleOperationType,
    LifecycleRecord,
    LifecycleState,
)

logger = get_logger("lifecycle.installer")


@dataclass
class LifecycleResult:
    """Outcome of an installation, upgrade, repair, or uninstall operation."""

    success: bool
    operation: LifecycleOperationType
    version: str
    message: str
    target_path: Optional[Path] = None
    backup_path: Optional[Path] = None
    details: dict[str, Any] = None


class LifecycleInstaller:
    """Production application lifecycle manager for Device Guardian."""

    @classmethod
    def get_installation_info(cls, user_data_dir: Optional[Path] = None) -> Optional[InstallationMetadata]:
        """Retrieve persistent installation metadata."""
        target_file = (Path(user_data_dir) / "install_metadata.json") if user_data_dir else ApplicationPaths.get_install_metadata_file_path()
        return InstallationMetadata.load(target_file)

    @classmethod
    def verify_installation(
        cls,
        install_root: Optional[Path] = None,
        user_data_dir: Optional[Path] = None,
    ) -> InstallationHealth:
        """Inspect and verify installation integrity, directories, and configuration."""
        i_root = install_root or ApplicationPaths.get_install_root()
        u_data = user_data_dir or ApplicationPaths.get_user_data_dir()

        from device_guardian.platform_compat import get_executable_name
        binary_name = get_executable_name()
        binary_path = i_root / binary_name
        binary_exists = binary_path.is_file()

        metadata_file = u_data / "install_metadata.json"
        metadata_exists = metadata_file.is_file()
        metadata = InstallationMetadata.load(metadata_file)
        metadata_valid = metadata is not None

        data_dir_valid = u_data.is_dir()
        config_file = u_data / ".env"
        config_present = config_file.is_file()

        # Check for DPAPI secrets.dat or FileSecretStore secrets.json
        secrets_file = u_data / "secrets.dat"
        secrets_json = u_data / "secrets.json"
        secrets_present = secrets_file.is_file() or secrets_json.is_file()

        issues = []
        if not binary_exists:
            issues.append(f"Binary not found at expected path: {binary_path}")
        if not metadata_exists:
            issues.append("Installation metadata missing.")
        elif not metadata_valid:
            issues.append("Installation metadata corrupted.")
        if not data_dir_valid:
            issues.append(f"User data directory missing: {u_data}")

        # Determine overall installation status
        if binary_exists and metadata_valid and data_dir_valid:
            status = "HEALTHY"
            message = "Installation is valid and healthy."
        elif binary_exists and data_dir_valid:
            status = "DEGRADED"
            message = "Application binary exists but metadata is incomplete."
        elif not binary_exists and not metadata_exists:
            status = "NOT_CONFIGURED"
            message = "Device Guardian is not installed."
        else:
            status = "FAILED"
            message = f"Installation verification failed: {'; '.join(issues)}"

        installed_ver = metadata.version if metadata else __version__

        return InstallationHealth(
            is_installed=binary_exists or metadata_exists,
            version=installed_ver,
            binary_path=str(binary_path),
            binary_exists=binary_exists,
            binary_valid=binary_exists and not is_symlink_or_reparse_point(binary_path),
            metadata_exists=metadata_exists,
            metadata_valid=metadata_valid,
            data_dir_valid=data_dir_valid,
            config_present=config_present,
            secrets_present=secrets_present,
            status=status,
            message=message,
            issues=issues,
        )

    @classmethod
    def fresh_install(
        cls,
        source_binary: Path | str,
        target_install_dir: Optional[Path | str] = None,
        target_user_data_dir: Optional[Path | str] = None,
        version: str = __version__,
        enable_startup: bool = False,
    ) -> LifecycleResult:
        # 1. Path Safety & Reparse Point Checks
        try:
            src_path = validate_safe_path(source_binary)
            dst_install = validate_safe_path(target_install_dir or ApplicationPaths.get_install_root())
            dst_data = validate_safe_path(target_user_data_dir or ApplicationPaths.get_user_data_dir())
        except Exception as err:
            log_security_event(
                event_type=SecurityEventType.INSTALL_FAILED,
                subsystem="lifecycle.installer",
                message=f"Installation rejected due to unsafe path: {err}",
                details={"error": str(err)},
                severity="ERROR",
            )
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.INSTALL,
                version=version,
                message=f"Installation path rejected: {err}",
            )

        record = LifecycleRecord(
            operation_type=LifecycleOperationType.INSTALL,
            version=version,
            install_path=str(dst_install),
        )
        record.transition_to(LifecycleState.VERIFYING)

        log_security_event(
            event_type=SecurityEventType.INSTALL_STARTED,
            subsystem="lifecycle.installer",
            message=f"Starting fresh installation of Device Guardian v{version}.",
            details={"source": str(src_path), "target": str(dst_install)},
            severity="INFO",
        )

        if not src_path.is_file():
            record.transition_to(LifecycleState.FAILED, error_message="Source binary does not exist.")
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.INSTALL,
                version=version,
                message=f"Source binary not found at: {src_path}",
            )

        from device_guardian.platform_compat import get_executable_name, is_windows, set_posix_permissions
        binary_name = get_executable_name()
        target_binary = dst_install / binary_name

        # Check if already installed
        if target_binary.is_file():
            logger.info("Target binary already exists at: %s", target_binary)

        # 2. Staging & Directory Creation
        record.transition_to(LifecycleState.STAGING)
        try:
            dst_install.mkdir(parents=True, exist_ok=True)
            dst_data.mkdir(parents=True, exist_ok=True)
            (dst_data / "logs").mkdir(parents=True, exist_ok=True)
            (dst_data / "updates").mkdir(parents=True, exist_ok=True)
            (dst_data / "updates" / "backup").mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            record.transition_to(LifecycleState.FAILED, error_message=f"Directory creation failed: {exc}")
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.INSTALL,
                version=version,
                message=f"Failed to create target directories: {exc}",
            )

        # 3. Installing Executable
        record.transition_to(LifecycleState.INSTALLING)
        try:
            temp_target = dst_install / f"{binary_name}.tmp.{os.getpid()}"
            shutil.copy2(src_path, temp_target)
            # Physical fsync
            with open(temp_target, "ab") as f:
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace into final position
            if target_binary.is_file():
                backup_old = dst_install / f"{binary_name}.old.{os.getpid()}"
                try:
                    os.replace(target_binary, backup_old)
                except OSError:
                    pass

            os.replace(temp_target, target_binary)
            if not is_windows():
                set_posix_permissions(target_binary, 0o755)
        except Exception as exc:
            record.transition_to(LifecycleState.FAILED, error_message=f"Binary installation failed: {exc}")
            log_security_event(
                event_type=SecurityEventType.INSTALL_FAILED,
                subsystem="lifecycle.installer",
                message=f"Failed to install binary: {exc}",
                details={"error": str(exc)},
                severity="ERROR",
            )
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.INSTALL,
                version=version,
                message=f"Failed to install application binary: {exc}",
            )

        # 4. Validating
        record.transition_to(LifecycleState.VALIDATING)
        sha256_hash = calculate_sha256(target_binary)
        if not target_binary.is_file() or target_binary.stat().st_size == 0:
            record.transition_to(LifecycleState.FAILED, error_message="Installed binary is missing or empty.")
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.INSTALL,
                version=version,
                message="Installed binary validation failed (missing or empty).",
            )

        # 5. Metadata & Default Configuration
        from device_guardian.platform_compat import get_platform_info
        info = get_platform_info()
        sys_name = info.os.value.lower()
        arch = info.arch.value

        metadata = InstallationMetadata(
            version=version,
            install_path=str(dst_install),
            user_data_path=str(dst_data),
            installed_at=datetime.now(timezone.utc).isoformat(),
            schema_version=CURRENT_STATE_SCHEMA_VERSION,
            platform=sys_name,
            architecture=arch,
            is_frozen=True,
            executable_hash=sha256_hash,
        )
        metadata.save(dst_data / "install_metadata.json")

        # Initialize default .env if not present
        env_file = dst_data / ".env"
        if not env_file.is_file():
            default_env = (
                "# Device Guardian Configuration\n"
                "LOG_LEVEL=INFO\n"
                "AUTH_FAILURE_THRESHOLD=3\n"
                "AUTH_FAILURE_WINDOW_SECONDS=60\n"
                "AUTH_ALERT_COOLDOWN_SECONDS=300\n"
                "VOICE_WARNING_ENABLED=true\n"
                "SMART_FILTERING_ENABLED=true\n"
                "ENVIRONMENTAL_TRIGGERS_ENABLED=true\n"
                "CAMERA_ALERT_ENABLED=true\n"
                "LOCATION_ALERT_ENABLED=true\n"
                "TELEGRAM_ALERT_ENABLED=true\n"
            )
            AtomicPersistence.atomic_write(env_file, default_env, backup=False, encoding="utf-8")

        # 6. Optional Startup Integration
        if enable_startup:
            try:
                startup_mgr = create_startup_manager()
                startup_mgr.enable(custom_command=f'"{target_binary}"')
                logger.info("Startup integration configured for: %s", target_binary)
            except Exception as exc:
                logger.warning("Startup integration registration non-critical failure: %s", exc)

        record.transition_to(LifecycleState.COMPLETED)
        log_security_event(
            event_type=SecurityEventType.INSTALL_COMPLETED,
            subsystem="lifecycle.installer",
            message=f"Device Guardian v{version} installed successfully at {target_binary}.",
            details={"install_path": str(dst_install), "sha256": sha256_hash},
            severity="INFO",
        )

        return LifecycleResult(
            success=True,
            operation=LifecycleOperationType.INSTALL,
            version=version,
            message=f"Device Guardian v{version} installed successfully.",
            target_path=target_binary,
            details={"sha256": sha256_hash, "user_data_dir": str(dst_data)},
        )

    @classmethod
    def upgrade(
        cls,
        new_binary_or_package: Path | str,
        target_install_dir: Optional[Path | str] = None,
        target_user_data_dir: Optional[Path | str] = None,
        target_version: Optional[str] = None,
        allow_downgrade: bool = False,
    ) -> LifecycleResult:
        """Upgrade installed Device Guardian binary with data preservation and rollback."""
        src_path = Path(new_binary_or_package).resolve()
        dst_install = Path(target_install_dir or ApplicationPaths.get_install_root()).resolve()
        # 0. Path Safety Check
        try:
            src_path = validate_safe_path(new_binary_or_package)
            dst_install = validate_safe_path(target_install_dir or ApplicationPaths.get_install_root())
            dst_data = validate_safe_path(target_user_data_dir or ApplicationPaths.get_user_data_dir())
        except Exception as err:
            log_security_event(
                event_type=SecurityEventType.UPGRADE_FAILED,
                subsystem="lifecycle.installer",
                message=f"Upgrade rejected due to unsafe path: {err}",
                details={"error": str(err)},
                severity="ERROR",
            )
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.UPGRADE,
                version="unknown",
                message=f"Upgrade path rejected: {err}",
            )

        metadata_file = dst_data / "install_metadata.json"
        metadata = InstallationMetadata.load(metadata_file)
        current_ver = metadata.version if metadata else __version__

        record = LifecycleRecord(
            operation_type=LifecycleOperationType.UPGRADE,
            version=current_ver,
            target_version=target_version or "new",
            install_path=str(dst_install),
        )
        record.transition_to(LifecycleState.VERIFYING)

        log_security_event(
            event_type=SecurityEventType.UPGRADE_STARTED,
            subsystem="lifecycle.installer",
            message=f"Starting upgrade of Device Guardian from v{current_ver}.",
            details={"current_version": current_ver, "target_version": target_version},
            severity="INFO",
        )

        # 1. Downgrade Defense
        if target_version:
            cmp_result = compare_versions(target_version, current_ver)
            if cmp_result < 0 and not allow_downgrade:
                record.transition_to(LifecycleState.FAILED, error_message="Downgrade prohibited.")
                log_security_event(
                    event_type=SecurityEventType.UPGRADE_FAILED,
                    subsystem="lifecycle.installer",
                    message=f"Upgrade rejected: Downgrade from {current_ver} to {target_version} prohibited without --allow-downgrade.",
                    details={"current": current_ver, "target": target_version},
                    severity="WARN",
                )
                return LifecycleResult(
                    success=False,
                    operation=LifecycleOperationType.UPGRADE,
                    version=current_ver,
                    message=f"Downgrade from v{current_ver} to v{target_version} is blocked. Use --allow-downgrade to override.",
                )

        # 2. Acquire Update Lock
        lock_file = dst_data / "updates" / "update.lock"
        try:
            update_lock = _UpdateLockContext(lock_file)
            update_lock.__enter__()
        except Exception as exc:
            record.transition_to(LifecycleState.FAILED, error_message=f"Lock conflict: {exc}")
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.UPGRADE,
                version=current_ver,
                message=f"Could not acquire update lock: {exc}",
            )

        try:
            # 3. Graceful Runtime Stop Coordination (no force kill)
            runtime_lock_file = dst_data / "guardian.lock"
            if runtime_lock_file.is_file():
                logger.info("Running instance detected. Requesting graceful shutdown before upgrade...")
                # Write IPC stop command
                control_file = dst_data / "guardian.control"
                try:
                    control_file.write_text("STOP", encoding="utf-8")
                except OSError:
                    pass

                # Wait bounded time for clean stop
                stopped = False
                for _ in range(20):
                    time.sleep(0.25)
                    if not runtime_lock_file.is_file():
                        stopped = True
                        break
                if not stopped:
                    logger.warning("Running instance did not stop within timeout. Aborting upgrade safely.")
                    record.transition_to(LifecycleState.FAILED, error_message="Runtime did not stop cleanly.")
                    return LifecycleResult(
                        success=False,
                        operation=LifecycleOperationType.UPGRADE,
                        version=current_ver,
                        message="Cannot upgrade while Device Guardian is running and refusing to stop.",
                    )

            # 4. Backup Existing Binary
            record.transition_to(LifecycleState.BACKING_UP)
            from device_guardian.platform_compat import get_executable_name, is_windows, set_posix_permissions
            binary_name = get_executable_name()
            target_binary = dst_install / binary_name
            backup_dir = dst_data / "updates" / "backup" / f"v_{current_ver}_{int(time.time())}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_binary = backup_dir / binary_name

            if target_binary.is_file():
                shutil.copy2(target_binary, backup_binary)
                record.backup_path = str(backup_binary)

            # 5. Staging & Binary Swap
            record.transition_to(LifecycleState.STAGING)
            temp_swap = dst_install / f"{binary_name}.swap.{os.getpid()}"
            shutil.copy2(src_path, temp_swap)

            record.transition_to(LifecycleState.INSTALLING)
            os.replace(temp_swap, target_binary)
            if not is_windows():
                set_posix_permissions(target_binary, 0o755)

            # 6. Validating Installation
            record.transition_to(LifecycleState.VALIDATING)
            if not target_binary.is_file() or target_binary.stat().st_size == 0:
                # Rollback!
                logger.error("Upgraded binary missing or invalid. Rolling back to backup...")
                record.transition_to(LifecycleState.ROLLING_BACK)
                if backup_binary.is_file():
                    os.replace(backup_binary, target_binary)
                record.transition_to(LifecycleState.ROLLED_BACK)
                return LifecycleResult(
                    success=False,
                    operation=LifecycleOperationType.UPGRADE,
                    version=current_ver,
                    message="Upgraded binary validation failed. Restored previous version from backup.",
                    backup_path=backup_binary,
                )

            # 7. Schema Migration Check
            new_ver_str = target_version or current_ver
            record.transition_to(LifecycleState.MIGRATING)
            migration_res = MigrationManager.apply_migrations(
                target_version=CURRENT_STATE_SCHEMA_VERSION,
                user_data_dir=dst_data,
            )
            if not migration_res.success:
                logger.warning("Schema migration warning: %s", migration_res.message)

            # Update Metadata
            sha256_hash = calculate_sha256(target_binary)
            upd_metadata = InstallationMetadata(
                version=new_ver_str,
                install_path=str(dst_install),
                user_data_path=str(dst_data),
                installed_at=metadata.installed_at if metadata else datetime.now(timezone.utc).isoformat(),
                last_upgraded_at=datetime.now(timezone.utc).isoformat(),
                schema_version=CURRENT_STATE_SCHEMA_VERSION,
                platform=platform.system().lower(),
                architecture="x64",
                is_frozen=True,
                executable_hash=sha256_hash,
            )
            upd_metadata.save(metadata_file)

            record.transition_to(LifecycleState.COMPLETED)
            log_security_event(
                event_type=SecurityEventType.UPGRADE_COMPLETED,
                subsystem="lifecycle.installer",
                message=f"Device Guardian upgraded successfully to v{new_ver_str}.",
                details={"from_version": current_ver, "to_version": new_ver_str, "sha256": sha256_hash},
                severity="INFO",
            )

            return LifecycleResult(
                success=True,
                operation=LifecycleOperationType.UPGRADE,
                version=new_ver_str,
                message=f"Device Guardian upgraded successfully from v{current_ver} to v{new_ver_str}.",
                target_path=target_binary,
                backup_path=backup_binary,
                details={"previous_version": current_ver, "sha256": sha256_hash},
            )

        finally:
            try:
                update_lock.__exit__(None, None, None)
            except Exception:
                pass

    @classmethod
    def repair(
        cls,
        install_root: Optional[Path | str] = None,
        user_data_dir: Optional[Path | str] = None,
    ) -> LifecycleResult:
        try:
            i_root = validate_safe_path(install_root or ApplicationPaths.get_install_root())
            u_data = validate_safe_path(user_data_dir or ApplicationPaths.get_user_data_dir())
        except Exception as err:
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.REPAIR,
                version=__version__,
                message=f"Repair path rejected: {err}",
            )

        log_security_event(
            event_type=SecurityEventType.REPAIR_STARTED,
            subsystem="lifecycle.installer",
            message="Starting application lifecycle repair operation.",
            details={"install_root": str(i_root), "user_data_dir": str(u_data)},
            severity="INFO",
        )

        repaired_items = []

        # 1. Recreate essential directories
        for d in [
            i_root,
            u_data,
            u_data / "logs",
            u_data / "updates",
            u_data / "updates" / "staging",
            u_data / "updates" / "verified",
            u_data / "updates" / "backup",
        ]:
            if not d.is_dir():
                d.mkdir(parents=True, exist_ok=True)
                repaired_items.append(f"Created missing directory: {d.name}")

        # 2. Check and repair install metadata
        meta_file = u_data / "install_metadata.json"
        meta = InstallationMetadata.load(meta_file)
        if meta is None:
            from device_guardian.platform_compat import get_executable_name, get_platform_info
            binary_name = get_executable_name()
            target_binary = i_root / binary_name
            sha = calculate_sha256(target_binary) if target_binary.is_file() else None
            p_info = get_platform_info()
            meta = InstallationMetadata(
                version=__version__,
                install_path=str(i_root),
                user_data_path=str(u_data),
                schema_version=CURRENT_STATE_SCHEMA_VERSION,
                platform=p_info.os.value.lower(),
                architecture=p_info.arch.value,
                executable_hash=sha,
            )
            meta.save(meta_file)
            repaired_items.append("Regenerated install_metadata.json")

        # 3. Clean stale locks
        lock_file = u_data / "guardian.lock"
        if lock_file.is_file():
            # If no active process, prune
            try:
                content = lock_file.read_text(encoding="utf-8").strip()
                if not content.isdigit() or int(content) <= 0:
                    lock_file.unlink()
                    repaired_items.append("Pruned malformed guardian.lock")
            except OSError:
                pass

        # GUARANTEE: Never touch .env, secrets.dat, secrets.json, or audit logs
        log_security_event(
            event_type=SecurityEventType.REPAIR_COMPLETED,
            subsystem="lifecycle.installer",
            message=f"Lifecycle repair completed. Repaired items: {len(repaired_items)}.",
            details={"repaired_items": repaired_items},
            severity="INFO",
        )

        return LifecycleResult(
            success=True,
            operation=LifecycleOperationType.REPAIR,
            version=meta.version if meta else __version__,
            message=f"Repair completed successfully. {len(repaired_items)} item(s) restored.",
            details={"repaired_items": repaired_items},
        )

    @classmethod
    def uninstall(
        cls,
        install_root: Optional[Path | str] = None,
        user_data_dir: Optional[Path | str] = None,
        remove_user_data: bool = False,
    ) -> LifecycleResult:
        try:
            i_root = validate_safe_path(install_root or ApplicationPaths.get_install_root())
            u_data = validate_safe_path(user_data_dir or ApplicationPaths.get_user_data_dir())
        except Exception as err:
            return LifecycleResult(
                success=False,
                operation=LifecycleOperationType.UNINSTALL,
                version=__version__,
                message=f"Uninstall path rejected: {err}",
            )

        log_security_event(
            event_type=SecurityEventType.UNINSTALL_STARTED,
            subsystem="lifecycle.installer",
            message="Starting application uninstallation.",
            details={"install_root": str(i_root), "remove_user_data": remove_user_data},
            severity="WARN",
        )

        # 1. Stop background service if running
        lock_file = u_data / "guardian.lock"
        if lock_file.is_file():
            logger.info("Requesting background service shutdown prior to uninstall...")
            control_file = u_data / "guardian.control"
            try:
                control_file.write_text("STOP", encoding="utf-8")
            except OSError:
                pass
            time.sleep(0.5)

        # 2. Remove Startup Entry
        try:
            startup_mgr = create_startup_manager()
            if startup_mgr.is_enabled():
                startup_mgr.disable()
                logger.info("Removed OS autostart registration during uninstall.")
        except Exception as exc:
            logger.warning("Startup removal error (non-critical): %s", exc)

        # 3. Remove application binaries
        from device_guardian.platform_compat import get_executable_name
        binary_name = get_executable_name()
        target_binary = i_root / binary_name
        if target_binary.is_file():
            try:
                target_binary.unlink()
            except OSError as exc:
                logger.warning("Could not unlink binary immediately (may be locked): %s", exc)

        # 4. Remove installation root directory if empty or application-owned
        if i_root.is_dir():
            try:
                # Remove known application files
                for f in i_root.glob("*.old*"):
                    try:
                        f.unlink()
                    except OSError:
                        pass
                if not any(i_root.iterdir()):
                    i_root.rmdir()
            except OSError:
                pass

        # 5. User Data Decision
        if remove_user_data:
            log_security_event(
                event_type=SecurityEventType.USER_DATA_DELETION_CONFIRMED,
                subsystem="lifecycle.installer",
                message="User explicitly authorized deletion of user data and configuration during uninstallation.",
                severity="WARN",
            )
            try:
                if u_data.is_dir():
                    shutil.rmtree(u_data, ignore_errors=True)
            except OSError as exc:
                logger.error("Failed to delete user data directory: %s", exc)
        else:
            logger.info("Preserving user data directory as requested: %s", u_data)

        log_security_event(
            event_type=SecurityEventType.UNINSTALL_COMPLETED,
            subsystem="lifecycle.installer",
            message="Application uninstallation completed.",
            details={"remove_user_data": remove_user_data},
            severity="INFO",
        )

        return LifecycleResult(
            success=True,
            operation=LifecycleOperationType.UNINSTALL,
            version=__version__,
            message=(
                "Device Guardian uninstalled successfully. User data was wiped."
                if remove_user_data
                else f"Device Guardian application uninstalled. User data preserved at: {u_data}"
            ),
            details={"user_data_preserved": not remove_user_data},
        )
