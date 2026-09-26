"""Atomic persistence and corruption recovery engine for Device Guardian (Phase 8).

Provides crash-resilient file persistence:
- Write to temporary file on same filesystem.
- Flush and fsync to guarantee physical media synchronization.
- Backup-on-write (.bak) for critical state.
- Atomic file replacement via os.replace.
- Safe JSON deserialization with schema validation and automatic fallback to backup.
- Never silently treats corrupted state as valid.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import threading
import time
from typing import Any, Callable, Optional, Union

from device_guardian.logger import get_logger
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point

logger = get_logger("recovery.persistence")


class PersistenceError(Exception):
    """Raised when an atomic write or state replacement fails."""
    pass


class CorruptedStateError(Exception):
    """Raised when a state file is missing, empty, or contains malformed data."""
    pass


class AtomicPersistence:
    """Provides crash-resilient, atomic file writing and corruption recovery."""

    @staticmethod
    def atomic_write(
        file_path: Union[Path, str],
        content: Union[str, bytes],
        backup: bool = True,
        encoding: str = "utf-8",
    ) -> Path:
        """Write content atomically using a temporary file and atomic replacement.

        Workflow:
            1. Ensure parent directory exists.
            2. Verify target is not an unauthorized symlink/reparse point.
            3. Write to collision-resistant temp file with exclusive creation (O_EXCL).
            4. Flush internal buffers and invoke os.fsync to ensure physical persistence.
            5. If backup=True and target file exists and is non-empty, create '{name}.bak'.
            6. Atomically replace target with temp file via os.replace.
            7. Clean up temporary file on any error.

        Args:
            file_path: Destination path for the file.
            content: String or byte content to write.
            backup: If True, maintains a single valid .bak copy of prior state.
            encoding: Text encoding when content is str.

        Returns:
            Resolved Path of the written file.

        Raises:
            PersistenceError: If the write, sync, or replace operation fails.
        """
        target = Path(file_path).resolve()
        parent_dir = target.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        if is_symlink_or_reparse_point(target):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="recovery.persistence",
                message=f"Target file is a symlink or reparse point: {target}",
                details={"target": str(target)},
            )
            raise PersistenceError(f"Refusing to write to symlink or reparse point: '{target}'")

        rand_hex = secrets.token_hex(4)
        temp_path = parent_dir / f"{target.name}.tmp.{os.getpid()}.{threading.get_ident()}.{time.perf_counter_ns()}.{rand_hex}"
        backup_path = parent_dir / f"{target.name}.bak"

        is_bytes = isinstance(content, bytes)
        raw_bytes = content if is_bytes else content.encode(encoding)

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            fd = os.open(temp_path, flags, 0o600)
            try:
                os.write(fd, raw_bytes)
                os.fsync(fd)
            finally:
                os.close(fd)

            # Backup existing file before replacement if valid
            if backup and target.is_file() and target.stat().st_size > 0:
                if is_symlink_or_reparse_point(backup_path):
                    try:
                        backup_path.unlink()
                    except OSError:
                        pass
                try:
                    shutil.copy2(target, backup_path)
                except Exception as exc:
                    logger.warning("Could not create backup file '%s': %s", backup_path, exc)

            # Atomic rename / replace with bounded retry on Windows
            replace_ok = False
            last_rep_exc = None
            for _ in range(5):
                try:
                    os.replace(temp_path, target)
                    replace_ok = True
                    break
                except OSError as rep_exc:
                    last_rep_exc = rep_exc
                    time.sleep(0.02)
            if not replace_ok:
                raise last_rep_exc or OSError(f"Could not replace '{target}' with '{temp_path}'")
            return target

        except Exception as exc:
            if temp_path.is_file():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            logger.error("Atomic write failed for '%s': %s", target, exc)
            raise PersistenceError(f"Failed to atomically persist '{target}': {exc}") from exc

    @classmethod
    def atomic_write_json(
        cls,
        file_path: Union[Path, str],
        data: Any,
        backup: bool = True,
        indent: int = 2,
    ) -> Path:
        """Serialize data to formatted JSON and write atomically.

        Args:
            file_path: Destination path.
            data: JSON-serializable object.
            backup: If True, maintain .bak backup.
            indent: JSON indentation.

        Returns:
            Resolved Path of the written file.
        """
        try:
            content = json.dumps(data, indent=indent, default=str)
        except Exception as exc:
            raise PersistenceError(f"Data serialization to JSON failed: {exc}") from exc
        return cls.atomic_write(file_path, content, backup=backup, encoding="utf-8")

    @staticmethod
    def safe_read_json(
        file_path: Union[Path, str],
        default: Any = None,
        schema_validator: Optional[Callable[[Any], bool]] = None,
        allow_backup_fallback: bool = True,
    ) -> tuple[Any, bool, Optional[str]]:
        """Safely read and validate a JSON file with automatic backup recovery.

        Args:
            file_path: Path to the JSON file.
            default: Default value returned if unrecoverable.
            schema_validator: Optional predicate function f(data) -> bool.
            allow_backup_fallback: Attempt reading '{name}.bak' if primary is corrupted.

        Returns:
            tuple: (data, recovered_from_backup: bool, error_message: Optional[str])
        """
        target = Path(file_path).resolve()
        backup_path = target.parent / f"{target.name}.bak"

        # Helper to test and parse a single file path
        def _try_parse(path: Path) -> tuple[Optional[Any], Optional[str]]:
            if is_symlink_or_reparse_point(path):
                log_security_event(
                    SecurityEventType.SECURITY_PATH_REJECTED,
                    subsystem="recovery.persistence",
                    message=f"Refusing to read JSON through symlink or reparse point: {path}",
                    details={"path": str(path)},
                )
                return None, f"Refusing to read symlink or reparse point: {path}"
            if not path.is_file():
                return None, f"File does not exist: {path}"
            size = path.stat().st_size
            if size == 0:
                return None, f"File is empty (zero bytes): {path}"
            try:
                text = path.read_text(encoding="utf-8")
                parsed = json.loads(text)
                if schema_validator and not schema_validator(parsed):
                    return None, f"JSON schema validation rejected contents of {path}"
                return parsed, None
            except json.JSONDecodeError as exc:
                return None, f"Malformed JSON in {path}: {exc}"
            except Exception as exc:
                return None, f"Failed to read {path}: {exc}"

        # 1. Try reading primary target file
        data, primary_err = _try_parse(target)
        if primary_err is None and data is not None:
            return data, False, None

        logger.warning("Primary state file corrupted or missing ('%s'): %s", target, primary_err)

        # 2. Try fallback to .bak if permitted
        if allow_backup_fallback and backup_path.is_file():
            backup_data, backup_err = _try_parse(backup_path)
            if backup_err is None and backup_data is not None:
                logger.info("Successfully recovered state from backup: %s", backup_path)
                return backup_data, True, f"Recovered from backup after primary error: {primary_err}"
            else:
                logger.warning("Backup state file also invalid ('%s'): %s", backup_path, backup_err)

        # 3. Unrecoverable: return default
        final_err = primary_err or "Unknown state file error"
        return default, False, final_err
