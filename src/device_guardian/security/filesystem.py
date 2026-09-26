"""Filesystem security validation and reparse-point/symlink defense for Device Guardian (Phase 9).

Provides robust local filesystem defenses:
- Rejection of path traversal ('..'), UNC network paths, drive-relative paths,
  and NTFS Alternate Data Streams (ADS).
- Defense against symbolic links, directory junctions, and Windows reparse points.
- Strict directory containment enforcement (no jailbreaking from data/staging directories).
- Safe temporary file creation with exclusive flags (O_EXCL | O_CREAT).
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import secrets
import stat
import threading
import time
from typing import Optional, Union

from device_guardian.logger import get_logger
from device_guardian.security.events import SecurityEventType, log_security_event

logger = get_logger("security.filesystem")


class SecurityPathError(Exception):
    """Raised when a path violates filesystem security policies."""
    pass


def is_symlink_or_reparse_point(path: Union[Path, str]) -> bool:
    """Check whether a path is a symbolic link, directory junction, or Windows reparse point.

    Args:
        path: Path to inspect.

    Returns:
        True if the path exists and is a symlink or reparse point, False otherwise.
    """
    try:
        p = Path(path)
        # Check standard symlink first (works on POSIX and modern Windows)
        if os.path.islink(str(p)):
            return True

        if hasattr(p, "is_symlink") and p.is_symlink():
            return True

        # Windows-specific reparse point check (handles NTFS junctions and mount points)
        if platform.system() == "Windows" and hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"):
            try:
                st = os.lstat(str(p))
                file_attrs = getattr(st, "st_file_attributes", 0)
                if file_attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    return True
            except (OSError, ValueError):
                pass

        return False
    except Exception:
        return False


def validate_safe_path(
    path: Union[Path, str],
    base_dir: Optional[Union[Path, str]] = None,
    allow_absolute: bool = True,
    allow_symlinks: bool = False,
    allow_reparse: bool = False,
    allow_unc: bool = False,
) -> Path:
    r"""Validate that a filesystem path adheres to security policies.

    Args:
        path: Path string or Path object to validate.
        base_dir: Optional base directory that the path must be strictly contained within.
        allow_absolute: If False, rejects absolute paths.
        allow_symlinks: If False, rejects symbolic links.
        allow_reparse: If False, rejects Windows reparse points / directory junctions.
        allow_unc: If False, rejects UNC network paths (e.g. \\server\share).

    Returns:
        Validated, resolved Path object.

    Raises:
        SecurityPathError: If any security rule is violated.
    """
    if path is None:
        raise SecurityPathError("Path cannot be None.")

    raw = str(path).strip()
    if not raw:
        raise SecurityPathError("Path cannot be empty.")

    # 1. Null byte injection check
    if "\0" in raw:
        log_security_event(
            SecurityEventType.SECURITY_PATH_REJECTED,
            subsystem="filesystem",
            message="Null byte detected in path.",
            details={"raw_path": repr(raw)},
        )
        raise SecurityPathError("Null byte injection detected in path.")

    # 2. UNC path check (\\server\share or //server/share)
    if not allow_unc and (raw.startswith(r"\\") or raw.startswith("//")):
        log_security_event(
            SecurityEventType.SECURITY_PATH_REJECTED,
            subsystem="filesystem",
            message="UNC network paths are prohibited.",
            details={"raw_path": raw},
        )
        raise SecurityPathError(f"UNC network paths are prohibited: '{raw}'")

    # 3. NTFS Alternate Data Streams (ADS) check
    # In Windows, paths like 'file.txt:stream' access hidden streams.
    # Exclude drive letters (e.g. 'C:\') which have colon at index 1.
    if platform.system() == "Windows":
        cleaned = raw[2:] if (len(raw) > 2 and raw[1] == ":") else raw
        if ":" in cleaned:
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="filesystem",
                message="NTFS Alternate Data Stream syntax detected.",
                details={"raw_path": raw},
            )
            raise SecurityPathError(f"NTFS Alternate Data Streams are prohibited: '{raw}'")

    # 4. Drive-relative path check (e.g. 'C:foo.txt' instead of 'C:\foo.txt')
    if platform.system() == "Windows" and len(raw) >= 2 and raw[1] == ":":
        if len(raw) == 2 or raw[2] not in ("\\", "/"):
            raise SecurityPathError(f"Drive-relative paths are prohibited: '{raw}'")

    # 5. Path traversal segment check ('..')
    normalized_parts = raw.replace("\\", "/").split("/")
    if ".." in normalized_parts:
        log_security_event(
            SecurityEventType.SECURITY_PATH_REJECTED,
            subsystem="filesystem",
            message="Path traversal segment ('..') detected.",
            details={"raw_path": raw},
        )
        raise SecurityPathError(f"Path traversal ('..') detected: '{raw}'")

    p = Path(raw)

    # 6. Absolute path policy check
    if not allow_absolute and p.is_absolute():
        raise SecurityPathError(f"Absolute paths are not allowed in this context: '{raw}'")

    resolved = p.resolve()

    # 7. Symlink and Reparse Point Checks
    if not allow_symlinks and is_symlink_or_reparse_point(resolved):
        log_security_event(
            SecurityEventType.SECURITY_PATH_REJECTED,
            subsystem="filesystem",
            message="Symbolic link or junction blocked.",
            details={"path": str(resolved)},
        )
        raise SecurityPathError(f"Symbolic link or junction rejected: '{resolved}'")

    # 8. Directory containment check
    if base_dir is not None:
        resolved_base = Path(base_dir).resolve()
        try:
            resolved.relative_to(resolved_base)
        except ValueError:
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="filesystem",
                message="Path escapes required base directory containment.",
                details={"target": str(resolved), "base": str(resolved_base)},
            )
            raise SecurityPathError(
                f"Path '{resolved}' escapes base directory '{resolved_base}'"
            )

        # Inspect all intermediate ancestors inside base_dir for symlinks
        if not allow_symlinks or not allow_reparse:
            curr = resolved
            while curr != resolved_base and curr != curr.parent:
                if curr.exists() and is_symlink_or_reparse_point(curr):
                    raise SecurityPathError(
                        f"Reparse point or symlink ancestor detected: '{curr}'"
                    )
                curr = curr.parent

    return resolved


def secure_create_temp_file(
    parent_dir: Union[Path, str],
    prefix: str = "tmp",
    suffix: str = ".tmp",
) -> Path:
    """Create a temporary file securely with exclusive creation flags and restrictive permissions.

    Args:
        parent_dir: Directory where temp file should reside.
        prefix: Filename prefix.
        suffix: Filename suffix.

    Returns:
        Resolved Path of newly created empty file.

    Raises:
        SecurityPathError: If directory is invalid or file cannot be securely created.
    """
    target_dir = validate_safe_path(parent_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # Generate collision-resistant unique filename
    random_hex = secrets.token_hex(4)
    pid = os.getpid()
    tid = threading.get_ident()
    t_ns = time.perf_counter_ns()
    filename = f"{prefix}_{pid}_{tid}_{t_ns}_{random_hex}{suffix}"
    temp_path = target_dir / filename

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        fd = os.open(str(temp_path), flags, 0o600)
        os.close(fd)
        return temp_path.resolve()
    except Exception as exc:
        raise SecurityPathError(f"Failed to create secure temporary file '{temp_path}': {exc}") from exc
