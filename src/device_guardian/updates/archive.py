"""Safe archive validation and extraction for Device Guardian updates (Phase 7 & Phase 9 Hardening).

Guarantees:
- Path traversal rejection (no '..', absolute paths, drive letters, UNC, ADS).
- Symlink, hardlink, and Windows reparse point / junction attack prevention.
- Duplicate member and case-insensitive filename collision prevention.
- Strict directory containment enforcement.
- Zip bomb defense (strict individual file and total uncompressed size limits).
- Whitelist enforcement of allowable update artifacts.
- Post-extraction integrity and symlink verification.
- No execution of archive contents during extraction.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Set
import zipfile

from device_guardian.logger import get_logger
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import (
    is_symlink_or_reparse_point,
    validate_safe_path,
    SecurityPathError,
)

logger = get_logger("updates.archive")

MAX_FILE_SIZE_BYTES = 250 * 1024 * 1024       # 250 MB single file limit
MAX_TOTAL_ARCHIVE_BYTES = 500 * 1024 * 1024    # 500 MB total uncompressed limit
MAX_MEMBER_COUNT = 50                          # Maximum files in an update archive

ALLOWED_EXTENSIONS: Set[str] = {
    "",
    ".exe",
    ".bin",
    ".json",
    ".sig",
    ".txt",
    ".md",
    ".dll",
    ".so",
    ".dylib",
}


class ArchiveSecurityError(Exception):
    """Raised when an update archive violates security policies."""
    pass


# Backwards compatibility alias
ArchiveExtractionError = ArchiveSecurityError


class SafeZipExtractor:
    """Validates and extracts ZIP archives enforcing strict security boundaries."""

    @classmethod
    def validate_and_extract(
        cls,
        zip_path: Path | str,
        destination_dir: Path | str,
        max_members: Optional[int] = None,
        max_single_file_size_bytes: Optional[int] = None,
    ) -> list[Path]:
        """Validate an update archive and safely extract its members.

        Args:
            zip_path: Path to the .zip archive.
            destination_dir: Directory where verified files should be written.
            max_members: Optional maximum member count override.

        Returns:
            List of successfully extracted file paths.

        Raises:
            ArchiveSecurityError: If any path traversal, size limit, or unsafe member is detected.
        """
        archive_path = Path(zip_path).resolve()
        dest_dir = Path(destination_dir).resolve()

        if not archive_path.is_file():
            raise ArchiveSecurityError(f"Update archive file not found: {archive_path}")

        # Ensure destination directory is safe
        try:
            validate_safe_path(dest_dir, allow_symlinks=False, allow_reparse=False)
        except SecurityPathError as spe:
            raise ArchiveSecurityError(f"Destination directory security violation: {spe}")

        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                infolist = zf.infolist()

                if len(infolist) == 0:
                    raise ArchiveSecurityError("Update archive is empty.")
                effective_max = max_members if max_members is not None else MAX_MEMBER_COUNT
                if len(infolist) > effective_max:
                    log_security_event(
                        SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                        subsystem="updates.archive",
                        message=f"Archive exceeded max member count ({len(infolist)} > {effective_max}).",
                    )
                    raise ArchiveSecurityError(
                        f"Archive exceeds maximum allowed members ({len(infolist)} > {effective_max})."
                    )

                total_uncompressed = 0
                seen_names_lower: Set[str] = set()

                for info in infolist:
                    name = info.filename.replace("\\", "/")

                    # 1. Reject duplicate names and case-insensitive collisions
                    normalized_lower = name.strip("/").lower()
                    if normalized_lower in seen_names_lower:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Duplicate filename or case-insensitive collision: '{name}'",
                        )
                        raise ArchiveSecurityError(
                            f"Duplicate or case-insensitive collision detected in archive: '{name}'"
                        )
                    seen_names_lower.add(normalized_lower)

                    # 2. Check for path traversal attacks
                    if ".." in name.split("/"):
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Path traversal detected in member: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Path traversal detected in archive member: '{name}'")
                    if name.startswith("/") or (len(name) > 1 and name[1] == ":") or name.startswith("//"):
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Absolute or UNC path detected in member: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Absolute path detected in archive member: '{name}'")

                    # 3. Check for NTFS Alternate Data Streams
                    if ":" in name:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"NTFS ADS detected in member: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Prohibited colon/stream syntax in member: '{name}'")

                    # 4. Check for symlinks/special files (UNIX permission mode & Windows reparse attributes)
                    unix_mode = info.external_attr >> 16
                    if unix_mode & 0o120000 == 0o120000:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Symbolic link detected in archive: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Symbolic link detected and blocked in archive: '{name}'")

                    # Windows reparse point flag check in external_attr
                    if (info.external_attr & 0x0400) == 0x0400:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Reparse point attribute detected in member: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Reparse point attribute blocked in archive: '{name}'")

                    # 5. Check file extension against whitelist
                    ext = Path(name).suffix.lower()
                    if not info.is_dir() and ext not in ALLOWED_EXTENSIONS:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message=f"Prohibited file extension '{ext}' in member: '{name}'",
                        )
                        raise ArchiveSecurityError(f"Prohibited file extension '{ext}' in member: '{name}'")

                    # 6. Zip bomb checks
                    single_limit = max_single_file_size_bytes if max_single_file_size_bytes is not None else MAX_FILE_SIZE_BYTES
                    if info.file_size > single_limit:
                        raise ArchiveSecurityError(
                            f"File '{name}' exceeds size limit ({info.file_size} > {single_limit} bytes)."
                        )
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_TOTAL_ARCHIVE_BYTES:
                        log_security_event(
                            SecurityEventType.SECURITY_ARCHIVE_REJECTED,
                            subsystem="updates.archive",
                            message="Archive exceeded total uncompressed size limit.",
                        )
                        raise ArchiveSecurityError(
                            f"Total archive uncompressed size exceeds limit ({total_uncompressed} > {MAX_TOTAL_ARCHIVE_BYTES} bytes)."
                        )

                # Extraction phase
                extracted_files: list[Path] = []
                for info in infolist:
                    if info.is_dir():
                        continue

                    normalized_name = info.filename.replace("\\", "/").lstrip("/")
                    target_path = (dest_dir / normalized_name).resolve()

                    # Containment and symlink/junction defense
                    try:
                        validate_safe_path(
                            target_path,
                            base_dir=dest_dir,
                            allow_symlinks=False,
                            allow_reparse=False,
                        )
                    except SecurityPathError as spe:
                        raise ArchiveSecurityError(f"Target path security violation: {spe}")

                    if target_path.exists():
                        if is_symlink_or_reparse_point(target_path):
                            raise ArchiveSecurityError(
                                f"Existing target is a symlink or reparse point: '{target_path}'"
                            )
                        try:
                            target_path.unlink()
                        except OSError:
                            pass

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as source, target_path.open("wb") as target:
                        while True:
                            chunk = source.read(65536)
                            if not chunk:
                                break
                            target.write(chunk)

                    # Post-write symlink/reparse point validation
                    if is_symlink_or_reparse_point(target_path):
                        try:
                            target_path.unlink()
                        except OSError:
                            pass
                        raise ArchiveSecurityError(
                            f"Extracted file is a symlink or reparse point: '{target_path}'"
                        )

                    extracted_files.append(target_path)

                return extracted_files

        except zipfile.BadZipFile as exc:
            raise ArchiveSecurityError(f"Malformed or corrupted ZIP archive: {exc}")
        except ArchiveSecurityError:
            raise
        except Exception as exc:
            raise ArchiveSecurityError(f"Archive extraction failed: {exc}")

    extract = validate_and_extract
    extract_archive = validate_and_extract
