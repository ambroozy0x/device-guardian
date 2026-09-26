"""Secret storage abstraction and secure OS-backed implementations for Device Guardian (Phase 6).

Provides encrypted credential persistence:
- Windows: Native DPAPI (CryptProtectData / CryptUnprotectData) per-user storage.
- Linux/macOS fallback: Restrictive filesystem permissions (0600 owner-only).
- Atomic persistence with temporary files to avoid half-written state.
- No "dump all secrets" operation; strictly access-by-key.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point
from device_guardian.security.secret import SecretValue

logger = get_logger("security.store")


class SecretStore(ABC):
    """Abstract interface for secure local credential storage."""

    @abstractmethod
    def set_secret(self, name: str, value: str | SecretValue) -> bool:
        """Store a sensitive credential under a specific name.

        Args:
            name: Key identifier (e.g. 'telegram_bot_token').
            value: Secret content to persist.

        Returns:
            True if stored successfully, False otherwise.
        """
        pass

    @abstractmethod
    def get_secret(self, name: str) -> Optional[SecretValue]:
        """Retrieve a stored secret by name.

        Args:
            name: Key identifier.

        Returns:
            SecretValue if found, None if not stored.
        """
        pass

    @abstractmethod
    def delete_secret(self, name: str) -> bool:
        """Remove a stored secret.

        Args:
            name: Key identifier.

        Returns:
            True if removed or did not exist, False on error.
        """
        pass

    @abstractmethod
    def has_secret(self, name: str) -> bool:
        """Check whether a secret key exists in the store without exposing its value."""
        pass

    @abstractmethod
    def list_secret_names(self) -> list[str]:
        """List registered secret key names (values are never returned)."""
        pass

    @abstractmethod
    def get_backend_name(self) -> str:
        """Return the descriptive name of the active storage backend."""
        pass


class FileSecretStore(SecretStore):
    """Filesystem-based secret store with restrictive permissions and atomic writes."""

    def __init__(self, file_path: Optional[Path] = None) -> None:
        """Initialize file-based secret store.

        Args:
            file_path: Optional path override for secret storage file.
        """
        if file_path:
            self.file_path = Path(file_path).resolve()
        else:
            try:
                from device_guardian.runtime.paths import ApplicationPaths
                self.file_path = ApplicationPaths.get_user_data_dir() / "secrets.json"
            except Exception:
                self.file_path = Path.home() / ".device_guardian" / "secrets.json"

    def _load_data(self) -> dict[str, str]:
        """Read dictionary from disk securely with automatic backup fallback."""
        if not self.file_path.is_file():
            return {}
        if is_symlink_or_reparse_point(self.file_path):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="security.store",
                message=f"Secret store file is a symlink or reparse point: {self.file_path}",
                details={"path": str(self.file_path)},
            )
            return {}
        try:
            from device_guardian.recovery.persistence import AtomicPersistence
            data, recovered, err = AtomicPersistence.safe_read_json(
                self.file_path,
                default=None,
                allow_backup_fallback=True,
            )
            if isinstance(data, dict):
                return data

            # Primary and backup failed. Preserve corrupted file
            if self.file_path.is_file() and self.file_path.stat().st_size > 0:
                corrupt_path = self.file_path.parent / f"{self.file_path.name}.corrupt.{int(time.time())}"
                shutil.copy2(self.file_path, corrupt_path)
                logger.error("Preserved corrupted secret store file to: %s", corrupt_path)
        except Exception as exc:
            logger.debug("Failed to read file secret store: %s", exc)
        return {}

    def _save_data(self, data: dict[str, str]) -> bool:
        """Persist dictionary to disk atomically with restrictive permissions and backup."""
        if is_symlink_or_reparse_point(self.file_path):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="security.store",
                message=f"Secret store destination is a symlink or reparse point: {self.file_path}",
                details={"path": str(self.file_path)},
            )
            return False
        try:
            from device_guardian.platform_compat import set_posix_permissions
            from device_guardian.recovery.persistence import AtomicPersistence
            AtomicPersistence.atomic_write_json(self.file_path, data, backup=True, indent=2)
            set_posix_permissions(self.file_path, 0o600)
            backup_path = self.file_path.parent / f"{self.file_path.name}.bak"
            if backup_path.is_file():
                set_posix_permissions(backup_path, 0o600)
            return True
        except Exception as exc:
            logger.error("Failed to persist file secret store: %s", exc)
            return False

    def set_secret(self, name: str, value: str | SecretValue) -> bool:
        data = self._load_data()
        val_str = value.get_secret_value() if isinstance(value, SecretValue) else str(value)
        data[name] = val_str
        return self._save_data(data)

    def get_secret(self, name: str) -> Optional[SecretValue]:
        data = self._load_data()
        val = data.get(name)
        if val is None:
            return None
        return SecretValue(val)

    def delete_secret(self, name: str) -> bool:
        data = self._load_data()
        if name in data:
            del data[name]
            return self._save_data(data)
        return True

    def has_secret(self, name: str) -> bool:
        data = self._load_data()
        return name in data and bool(data[name].strip())

    def list_secret_names(self) -> list[str]:
        data = self._load_data()
        return sorted(list(data.keys()))

    def get_backend_name(self) -> str:
        return "Filesystem (Restricted Permissions)"


class WindowsDPAPISecretStore(SecretStore):
    """Windows Data Protection API (DPAPI) encrypted secret store.

    Uses CryptProtectData and CryptUnprotectData to encrypt credentials using the
    current logged-in Windows user's cryptographic keys. Decryption is only possible
    under the same user account on the same machine.
    """

    def __init__(self, file_path: Optional[Path] = None) -> None:
        """Initialize DPAPI secret store.

        Args:
            file_path: Optional path override for encrypted blob storage.
        """
        if file_path:
            self.file_path = Path(file_path).resolve()
        else:
            try:
                from device_guardian.runtime.paths import ApplicationPaths
                self.file_path = ApplicationPaths.get_user_data_dir() / "secrets.dat"
            except Exception:
                self.file_path = Path.home() / ".device_guardian" / "secrets.dat"

    def _encrypt(self, data_bytes: bytes) -> bytes:
        """Encrypt bytes using Windows DPAPI."""
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB(
            len(data_bytes),
            ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)),
        )
        out_blob = DATA_BLOB()

        # CRYPTPROTECT_UI_FORBIDDEN = 0x1
        success = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "DeviceGuardianSecrets",
            None,
            None,
            None,
            0x1,
            ctypes.byref(out_blob),
        )
        if not success:
            raise OSError(f"CryptProtectData failed with error code: {kernel32.GetLastError()}")

        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        kernel32.LocalFree(out_blob.pbData)
        return encrypted

    def _decrypt(self, encrypted_bytes: bytes) -> bytes:
        """Decrypt bytes using Windows DPAPI."""
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB(
            len(encrypted_bytes),
            ctypes.cast(ctypes.create_string_buffer(encrypted_bytes), ctypes.POINTER(ctypes.c_byte)),
        )
        out_blob = DATA_BLOB()

        # CRYPTPROTECT_UI_FORBIDDEN = 0x1
        success = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0x1,
            ctypes.byref(out_blob),
        )
        if not success:
            raise OSError(f"CryptUnprotectData failed with error code: {kernel32.GetLastError()}")

        decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        kernel32.LocalFree(out_blob.pbData)
        return decrypted

    def _load_data(self) -> dict[str, str]:
        """Read and decrypt stored dictionary from disk with backup fallback."""
        if not self.file_path.is_file():
            return {}
        if is_symlink_or_reparse_point(self.file_path):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="security.store",
                message=f"DPAPI secrets file is a symlink or reparse point: {self.file_path}",
                details={"path": str(self.file_path)},
            )
            return {}
        backup_path = self.file_path.parent / f"{self.file_path.name}.bak"
        try:
            encrypted_payload = self.file_path.read_bytes()
            if not encrypted_payload:
                return {}
            decrypted_json = self._decrypt(encrypted_payload).decode("utf-8")
            return json.loads(decrypted_json)
        except Exception as exc:
            logger.warning("Failed to decrypt primary DPAPI secrets file ('%s'): %s", self.file_path, exc)
            if backup_path.is_file():
                try:
                    bk_payload = backup_path.read_bytes()
                    if bk_payload:
                        bk_json = self._decrypt(bk_payload).decode("utf-8")
                        logger.info("Successfully recovered DPAPI secrets from backup: %s", backup_path)
                        return json.loads(bk_json)
                except Exception as bk_exc:
                    logger.warning("Backup DPAPI secrets file also invalid ('%s'): %s", backup_path, bk_exc)

            # Preserve corrupted file
            try:
                if self.file_path.is_file() and self.file_path.stat().st_size > 0:
                    corrupt_path = self.file_path.parent / f"{self.file_path.name}.corrupt.{int(time.time())}"
                    shutil.copy2(self.file_path, corrupt_path)
                    logger.error("Preserved corrupted DPAPI secrets file to: %s", corrupt_path)
            except Exception:
                pass
            return {}

    def _save_data(self, data: dict[str, str]) -> bool:
        """Encrypt and atomically write dictionary to disk with backup."""
        if is_symlink_or_reparse_point(self.file_path):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="security.store",
                message=f"DPAPI secrets destination is a symlink or reparse point: {self.file_path}",
                details={"path": str(self.file_path)},
            )
            return False
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            raw_bytes = json.dumps(data).encode("utf-8")
            encrypted = self._encrypt(raw_bytes)

            from device_guardian.recovery.persistence import AtomicPersistence
            AtomicPersistence.atomic_write(self.file_path, encrypted, backup=True)
            return True
        except Exception as exc:
            logger.error("Failed to write DPAPI secrets: %s", exc)
            return False

    def set_secret(self, name: str, value: str | SecretValue) -> bool:
        data = self._load_data()
        val_str = value.get_secret_value() if isinstance(value, SecretValue) else str(value)
        data[name] = val_str
        return self._save_data(data)

    def get_secret(self, name: str) -> Optional[SecretValue]:
        data = self._load_data()
        val = data.get(name)
        if val is None:
            return None
        return SecretValue(val)

    def delete_secret(self, name: str) -> bool:
        data = self._load_data()
        if name in data:
            del data[name]
            return self._save_data(data)
        return True

    def has_secret(self, name: str) -> bool:
        data = self._load_data()
        return name in data and bool(data[name].strip())

    def list_secret_names(self) -> list[str]:
        data = self._load_data()
        return sorted(list(data.keys()))

    def get_backend_name(self) -> str:
        return "Windows DPAPI (CryptProtectData User-Bound Encryption)"


def create_default_secret_store(file_path: Optional[Path] = None) -> SecretStore:
    """Instantiate the most secure secret store supported on the current host.

    Priority:
    1. Windows DPAPI if on Windows platform.
    2. Fallback to restrictive FileSecretStore on other platforms or if DPAPI is unavailable.
    """
    from device_guardian.platform_compat import is_windows
    if is_windows():
        try:
            return WindowsDPAPISecretStore(file_path=file_path)
        except Exception as exc:
            logger.warning("Windows DPAPI store initialization failed, falling back to file store: %s", exc)
            return FileSecretStore(file_path=file_path)
    return FileSecretStore(file_path=file_path)
