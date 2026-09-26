"""Application paths and resource discovery for Device Guardian (Phase 5).

Provides reliable resource resolution across source execution, testing,
and frozen PyInstaller executables. Ensures mutable data (logs, config,
locks) is never written into read-only installation directories.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import sys
from typing import Optional


class ApplicationPaths:
    """Manages application filesystem locations and asset discovery."""

    _override_data_dir: Optional[Path] = None
    _override_install_dir: Optional[Path] = None

    @classmethod
    def set_data_dir_override(cls, path: Optional[Path | str]) -> None:
        """Override data directory for test isolation."""
        cls._override_data_dir = Path(path).resolve() if path else None

    @classmethod
    def set_install_dir_override(cls, path: Optional[Path | str]) -> None:
        """Override install root directory for test isolation."""
        cls._override_install_dir = Path(path).resolve() if path else None

    @classmethod
    def is_frozen(cls) -> bool:
        """Check if application is running as a packaged executable."""
        return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")

    @classmethod
    def get_bundle_dir(cls) -> Path:
        """Return the read-only directory containing bundled code and assets.

        - If frozen: PyInstaller temporary extraction directory (_MEIPASS) or executable dir.
        - If source: Project root directory containing src/ and resources.
        """
        if getattr(sys, "frozen", False):
            if hasattr(sys, "_MEIPASS"):
                return Path(sys._MEIPASS).resolve()
            return Path(sys.executable).resolve().parent

        # Source execution: 3 levels up from src/device_guardian/runtime/paths.py -> project root
        return Path(__file__).resolve().parent.parent.parent.parent

    @classmethod
    def get_executable_dir(cls) -> Path:
        """Return the directory containing the running executable or python script."""
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path.cwd().resolve()

    @classmethod
    def get_user_data_dir(cls) -> Path:
        """Return the writable user data directory appropriate for the current OS.

        Windows: %LOCALAPPDATA%\\DeviceGuardian
        macOS:   ~/Library/Application Support/DeviceGuardian
        Linux:   ~/.local/share/device-guardian
        """
        if cls._override_data_dir is not None:
            cls._override_data_dir.mkdir(parents=True, exist_ok=True)
            return cls._override_data_dir

        from device_guardian.platform_compat import is_windows, is_macos

        if is_windows():
            local_appdata = os.environ.get("LOCALAPPDATA")
            if local_appdata:
                base = Path(local_appdata) / "DeviceGuardian"
            else:
                base = Path.home() / ".device_guardian"
        elif is_macos():
            base = Path.home() / "Library" / "Application Support" / "DeviceGuardian"
        else:
            xdg_data = os.environ.get("XDG_DATA_HOME")
            if xdg_data:
                base = Path(xdg_data) / "device-guardian"
            else:
                base = Path.home() / ".local" / "share" / "device-guardian"

        base.mkdir(parents=True, exist_ok=True)
        return base

    @classmethod
    def get_config_file_path(cls) -> Path:
        """Find or create the .env configuration file path.

        Priority:
        1. Explicit .env in user data directory (preferred for packaged app)
        2. .env in current working directory (preferred for source dev)
        3. .env in executable directory
        """
        # First check CWD for developer convenience
        cwd_env = Path.cwd() / ".env"
        if cwd_env.is_file():
            return cwd_env

        # Check user data dir
        user_env = cls.get_user_data_dir() / ".env"
        if user_env.is_file():
            return user_env

        # Check executable directory
        exe_env = cls.get_executable_dir() / ".env"
        if exe_env.is_file():
            return exe_env

        # Default to CWD if running from source, otherwise user data dir
        if cls.is_frozen():
            return user_env
        return cwd_env

    @classmethod
    def get_log_dir(cls) -> Path:
        """Return the directory designated for application logs."""
        log_dir = cls.get_user_data_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir

    @classmethod
    def get_lock_file_path(cls) -> Path:
        """Return lock file path for single instance coordination."""
        return cls.get_user_data_dir() / "guardian.lock"

    @classmethod
    def get_status_file_path(cls) -> Path:
        """Return JSON status file path for CLI and tray status observation."""
        return cls.get_user_data_dir() / "runtime_status.json"

    @classmethod
    def get_control_file_path(cls) -> Path:
        """Return control signal file path for cross-process IPC (e.g. stop command)."""
        return cls.get_user_data_dir() / "guardian.control"

    @classmethod
    def get_executable_path(cls) -> Path:
        """Return the resolved path to the running or target binary."""
        if cls.is_frozen():
            return Path(sys.executable).resolve()
        from device_guardian.platform_compat import get_executable_name
        binary_name = get_executable_name()
        return (cls.get_bundle_dir() / "dist" / binary_name).resolve()

    @classmethod
    def get_updates_dir(cls) -> Path:
        """Return the base directory for update staging, validation, and backups."""
        updates_dir = cls.get_user_data_dir() / "updates"
        updates_dir.mkdir(parents=True, exist_ok=True)
        return updates_dir

    @classmethod
    def get_update_staging_dir(cls) -> Path:
        """Return isolated directory for extracting and staging unverified packages."""
        staging_dir = cls.get_updates_dir() / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        return staging_dir

    @classmethod
    def get_update_verified_dir(cls) -> Path:
        """Return directory for verified, ready-to-deploy release artifacts."""
        verified_dir = cls.get_updates_dir() / "verified"
        verified_dir.mkdir(parents=True, exist_ok=True)
        return verified_dir

    @classmethod
    def get_update_backup_dir(cls) -> Path:
        """Return directory containing rollback backups of previous verified versions."""
        backup_dir = cls.get_updates_dir() / "backup"
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    @classmethod
    def get_update_failed_dir(cls) -> Path:
        """Return directory where failed or rejected update artifacts are quarantined."""
        failed_dir = cls.get_updates_dir() / "failed"
        failed_dir.mkdir(parents=True, exist_ok=True)
        return failed_dir

    @classmethod
    def get_update_transaction_file_path(cls) -> Path:
        """Return file path for atomic update transaction state persistence."""
        return cls.get_updates_dir() / "update_transaction.json"

    @classmethod
    def get_install_root(cls) -> Path:
        """Return the root installation directory containing binaries and bundled assets.

        Separates application binary installation root from mutable user data directory.
        """
        if cls._override_install_dir is not None:
            cls._override_install_dir.mkdir(parents=True, exist_ok=True)
            return cls._override_install_dir

        if cls.is_frozen():
            return cls.get_executable_dir()

        from device_guardian.platform_compat import is_windows, is_macos

        if is_windows():
            local_appdata = os.environ.get("LOCALAPPDATA")
            if local_appdata:
                base = Path(local_appdata) / "Programs" / "DeviceGuardian"
            else:
                base = Path.home() / "AppData" / "Local" / "Programs" / "DeviceGuardian"
        elif is_macos():
            base = Path.home() / "Applications" / "DeviceGuardian"
        else:
            base = Path.home() / ".local" / "share" / "device-guardian" / "bin"

        base.mkdir(parents=True, exist_ok=True)
        return base

    @classmethod
    def get_install_metadata_file_path(cls) -> Path:
        """Return path to persistent installation metadata file."""
        return cls.get_user_data_dir() / "install_metadata.json"

    @classmethod
    def get_lifecycle_transaction_file_path(cls) -> Path:
        """Return path to atomic lifecycle transaction state file."""
        return cls.get_user_data_dir() / "lifecycle_transaction.json"


def set_install_dir_override(path: Optional[Path | str]) -> None:
    """Override application installation directory for testing."""
    ApplicationPaths.set_install_dir_override(path)


def set_user_data_dir_override(path: Optional[Path | str]) -> None:
    """Override user data directory for testing."""
    ApplicationPaths.set_data_dir_override(path)


