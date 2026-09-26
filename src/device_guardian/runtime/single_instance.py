"""Single instance lock and cross-process coordination for Device Guardian (Phase 5 & Phase 9 Hardening).

Ensures only one instance of Device Guardian runs at a time:
- Local-only coordination; absolutely NO listening network ports or sockets.
- On Windows: Uses Win32 Named Mutex via ctypes with fallback PID lockfile.
- On Linux/macOS: Uses file locking with active PID liveness checks.
- Process identity verification & PID reuse defense: verifies process executable
  and creation time to avoid misidentifying recycled PIDs.
- Automatically detects and prunes stale or corrupted locks from aborted processes.
- Safe cross-process signaling using hardened ControlChannel with replay protection,
  schema validation, and TTL expiry.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Optional

from device_guardian.logger import get_logger
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.security.events import SecurityEventType, log_security_event
from device_guardian.security.filesystem import is_symlink_or_reparse_point, validate_safe_path
from device_guardian.security.ipc import ControlChannel, ControlCommand

logger = get_logger("runtime.single_instance")

MUTEX_NAME = "Local\\DeviceGuardianSingleInstanceMutex"


def _get_process_info_windows(pid: int) -> tuple[bool, Optional[str], Optional[int]]:
    """Query liveness, image path, and creation time for a Windows process.

    Returns:
        (is_alive, exe_path, creation_time_ticks)
    """
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False, None, None

        try:
            exit_code = ctypes.c_ulong()
            res = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not res or exit_code.value != STILL_ACTIVE:
                return False, None, None

            # Query executable name
            exe_path = None
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if hasattr(kernel32, "QueryFullProcessImageNameW"):
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    exe_path = buf.value

            # Query process creation time
            creation_ticks = None
            c_time = wintypes.FILETIME()
            e_time = wintypes.FILETIME()
            k_time = wintypes.FILETIME()
            u_time = wintypes.FILETIME()
            if kernel32.GetProcessTimes(
                handle,
                ctypes.byref(c_time),
                ctypes.byref(e_time),
                ctypes.byref(k_time),
                ctypes.byref(u_time),
            ):
                creation_ticks = (c_time.dwHighDateTime << 32) | c_time.dwLowDateTime

            return True, exe_path, creation_ticks
        finally:
            kernel32.CloseHandle(handle)
    except Exception as exc:
        logger.debug("Windows process inspection failed for PID %d: %s", pid, exc)
        return False, None, None


class SingleInstanceLock:
    """Manages hardened single-instance enforcement and local process coordination."""

    def __init__(
        self,
        lock_file_path: Optional[Path] = None,
        control_file_path: Optional[Path] = None,
        mutex_name: Optional[str] = MUTEX_NAME,
    ) -> None:
        """Initialize the single instance manager.

        Args:
            lock_file_path: Optional path to override the lock file location.
            control_file_path: Optional path to override the control signaling file.
            mutex_name: Optional name for Windows named mutex, or None to disable.
        """
        self.lock_file = lock_file_path or ApplicationPaths.get_lock_file_path()
        self.control_file = control_file_path or ApplicationPaths.get_control_file_path()
        self.mutex_name = mutex_name
        self._mutex_handle = None
        self._flock_fd: Optional[int] = None
        self._flock_file = self.lock_file.with_suffix(".flock")
        self._acquired = False

    def is_locked(self) -> bool:
        """Check whether another active instance currently holds the lock."""
        lock_data = self.get_lock_data()
        if not lock_data:
            return False
        pid = lock_data.get("pid")
        if pid is None or pid <= 0:
            return False
        return self._is_pid_alive(
            pid,
            expected_creation=lock_data.get("creation_time"),
            expected_exe=lock_data.get("executable"),
        )

    def get_lock_data(self) -> Optional[dict[str, Any]]:
        """Read and validate lock file data."""
        if not self.lock_file.is_file():
            return None
        if is_symlink_or_reparse_point(self.lock_file):
            log_security_event(
                SecurityEventType.SECURITY_PATH_REJECTED,
                subsystem="single_instance",
                message="Lock file is a symlink or reparse point.",
                details={"path": str(self.lock_file)},
            )
            return None
        try:
            content = self.lock_file.read_text(encoding="utf-8").strip()
            if not content:
                return None
            data = json.loads(content)
            if not isinstance(data, dict):
                return None
            # Validate pid field
            raw_pid = data.get("pid")
            if raw_pid is None or not isinstance(raw_pid, int) or raw_pid <= 0:
                return None
            return data
        except Exception:
            return None

    def get_active_pid(self) -> Optional[int]:
        """Read the PID of the current lock holder if file exists and is valid."""
        data = self.get_lock_data()
        if data:
            return data.get("pid")
        return None

    def _is_pid_alive(
        self,
        pid: int,
        expected_creation: Optional[int] = None,
        expected_exe: Optional[str] = None,
    ) -> bool:
        """Check if process is active and corresponds to Device Guardian."""
        if pid <= 0:
            return False

        from device_guardian.platform_compat import is_windows
        if is_windows():
            alive, exe_path, creation_ticks = _get_process_info_windows(pid)
            if not alive:
                return False

            # Verify PID reuse against creation time if recorded
            if expected_creation is not None and creation_ticks is not None:
                if abs(creation_ticks - expected_creation) > 20000000:  # > 2 seconds difference
                    logger.warning("PID %d was reused by another process (creation time mismatch).", pid)
                    return False

            # Verify executable name corresponds to python or device-guardian
            if exe_path:
                exe_lower = exe_path.lower()
                valid_names = ("python.exe", "pythonw.exe", "device-guardian.exe", "pytest.exe")
                if not any(name in exe_lower for name in valid_names):
                    logger.warning("PID %d was reused by non-Guardian process: '%s'", pid, exe_path)
                    return False

            return True
        else:
            try:
                os.kill(pid, 0)
                # On Linux, inspect /proc/{pid}/cmdline if available
                proc_cmdline = Path(f"/proc/{pid}/cmdline")
                if proc_cmdline.is_file():
                    try:
                        cmdline = proc_cmdline.read_text(encoding="utf-8", errors="ignore").lower()
                        if "python" not in cmdline and "guardian" not in cmdline:
                            return False
                    except OSError:
                        pass
                return True
            except OSError:
                return False

    def acquire(self) -> bool:
        """Attempt to acquire exclusive single instance lock.

        Returns:
            True if lock was acquired successfully, False if another instance is active.
        """
        if self._acquired:
            return True

        current_pid = os.getpid()

        # Step 1: Check existing lock file and prune stale lock if present
        lock_data = self.get_lock_data()
        if lock_data is not None:
            active_pid = lock_data.get("pid")
            if active_pid is not None and active_pid != current_pid:
                if self._is_pid_alive(
                    active_pid,
                    expected_creation=lock_data.get("creation_time"),
                    expected_exe=lock_data.get("executable"),
                ):
                    logger.warning(
                        "Another active Device Guardian instance detected (PID: %d). Aborting startup.",
                        active_pid,
                    )
                    log_security_event(
                        SecurityEventType.SECURITY_LOCK_CONFLICT,
                        subsystem="single_instance",
                        message=f"Startup blocked by active instance (PID: {active_pid}).",
                        details={"active_pid": active_pid},
                    )
                    return False
                else:
                    logger.info("Pruning stale lock from terminated/recycled process (PID: %d).", active_pid)
                    self._cleanup_lock_file()

        # Step 2: System-level mutual exclusion
        from device_guardian.platform_compat import get_current_os, is_windows
        if is_windows() and self.mutex_name:
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                ERROR_ALREADY_EXISTS = 183

                handle = kernel32.CreateMutexW(None, False, self.mutex_name)
                last_error = kernel32.GetLastError()

                if handle and last_error == ERROR_ALREADY_EXISTS:
                    kernel32.CloseHandle(handle)
                    logger.warning("Windows Named Mutex already exists; another instance is running.")
                    log_security_event(
                        SecurityEventType.SECURITY_LOCK_CONFLICT,
                        subsystem="single_instance",
                        message="Windows Named Mutex already held by another process.",
                    )
                    return False

                self._mutex_handle = handle
            except Exception as exc:
                logger.debug("Windows Mutex acquisition skipped or failed: %s", exc)
        else:
            # POSIX flock mutual exclusion when fcntl is available
            try:
                import fcntl
                self._flock_file.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(self._flock_file), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._flock_fd = fd
                except (BlockingIOError, OSError) as lock_err:
                    os.close(fd)
                    logger.warning("POSIX file lock already held by another process: %s", lock_err)
                    log_security_event(
                        SecurityEventType.SECURITY_LOCK_CONFLICT,
                        subsystem="single_instance",
                        message="POSIX file lock already held by another process.",
                    )
                    return False
            except ImportError:
                pass
            except Exception as exc:
                logger.debug("POSIX flock acquisition skipped or failed: %s", exc)

        # Step 3: Write current process metadata to lock file using atomic persistence
        try:
            self.lock_file.parent.mkdir(parents=True, exist_ok=True)
            creation_ticks = None
            if is_windows():
                _, _, creation_ticks = _get_process_info_windows(current_pid)

            payload = {
                "pid": current_pid,
                "started_at": time.time(),
                "platform": get_current_os().value,
                "executable": sys.executable,
                "creation_time": creation_ticks,
            }

            from device_guardian.recovery.persistence import AtomicPersistence
            AtomicPersistence.atomic_write_json(self.lock_file, payload, backup=False)
            self._acquired = True
            self.clear_stop_signal()
            logger.info("Single instance lock acquired successfully (PID: %d).", current_pid)
            return True
        except Exception as exc:
            logger.error("Failed to write single instance lock file: %s", exc)
            self.release()
            return False

    def release(self) -> None:
        """Release the single instance lock."""
        # Release Windows Mutex
        if self._mutex_handle:
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
            except Exception:
                pass
            self._mutex_handle = None

        # Release POSIX flock if held
        if self._flock_fd is not None:
            try:
                import fcntl
                fcntl.flock(self._flock_fd, fcntl.LOCK_UN)
                os.close(self._flock_fd)
            except Exception:
                pass
            self._flock_fd = None
            try:
                if self._flock_file.is_file():
                    self._flock_file.unlink()
            except Exception:
                pass

        # Remove lock file if it belongs to current PID
        active_pid = self.get_active_pid()
        if active_pid == os.getpid():
            self._cleanup_lock_file()

        self._acquired = False
        logger.info("Single instance lock released.")

    def _cleanup_lock_file(self) -> None:
        """Safely remove the lock file."""
        try:
            if self.lock_file.is_file() or is_symlink_or_reparse_point(self.lock_file):
                self.lock_file.unlink()
            if self._flock_file.is_file() or is_symlink_or_reparse_point(self._flock_file):
                self._flock_file.unlink()
        except Exception as exc:
            logger.debug("Error cleaning up lock file: %s", exc)

    def signal_stop(self) -> bool:
        """Signal the running background instance to shut down cleanly using secure IPC."""
        return ControlChannel.send_command(self.control_file, ControlCommand.STOP)

    def check_stop_signal(self) -> bool:
        """Check if a valid, unexpired stop signal has been requested."""
        msg = ControlChannel.read_command(self.control_file)
        if msg is not None and msg.command == ControlCommand.STOP:
            return True
        return False

    def clear_stop_signal(self) -> None:
        """Clear any pending stop signals."""
        ControlChannel.clear(self.control_file)
