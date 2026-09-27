"""Runtime controller for Device Guardian (Phase 5).

Manages background worker lifecycle, explicit state machine transitions,
auto-restart crash recovery, IPC stop signaling, and status serialization.
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import threading
import time
from typing import Callable, Optional

from device_guardian.config import AppConfig, load_config
from device_guardian.detection.manager import DetectionManager
from device_guardian.logger import get_logger
from device_guardian.runtime.models import RuntimeState, RuntimeStatus
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock

logger = get_logger("runtime.controller")


class GuardianRuntime:
    """Controls the background lifecycle of Device Guardian."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        detection_manager: Optional[DetectionManager] = None,
        single_instance_lock: Optional[SingleInstanceLock] = None,
        status_file_path: Optional[Path] = None,
        poll_interval: float = 2.0,
    ) -> None:
        """Initialize the runtime controller.

        Args:
            config: Optional application configuration (loaded from disk if omitted).
            detection_manager: Optional detection manager instance.
            single_instance_lock: Optional single-instance lock instance.
            status_file_path: Optional path for persisting runtime status JSON.
            poll_interval: Polling sleep interval in seconds.
        """
        self.config = config or load_config()
        self.detection_manager = detection_manager
        self.single_instance = single_instance_lock or SingleInstanceLock()
        self.status_file = status_file_path or ApplicationPaths.get_status_file_path()
        self.poll_interval = poll_interval

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._status = RuntimeStatus()
        self._restart_attempts = 0
        self._is_restarting = False

    @property
    def status(self) -> RuntimeStatus:
        """Get the current runtime status copy."""
        with self._lock:
            self._sync_status_fields()
            return self._status

    def _sync_status_fields(self) -> None:
        """Synchronize telemetry from detection manager and instance lock into status."""
        self._status.pid = os.getpid() if self._status.state in {RuntimeState.STARTING, RuntimeState.RUNNING} else None
        self._status.single_instance_active = self.single_instance.is_locked()
        self._status.startup_enabled = self.config.start_with_system

        if self.detection_manager is not None:
            self._status.total_events_processed = self.detection_manager.total_events_processed
            self._status.alerts_triggered = self.detection_manager.alerts_triggered
            self._status.alerts_suppressed_by_cooldown = (
                self.detection_manager.alerts_suppressed_by_cooldown
            )
            self._status.alerts_suppressed_by_filter = (
                self.detection_manager.alerts_suppressed_by_filter
            )

    def persist_status(self) -> None:
        """Write current status to disk for CLI and system tray observation."""
        try:
            with self._lock:
                self._sync_status_fields()
                status_dict = self._status.to_dict()

            from device_guardian.recovery.persistence import AtomicPersistence
            AtomicPersistence.atomic_write_json(self.status_file, status_dict, backup=True)
        except Exception as exc:
            logger.debug("Failed to persist runtime status: %s", exc)

    def start(self, blocking: bool = False) -> bool:
        """Start the background monitoring runtime.

        Args:
            blocking: If True, blocks the calling thread until the runtime is stopped.

        Returns:
            True if started successfully, False if already running or lock acquisition failed.
        """
        with self._lock:
            if self._status.state in {RuntimeState.RUNNING, RuntimeState.STARTING}:
                logger.warning("Device Guardian is already running (State: %s).", self._status.state.value)
                return True

            self._status.state = RuntimeState.STARTING
            self._status.last_error = None

        logger.info("Initializing Device Guardian background runtime...")

        # Step 1: Single Instance Lock
        if self.config.single_instance_enabled:
            if not self.single_instance.acquire():
                with self._lock:
                    self._status.state = RuntimeState.STOPPED
                    self._status.last_error = "Could not acquire single instance lock; another process is running."
                self.persist_status()
                return False

        # Step 2: Ensure DetectionManager is initialized
        if self.detection_manager is None:
            self.detection_manager = DetectionManager(config=self.config)

        # Step 3: Clean up any prior terminated thread
        if self._worker_thread is not None and not self._worker_thread.is_alive():
            self._worker_thread = None

        # Spawn background worker thread
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="GuardianRuntimeWorker",
            daemon=True,
        )
        self._worker_thread.start()

        # Wait briefly for worker to transition to RUNNING
        start_wait = 0.0
        while start_wait < 2.0 and self._status.state == RuntimeState.STARTING:
            time.sleep(0.02)
            start_wait += 0.02

        self.persist_status()

        if blocking:
            try:
                while self.is_running():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received. Stopping runtime...")
                self.stop()

        return self._status.state == RuntimeState.RUNNING

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop the background monitoring runtime gracefully.

        Args:
            timeout: Maximum seconds to wait for worker thread shutdown.

        Returns:
            True if stopped cleanly.
        """
        with self._lock:
            if self._status.state in {RuntimeState.STOPPED, RuntimeState.STOPPING}:
                return True
            self._status.state = RuntimeState.STOPPING

        logger.info("Stopping Device Guardian runtime...")
        self._stop_event.set()

        # Signal monitor if active
        if self.detection_manager is not None:
            try:
                self.detection_manager.monitor.stop()
            except Exception as exc:
                logger.debug("Error stopping monitor: %s", exc)

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            if self._worker_thread.is_alive():
                logger.warning("Worker thread did not terminate within %.1fs timeout.", timeout)
            else:
                self._worker_thread = None
        else:
            self._worker_thread = None

        # Release single instance lock
        if self.config.single_instance_enabled:
            self.single_instance.release()

        with self._lock:
            self._status.state = RuntimeState.STOPPED
            self._status.started_at = None
            self._restart_attempts = 0

        try:
            from device_guardian.reliability.metrics import get_reliability_metrics
            get_reliability_metrics().set_worker_count(0)
        except Exception:
            pass

        self.persist_status()
        logger.info("Device Guardian runtime stopped successfully.")
        return True

    def restart(self, timeout: float = 5.0) -> bool:
        """Restart the background runtime cleanly.

        Args:
            timeout: Shutdown timeout in seconds.

        Returns:
            True if restarted successfully.
        """
        logger.info("Restarting Device Guardian runtime...")
        self.stop(timeout=timeout)
        time.sleep(0.5)
        return self.start(blocking=False)

    def is_running(self) -> bool:
        """Check whether the runtime is actively running."""
        with self._lock:
            return self._status.state == RuntimeState.RUNNING

    def _worker_loop(self) -> None:
        """Continuous execution loop executed inside background worker thread."""
        with self._lock:
            self._status.state = RuntimeState.RUNNING
            self._status.started_at = datetime.now()
            self._status.pid = os.getpid()

        self.persist_status()

        if self.detection_manager is not None:
            try:
                self.detection_manager.monitor.start()
            except Exception as exc:
                logger.warning("Could not start platform monitor: %s", exc)

        logger.info("Guardian background worker running (PID: %d).", os.getpid())

        try:
            from device_guardian.reliability.metrics import get_reliability_metrics
            get_reliability_metrics().set_worker_count(1)
        except Exception:
            pass

        while not self._stop_event.is_set():
            # Check IPC stop signal from another CLI invocation
            if self.single_instance.check_stop_signal():
                logger.info("IPC stop signal detected. Initiating clean shutdown.")
                self.single_instance.clear_stop_signal()
                self._stop_event.set()
                break

            try:
                if self.detection_manager is not None:
                    self.detection_manager.poll_once()

                with self._lock:
                    self._status.last_detection_cycle = datetime.now()
                    self._sync_status_fields()

                # Periodic status flush
                self.persist_status()

            except Exception as exc:
                logger.error("Unexpected error in background worker loop: %s", exc)
                try:
                    from device_guardian.reliability.metrics import get_reliability_metrics
                    get_reliability_metrics().record_unexpected_exception(exc)
                except Exception:
                    pass
                with self._lock:
                    self._status.last_error = str(exc)

                # Attempt bounded crash recovery if configured
                recovered = self._handle_worker_crash()
                if not recovered:
                    with self._lock:
                        self._status.state = RuntimeState.FAILED
                    if self.config.single_instance_enabled:
                        self.single_instance.release()
                    self.persist_status()
                    try:
                        from device_guardian.reliability.metrics import get_reliability_metrics
                        get_reliability_metrics().set_worker_count(0)
                    except Exception:
                        pass
                    return

            # Responsive wait on stop event
            self._stop_event.wait(timeout=self.poll_interval)

        # Worker shutdown
        if self.detection_manager is not None:
            try:
                self.detection_manager.monitor.stop()
            except Exception:
                pass

        try:
            from device_guardian.reliability.metrics import get_reliability_metrics
            get_reliability_metrics().set_worker_count(0)
        except Exception:
            pass

        with self._lock:
            if self._status.state != RuntimeState.FAILED:
                self._status.state = RuntimeState.STOPPED

        self.persist_status()

    def _handle_worker_crash(self) -> bool:
        """Handle worker crash with bounded auto-restart recovery.

        Returns:
            True if recovered and execution should continue, False if retries exhausted.
        """
        if not self.config.auto_restart_enabled:
            logger.error("Auto-restart is disabled. Worker terminating permanently.")
            return False

        if self._restart_attempts >= self.config.max_restart_attempts:
            logger.critical(
                "Maximum restart attempts (%d) reached. Transitioning to FAILED state.",
                self.config.max_restart_attempts,
            )
            return False

        self._restart_attempts += 1
        with self._lock:
            self._status.restart_count = self._restart_attempts

        backoff = self.config.restart_backoff_seconds * (1.5 ** (self._restart_attempts - 1))
        logger.warning(
            "Worker error encountered. Attempting recovery restart %d/%d after %.1fs backoff...",
            self._restart_attempts,
            self.config.max_restart_attempts,
            backoff,
        )

        interrupted = self._stop_event.wait(timeout=backoff)
        if interrupted or self._stop_event.is_set():
            logger.info("Stop event signaled during recovery backoff. Aborting restart.")
            return False

        # Re-initialize detector monitor
        try:
            if self.detection_manager is not None:
                self.detection_manager.monitor.stop()
                self.detection_manager.monitor.start()
            logger.info("Worker recovered successfully on attempt %d.", self._restart_attempts)
            return True
        except Exception as retry_exc:
            logger.error("Worker recovery failed on attempt %d: %s", self._restart_attempts, retry_exc)
            return False
