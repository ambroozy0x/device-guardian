"""System tray manager for Device Guardian (Phase 5).

Provides background tray icon integration using pystray:
- Dynamic status icon reflecting RuntimeState.
- Interactive context menu (Start, Stop, Restart, Test Alert, Startup Toggle, Exit).
- Safe background thread updates.
- Headless graceful degradation.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

from device_guardian.logger import get_logger
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.startup.factory import create_startup_manager
from device_guardian.tray.icons import create_tray_image

logger = get_logger("tray.manager")


class TrayManager:
    """Manages the system tray icon, lifecycle, and interactive menu."""

    def __init__(
        self,
        runtime: GuardianRuntime,
        poll_interval: float = 1.0,
    ) -> None:
        """Initialize the tray manager.

        Args:
            runtime: Active GuardianRuntime instance.
            poll_interval: Seconds between state checks for icon updates.
        """
        self.runtime = runtime
        self.poll_interval = poll_interval
        self.startup_manager = create_startup_manager()

        self._icon = None
        self._stop_event = threading.Event()
        self._updater_thread: Optional[threading.Thread] = None
        self._last_state: Optional[RuntimeState] = None

    def is_headless(self) -> bool:
        """Detect whether the current environment lacks a graphical display server."""
        from device_guardian.platform_compat import is_linux
        if is_linux() and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return True
        return False

    def setup_icon(self) -> bool:
        """Prepare the pystray icon and menu structure.

        Returns:
            True if tray icon setup succeeded, False if unavailable/headless.
        """
        if self.is_headless():
            logger.info("Headless environment detected; system tray icon will not be initialized.")
            return False

        try:
            import pystray
        except ImportError:
            logger.warning("pystray is not installed; system tray unavailable.")
            return False

        try:
            current_state = self.runtime.status.state
            initial_image = create_tray_image(current_state)

            menu = pystray.Menu(
                pystray.MenuItem(
                    lambda text: f"Status: {self.runtime.status.state.value}",
                    action=None,
                    enabled=False,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Start Monitoring",
                    self._on_start,
                    enabled=lambda item: not self.runtime.is_running(),
                ),
                pystray.MenuItem(
                    "Stop Monitoring",
                    self._on_stop,
                    enabled=lambda item: self.runtime.is_running(),
                ),
                pystray.MenuItem(
                    "Restart Monitoring",
                    self._on_restart,
                    enabled=lambda item: self.runtime.is_running(),
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Trigger Test Alert",
                    self._on_test_alert,
                ),
                pystray.MenuItem(
                    "Run System Diagnostics",
                    self._on_diagnostics,
                ),
                pystray.MenuItem(
                    "Check Update Status",
                    self._on_update_status,
                ),
                pystray.MenuItem(
                    lambda text: f"Launch at Startup: {'[ON]' if self.startup_manager.is_enabled() else '[OFF]'}",
                    self._on_toggle_startup,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Exit Device Guardian",
                    self._on_exit,
                ),
            )

            self._icon = pystray.Icon(
                name="DeviceGuardian",
                icon=initial_image,
                title=f"Device Guardian ({current_state.value})",
                menu=menu,
            )
            self._last_state = current_state
            return True
        except Exception as exc:
            logger.warning("Failed to initialize system tray icon: %s", exc)
            self._icon = None
            return False

    def run(self, blocking: bool = True) -> None:
        """Run the tray icon event loop.

        Args:
            blocking: If True, blocks on icon.run(). If False, runs in background thread.
        """
        if self._icon is None:
            if not self.setup_icon():
                return

        self._stop_event.clear()
        self._updater_thread = threading.Thread(
            target=self._state_watcher_loop,
            name="TrayStateWatcher",
            daemon=True,
        )
        self._updater_thread.start()

        logger.info("System tray icon starting...")
        try:
            if blocking:
                self._icon.run()
            else:
                tray_thread = threading.Thread(
                    target=self._icon.run,
                    name="TrayMainThread",
                    daemon=True,
                )
                tray_thread.start()
        except Exception as exc:
            logger.warning("System tray run terminated: %s", exc)

    def stop(self) -> None:
        """Stop the tray icon and clean up resources."""
        self._stop_event.set()
        if self._updater_thread and self._updater_thread.is_alive():
            self._updater_thread.join(timeout=2.0)

        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception as exc:
                logger.debug("Error stopping tray icon: %s", exc)
            self._icon = None

        logger.info("System tray icon stopped.")

    def _state_watcher_loop(self) -> None:
        """Background loop to update tray icon and tooltip when runtime state changes."""
        while not self._stop_event.is_set():
            try:
                current_state = self.runtime.status.state
                if current_state != self._last_state and self._icon is not None:
                    self._last_state = current_state
                    new_img = create_tray_image(current_state)
                    self._icon.icon = new_img
                    self._icon.title = f"Device Guardian ({current_state.value})"
                    self._icon.update_menu()
            except Exception as exc:
                logger.debug("Error updating tray icon: %s", exc)

            self._stop_event.wait(timeout=self.poll_interval)

    # --- Menu Callbacks ---

    def _on_start(self, icon, item) -> None:
        """Handle Start Monitoring menu action."""
        logger.info("Tray: Start Monitoring selected.")
        threading.Thread(target=self.runtime.start, kwargs={"blocking": False}, daemon=True).start()

    def _on_stop(self, icon, item) -> None:
        """Handle Stop Monitoring menu action."""
        logger.info("Tray: Stop Monitoring selected.")
        threading.Thread(target=self.runtime.stop, daemon=True).start()

    def _on_restart(self, icon, item) -> None:
        """Handle Restart Monitoring menu action."""
        logger.info("Tray: Restart Monitoring selected.")
        threading.Thread(target=self.runtime.restart, daemon=True).start()

    def _on_test_alert(self, icon, item) -> None:
        """Handle Test Alert menu action in background thread."""
        logger.info("Tray: Test Alert selected.")
        def _run_test():
            if self.runtime.detection_manager is not None:
                self.runtime.detection_manager.run_synthetic_test(count=1)
            else:
                from device_guardian.alerts.pipeline import trigger_alert
                trigger_alert(reason="Test Alert from System Tray", config=self.runtime.config)
        threading.Thread(target=_run_test, daemon=True).start()

    def _on_diagnostics(self, icon, item) -> None:
        """Handle Run Diagnostics menu action in background thread."""
        logger.info("Tray: Run Diagnostics selected.")
        def _run_diag():
            from device_guardian.recovery.health import assess_system_health
            report = assess_system_health(config=self.runtime.config)
            logger.info("Tray Diagnostics result: %s", report.overall_status.value)
        threading.Thread(target=_run_diag, daemon=True).start()

    def _on_update_status(self, icon, item) -> None:
        """Handle Check Update Status menu action in background thread."""
        logger.info("Tray: Check Update Status selected.")
        def _run_update():
            from device_guardian.updates.installer import UpdateInstaller
            summary = UpdateInstaller.get_update_status_summary()
            rollbacks = summary.get("available_rollbacks", [])
            logger.info("Tray Update Check: rollbacks available=%d", len(rollbacks))
        threading.Thread(target=_run_update, daemon=True).start()

    def _on_toggle_startup(self, icon, item) -> None:
        """Toggle OS startup registration."""
        if self.startup_manager.is_enabled():
            self.startup_manager.disable()
            logger.info("Tray: Startup launch disabled.")
        else:
            self.startup_manager.enable()
            logger.info("Tray: Startup launch enabled.")
        if self._icon is not None:
            self._icon.update_menu()

    def _on_exit(self, icon, item) -> None:
        """Gracefully terminate background runtime and quit tray."""
        logger.info("Tray: Exit requested by user.")
        self.stop()
        self.runtime.stop()
