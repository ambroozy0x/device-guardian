"""Detection Manager coordinating authentication monitoring, thresholds, and alerts.

Maintains detection lifecycle:
- Manages the active platform authentication monitor.
- Routes normalized failure events through SlidingWindowThresholdEngine.
- Evaluates cooldown windows to prevent alert storms.
- Synthesizes offline voice warnings when threshold is exceeded.
- Triggers the central Device Guardian alert pipeline without duplicating code.
"""

from __future__ import annotations

from datetime import datetime
import platform
import threading
import time
from typing import Callable, Optional

from device_guardian.alerts.pipeline import AlertResult, trigger_alert
from device_guardian.config import AppConfig, load_config
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.cooldown import AlertCooldownManager
from device_guardian.detection.linux import LinuxAuthLogMonitor
from device_guardian.detection.macos import MacOSAuthLogMonitor
from device_guardian.detection.models import (
    AuthenticationFailureEvent,
    DetectionStatus,
    MonitorState,
)
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.detection.voice import OfflineVoiceWarning
from device_guardian.detection.windows import WindowsSecurityLogMonitor
from device_guardian.environment.detector import EnvironmentalDetector
from device_guardian.environment.models import EnvironmentalContext
from device_guardian.filtering.engine import SmartFilterEngine
from device_guardian.filtering.models import FilterContext, FilterDecision, FilterResult
from device_guardian.filtering.trusted import TrustedContext
from device_guardian.logger import get_logger

logger = get_logger("detection.manager")


class NullAuthenticationMonitor(BaseAuthenticationMonitor):
    """Fallback monitor for unsupported operating systems."""

    def is_available(self) -> tuple[bool, str]:
        from device_guardian.platform_compat import get_current_os
        return False, f"Operating system '{get_current_os().value}' is not supported for authentication monitoring."

    def get_source_name(self) -> str:
        return "Unsupported Platform Monitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list[AuthenticationFailureEvent]:
        return []


def create_platform_monitor() -> BaseAuthenticationMonitor:
    """Instantiate the appropriate authentication monitor for the current platform."""
    from device_guardian.platform_compat import OperatingSystem, get_current_os
    curr_os = get_current_os()
    if curr_os == OperatingSystem.WINDOWS:
        return WindowsSecurityLogMonitor()
    elif curr_os == OperatingSystem.LINUX:
        return LinuxAuthLogMonitor()
    elif curr_os == OperatingSystem.MACOS:
        return MacOSAuthLogMonitor()
    return NullAuthenticationMonitor()


class DetectionManager:
    """Coordinates authentication failure monitoring, threshold evaluation, and alert dispatch."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        monitor: Optional[BaseAuthenticationMonitor] = None,
        threshold_engine: Optional[SlidingWindowThresholdEngine] = None,
        cooldown_manager: Optional[AlertCooldownManager] = None,
        voice_warning: Optional[OfflineVoiceWarning] = None,
        alert_dispatcher: Optional[Callable[..., AlertResult]] = None,
        environmental_detector: Optional[EnvironmentalDetector] = None,
        filter_engine: Optional[SmartFilterEngine] = None,
    ) -> None:
        """Initialize the detection manager.

        Args:
            config: Optional pre-loaded AppConfig.
            monitor: Optional OS authentication monitor (defaults to platform monitor).
            threshold_engine: Optional threshold engine.
            cooldown_manager: Optional alert cooldown manager.
            voice_warning: Optional offline voice warning engine.
            alert_dispatcher: Optional alert execution callable (defaults to trigger_alert).
            environmental_detector: Optional environmental detector.
            filter_engine: Optional smart filter engine.
        """
        self.config = config or load_config()
        self.monitor = monitor or create_platform_monitor()
        self.threshold_engine = threshold_engine or SlidingWindowThresholdEngine(
            threshold=self.config.auth_failure_threshold,
            window_seconds=self.config.auth_failure_window_seconds,
        )
        self.cooldown_manager = cooldown_manager or AlertCooldownManager(
            cooldown_seconds=self.config.auth_alert_cooldown_seconds,
        )
        self.voice_warning = voice_warning or OfflineVoiceWarning(
            enabled=self.config.voice_warning_enabled,
            warning_text=self.config.voice_warning_text,
            cooldown_seconds=self.config.voice_warning_cooldown_seconds,
        )
        self.alert_dispatcher = alert_dispatcher or trigger_alert

        # Phase 4: Environmental detection and smart filtering
        self.environmental_detector = environmental_detector or EnvironmentalDetector(
            network_context_enabled=self.config.network_context_enabled,
            device_state_context_enabled=self.config.device_state_context_enabled,
            environmental_triggers_enabled=self.config.environmental_triggers_enabled,
        )
        trusted_ctx = TrustedContext(
            trusted_users=self.config.trusted_users,
            trusted_networks=self.config.trusted_networks,
            trusted_auth_types=self.config.trusted_auth_types,
        )
        self.filter_engine = filter_engine or SmartFilterEngine(
            trusted_context=trusted_ctx,
            filtering_enabled=self.config.smart_filtering_enabled,
            require_context_for_alert=self.config.require_context_for_alert,
        )

        self._last_auth_env_context: Optional[EnvironmentalContext] = None
        self.state: MonitorState = MonitorState.READY
        self.total_events_processed: int = 0
        self.alerts_triggered: int = 0
        self.alerts_suppressed_by_cooldown: int = 0
        self.alerts_suppressed_by_filter: int = 0

    def get_monitor_status(self) -> tuple[DetectionStatus, str]:
        """Check operational status of the underlying authentication monitor.

        Returns:
            Tuple of (DetectionStatus, status_message).
        """
        available, msg = self.monitor.is_available()
        status = DetectionStatus.READY if available else DetectionStatus.UNAVAILABLE
        return status, msg

    def process_event(
        self,
        event: AuthenticationFailureEvent,
        is_synthetic: bool = False,
    ) -> bool:
        """Process a single normalized authentication failure event.

        Evaluates sliding-window threshold, collects environmental context,
        evaluates deterministic filter rules, checks cooldown, triggers voice warning,
        and executes the alert pipeline if conditions are met.

        Args:
            event: Normalized authentication failure event.
            is_synthetic: Explicit flag indicating whether event is part of an authorized synthetic test.

        Returns:
            True if an alert was successfully triggered, False otherwise.
        """
        self.total_events_processed += 1
        logger.info(
            "Processing authentication failure event: %s",
            event.format_summary(),
        )

        # Step 1: Record event in sliding-window threshold engine
        threshold_reached, count, window_events = self.threshold_engine.record_event(event)

        # Step 2: Collect environmental context
        env_context = self.environmental_detector.collect_context()

        # Step 2b: Detect context transition across auth failure events
        if self._last_auth_env_context is not None:
            state_changed = (
                env_context.device_state != self._last_auth_env_context.device_state
                or env_context.network_context.state != self._last_auth_env_context.network_context.state
            )
            if state_changed:
                desc = (
                    f"Authentication failure recorded with environmental context transition: "
                    f"Device [{self._last_auth_env_context.device_state.value} -> {env_context.device_state.value}], "
                    f"Network [{self._last_auth_env_context.network_context.state.value} -> {env_context.network_context.state.value}]"
                )
                self.environmental_detector.record_auth_context_change(desc, env_context)
        self._last_auth_env_context = env_context

        # Step 3: Evaluate through Smart Filter Engine
        synthetic_flag = (
            is_synthetic
            or (event.source == "SyntheticTestMonitor" and bool(event.details.get("test_run", False)))
        )
        filter_context = FilterContext(
            event=event,
            environmental_context=env_context,
            consecutive_failures=count,
            threshold=self.threshold_engine.threshold,
            window_seconds=self.threshold_engine.window_seconds,
            is_synthetic=synthetic_flag,
        )
        filter_result = self.filter_engine.evaluate(filter_context)

        # Step 4: Handle filter suppression
        if filter_result.decision == FilterDecision.FILTER:
            if threshold_reached:
                self.alerts_suppressed_by_filter += 1
            self.state = MonitorState.READY
            logger.info(
                "Event filtered by Smart Filter Engine: [%s] %s",
                filter_result.rule_id,
                filter_result.explanation,
            )
            return False

        if filter_result.decision != FilterDecision.ALERT_ELIGIBLE:
            self.state = MonitorState.READY
            return False

        # Step 5: Threshold and rules justify alert; evaluate cooldown
        self.state = MonitorState.THRESHOLD_REACHED

        if not self.cooldown_manager.can_alert():
            self.alerts_suppressed_by_cooldown += 1
            self.state = MonitorState.COOLDOWN
            logger.info(
                "Authentication failure threshold (%d) met, but alert suppressed due to active cooldown "
                "(%.1fs remaining).",
                count,
                self.cooldown_manager.time_remaining(),
            )
            return False

        logger.warning(
            "Authentication failure threshold reached (%d failures within %.1fs window). "
            "Environmental Context: %s. Dispatching alert workflow.",
            count,
            self.threshold_engine.window_seconds,
            env_context.format_summary(),
        )

        # Step 6: Trigger offline voice warning if enabled
        if self.voice_warning.enabled and self.voice_warning.can_speak():
            try:
                self.voice_warning.speak()
            except Exception as exc:
                logger.warning("Voice warning invocation failed: %s", exc)

        # Step 7: Execute alert pipeline
        reason = (
            f"Repeated authentication failures detected "
            f"({count} events in {self.threshold_engine.window_seconds:.0f}s)"
        )
        try:
            result = self.alert_dispatcher(reason=reason, config=self.config)
            # Record alert attempt and reset sliding window to prevent alert storm,
            # even if external notification delivery partially or fully failed
            self.cooldown_manager.record_alert()
            self.threshold_engine.reset()

            if result.success:
                self.alerts_triggered += 1
                self.state = MonitorState.ALERT_SENT
                logger.info("Security alert dispatched successfully.")
                return True
            else:
                self.state = MonitorState.ERROR
                logger.error("Alert pipeline failed: %s", result.error_message)
                return False
        except Exception as exc:
            self.cooldown_manager.record_alert()
            self.threshold_engine.reset()
            self.state = MonitorState.ERROR
            logger.error("Unexpected error executing alert pipeline: %s", exc)
            return False

    def poll_once(self) -> list[AuthenticationFailureEvent]:
        """Poll the active monitor once and process any new events detected.

        Returns:
            List of new authentication failure events detected during the poll.
        """
        new_events = self.monitor.poll()
        for ev in new_events:
            self.process_event(ev)
        return new_events

    def run_monitoring_loop(
        self,
        sleep_interval: float = 2.0,
        stop_event: Optional[threading.Event] = None,
        max_iterations: Optional[int] = None,
    ) -> None:
        """Run the continuous polling and detection loop.

        Args:
            sleep_interval: Delay between polls in seconds.
            stop_event: Optional threading.Event to signal loop termination.
            max_iterations: Optional maximum loop iterations (useful for testing).
        """
        logger.info(
            "Starting authentication monitoring loop (Source: %s, Threshold: %d in %.1fs, Cooldown: %.1fs)...",
            self.monitor.get_source_name(),
            self.threshold_engine.threshold,
            self.threshold_engine.window_seconds,
            self.cooldown_manager.cooldown_seconds,
        )

        self.monitor.start()
        iterations = 0

        try:
            while True:
                if stop_event and stop_event.is_set():
                    logger.info("Stop event signaled; terminating monitor loop.")
                    break

                if max_iterations is not None and iterations >= max_iterations:
                    break

                self.poll_once()
                iterations += 1

                # Responsive sleep checking stop_event
                if stop_event:
                    stop_event.wait(timeout=sleep_interval)
                else:
                    time.sleep(sleep_interval)

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received; shutting down monitor cleanly.")
        finally:
            self.monitor.stop()
            logger.info("Authentication monitoring loop stopped.")

    def run_synthetic_test(self, count: Optional[int] = None) -> bool:
        """Execute an end-to-end test of the threshold and alert pipeline using synthetic events.

        Allows validating detection, voice warning, and alert delivery without requiring
        real authentication failures or administrative log privileges.

        Args:
            count: Number of synthetic events to inject (defaults to threshold count).

        Returns:
            True if the test triggered the pipeline successfully, False otherwise.
        """
        target_count = count or self.threshold_engine.threshold
        logger.info(
            "Executing synthetic authentication monitor test (%d events)...",
            target_count,
        )

        from device_guardian.platform_compat import get_current_os
        triggered = False
        for i in range(1, target_count + 1):
            synthetic_event = AuthenticationFailureEvent(
                timestamp=datetime.now(),
                platform=get_current_os().value,
                source="SyntheticTestMonitor",
                username="test_user",
                remote_address="Local Console",
                authentication_type="local",
                details={"test_run": True, "event_number": i},
            )
            was_triggered = self.process_event(synthetic_event, is_synthetic=True)
            if was_triggered:
                triggered = True

        return triggered
