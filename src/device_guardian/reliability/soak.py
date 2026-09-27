"""Dedicated soak-test framework for Device Guardian (Phase 14).

Executes continuous reliability and resource stability soak tests across configurable modes:
- smoke: 30 seconds (or custom duration)
- short: 5 minutes (300s)
- extended: 30-60 minutes (1800s - 3600s)
- production: 24 hours (86400s)

Safety guarantees:
- Runs in an isolated temporary directory (never touches ~/.device_guardian).
- Uses mock/local notification sinks (never transmits real alerts or calls external APIs).
- Never requires real credentials or modifies production configuration.
- Periodically records JSON checkpoints with resource metrics (RSS memory, threads, queues, alerts).
- Gracefully handles SIGINT (Ctrl+C) and SIGTERM with clean state flush and cleanup.
- Rigorously validates execution against explicit reliability acceptance criteria (RSS growth,
  thread leakage, error budgets, retry bounds, and queue stability).
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Optional

from device_guardian.alerts.pipeline import AlertResult
from device_guardian.alerts.queue import BoundedAlertQueue
from device_guardian.config import AppConfig
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.logger import get_logger, setup_logging
from device_guardian.reliability.metrics import (
    ReliabilityMetrics,
    ReliabilityMetricsTracker,
    get_current_rss_bytes,
    get_current_thread_count,
    get_reliability_metrics,
    reset_reliability_metrics,
)
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.single_instance import SingleInstanceLock

logger = get_logger("reliability.soak")

SOAK_MODES: dict[str, float] = {
    "smoke": 30.0,
    "short": 300.0,
    "extended": 1800.0,
    "production": 86400.0,
}


@dataclass
class SoakAcceptanceCriteria:
    """Configurable thresholds for reliability soak acceptance."""

    max_unexpected_exceptions: int = 0
    max_thread_growth: int = 1  # Maximum permanent thread growth after runtime shutdown vs baseline
    max_rss_growth_mb: float = 80.0  # Maximum absolute RSS memory growth in MB
    max_rss_growth_ratio: float = 2.0  # Maximum relative RSS growth (final / initial)
    max_retry_count: int = 10  # Maximum total retries during soak
    max_queue_high_watermark: int = 50  # Maximum alert queue depth
    max_persistence_failures: int = 0  # Maximum persistence errors
    max_unrecovered_sensor_failures: int = 0  # Maximum unrecovered sensor failures

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ThresholdEvaluation:
    """Evaluation result for an individual reliability acceptance criterion."""

    name: str
    target: Any
    actual: Any
    passed: bool
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SoakCheckpoint:
    """Point-in-time diagnostic checkpoint during soak execution."""

    timestamp_iso: str
    elapsed_seconds: float
    mode: str
    target_duration_seconds: float
    rss_bytes: int
    rss_mb: float
    peak_rss_mb: float
    thread_count: int
    peak_thread_count: int
    events_injected: int
    events_processed: int
    alerts_triggered: int
    alerts_suppressed_cooldown: int
    alerts_suppressed_filter: int
    queue_high_watermark: int
    retry_count: int
    error_count: int
    status: str  # "STARTING", "RUNNING", "COMPLETED", "INTERRUPTED", "FAILED"


@dataclass
class SoakResult:
    """Final comprehensive report from a completed or interrupted soak test."""

    mode: str
    status: str  # "COMPLETED", "INTERRUPTED", "FAILED"
    acceptance_verdict: str  # "PASSED", "FAILED", "NOT_EVALUATED"
    success: bool  # True iff status == "COMPLETED" and acceptance_verdict == "PASSED"
    duration_seconds: float
    target_duration_seconds: float
    checkpoints_count: int

    # Memory metrics
    initial_rss_mb: float
    final_rss_mb: float
    peak_rss_mb: float
    rss_growth_mb: float
    rss_growth_ratio: float
    memory_accepted: bool

    # Thread metrics
    initial_thread_count: int
    final_thread_count: int
    peak_thread_count: int
    thread_growth: int
    threads_accepted: bool

    # Event metrics
    total_events_injected: int
    total_events_processed: int
    total_alerts_triggered: int
    total_alerts_suppressed: int

    # Queue metrics
    queue_high_watermark: int
    queue_dropped_count: int
    queue_accepted: bool

    # Retries & Errors
    total_retries: int
    total_unexpected_exceptions: int
    total_sensor_failures: int
    total_sensor_recoveries: int
    total_persistence_failures: int
    errors_accepted: bool

    # Evaluation details
    criteria: dict[str, Any]
    evaluations: list[dict[str, Any]]
    output_directory: str
    summary_message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SoakSyntheticMonitor(BaseAuthenticationMonitor):
    """Controlled monitor for injecting failure events periodically into the real pipeline."""

    def __init__(self, stop_ev: threading.Event) -> None:
        self.stop_ev = stop_ev
        self._pending: list[AuthenticationFailureEvent] = []
        self._lock = threading.Lock()

    def is_available(self) -> tuple[bool, str]:
        return True, "Soak synthetic monitor operational"

    def get_source_name(self) -> str:
        return "SoakSyntheticMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def enqueue(self, event: AuthenticationFailureEvent) -> None:
        with self._lock:
            self._pending.append(event)

    def poll(self) -> list[AuthenticationFailureEvent]:
        with self._lock:
            events = list(self._pending)
            self._pending.clear()
            return events


class SoakTestRunner:
    """Orchestrates continuous execution of Device Guardian under soak conditions."""

    def __init__(
        self,
        mode: str = "smoke",
        duration_seconds: Optional[float] = None,
        checkpoint_interval: float = 5.0,
        event_interval: float = 2.0,
        criteria: Optional[SoakAcceptanceCriteria] = None,
        output_dir: Optional[Path | str] = None,
        cleanup_on_exit: bool = False,
    ) -> None:
        """Initialize soak test runner.

        Args:
            mode: One of 'smoke', 'short', 'extended', 'production'.
            duration_seconds: Explicit override for soak duration in seconds.
            checkpoint_interval: Seconds between periodic metric checkpoints.
            event_interval: Seconds between synthetic event injections.
            criteria: Optional acceptance thresholds (uses defaults if omitted).
            output_dir: Directory for checkpoints and logs; defaults to secure temp dir.
            cleanup_on_exit: Whether to remove the temporary output directory on exit.
        """
        self.mode = mode.lower()
        if self.mode not in SOAK_MODES and duration_seconds is None:
            raise ValueError(f"Unknown soak mode '{mode}'. Choose from {list(SOAK_MODES.keys())}.")

        self.duration_seconds = duration_seconds if duration_seconds is not None else SOAK_MODES.get(self.mode, 30.0)
        self.checkpoint_interval = max(0.5, checkpoint_interval)
        self.event_interval = max(0.2, event_interval)
        self.criteria = criteria or SoakAcceptanceCriteria()
        self.cleanup_on_exit = cleanup_on_exit

        # Isolated directory setup
        if output_dir:
            self.work_dir = Path(output_dir).resolve()
            self.work_dir.mkdir(parents=True, exist_ok=True)
            self._owns_work_dir = False
        else:
            self.work_dir = Path(tempfile.mkdtemp(prefix="dg_soak_"))
            self._owns_work_dir = True

        self.checkpoints_file = self.work_dir / "soak_checkpoints.jsonl"
        self.summary_file = self.work_dir / "soak_summary.json"
        self.status_file = self.work_dir / "soak_status.json"
        self.lock_file = self.work_dir / "soak_instance.lock"

        # Dedicated bounded queue to exercise backpressure & queue metrics
        self.alert_queue = BoundedAlertQueue(maxsize=max(5, self.criteria.max_queue_high_watermark))

        self._stop_event = threading.Event()
        self._checkpoints: list[SoakCheckpoint] = []
        self._events_injected = 0
        self._peak_rss = get_current_rss_bytes()
        self._initial_rss = self._peak_rss
        self._initial_threads = get_current_thread_count()
        self._peak_threads = self._initial_threads
        self._status = "READY"
        self._interrupted = False

    def _setup_signal_handlers(self) -> None:
        """Register graceful interruption handlers for Ctrl+C and SIGTERM."""
        def _handle_interrupt(signum: int, frame: Any) -> None:
            logger.info("Interrupt signal (%d) received. Commencing graceful soak shutdown...", signum)
            self._interrupted = True
            self._stop_event.set()

        try:
            signal.signal(signal.SIGINT, _handle_interrupt)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, _handle_interrupt)
        except (ValueError, AttributeError):
            # In non-main thread or certain Windows test scenarios
            pass

    def _create_mock_alert_dispatcher(self) -> Callable[..., AlertResult]:
        """Create an in-memory alert dispatcher that exercises the bounded queue and never calls external APIs."""
        def _mock_dispatcher(reason: str, config: Optional[AppConfig] = None) -> AlertResult:
            logger.info("[SOAK MOCK ALERT] Alert triggered: %s", reason)
            # Push into bounded alert queue to exercise queue mechanics and depth tracking
            self.alert_queue.push(reason, priority=1)
            # Consume from queue to maintain realistic steady-state processing
            self.alert_queue.pop(timeout=0.01)
            return AlertResult(
                success=True,
                reason=reason,
                camera_success=False,
                location_success=False,
                telegram_success=True,
                details={"mock_soak_dispatch": True},
            )
        return _mock_dispatcher

    def _create_isolated_config(self) -> AppConfig:
        """Construct an isolated AppConfig instance that operates safely."""
        return AppConfig(
            env_file_path=self.work_dir / ".env",
            telegram_alert_enabled=False,
            camera_alert_enabled=False,
            location_alert_enabled=False,
            voice_warning_enabled=False,
            single_instance_enabled=False,
            auto_restart_enabled=True,
            max_restart_attempts=3,
            restart_backoff_seconds=0.1,
            auth_failure_threshold=3,
            auth_failure_window_seconds=10.0,
            auth_alert_cooldown_seconds=5.0,
        )

    def _record_checkpoint(self, elapsed: float, status: str, detection_mgr: Optional[DetectionManager] = None) -> SoakCheckpoint:
        """Record and persist an operational diagnostic checkpoint."""
        current_rss = get_current_rss_bytes()
        if current_rss > self._peak_rss:
            self._peak_rss = current_rss

        current_threads = get_current_thread_count()
        if current_threads > self._peak_threads:
            self._peak_threads = current_threads

        tracker = get_reliability_metrics()
        metrics_snap = tracker.snapshot()

        events_processed = (
            detection_mgr.total_events_processed
            if detection_mgr is not None
            else metrics_snap.events_processed
        )

        cp = SoakCheckpoint(
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=round(elapsed, 2),
            mode=self.mode,
            target_duration_seconds=self.duration_seconds,
            rss_bytes=current_rss,
            rss_mb=round(current_rss / (1024 * 1024), 2),
            peak_rss_mb=round(self._peak_rss / (1024 * 1024), 2),
            thread_count=current_threads,
            peak_thread_count=self._peak_threads,
            events_injected=self._events_injected,
            events_processed=events_processed,
            alerts_triggered=metrics_snap.alerts_delivered,
            alerts_suppressed_cooldown=metrics_snap.alerts_suppressed_cooldown,
            alerts_suppressed_filter=metrics_snap.alerts_suppressed_filter,
            queue_high_watermark=metrics_snap.queue_high_watermark,
            retry_count=metrics_snap.retry_count,
            error_count=metrics_snap.unexpected_exceptions,
            status=status,
        )
        self._checkpoints.append(cp)

        # Append to JSONL log
        try:
            with open(self.checkpoints_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(cp)) + "\n")
        except Exception as exc:
            logger.debug("Failed to write soak checkpoint: %s", exc)

        return cp

    def _evaluate_acceptance(
        self,
        final_rss_bytes: int,
        final_threads: int,
        metrics_snap: ReliabilityMetrics,
    ) -> tuple[str, bool, list[ThresholdEvaluation]]:
        """Evaluate operational metrics against defined SoakAcceptanceCriteria."""
        evals: list[ThresholdEvaluation] = []
        all_passed = True

        init_mb = self._initial_rss / (1024 * 1024)
        final_mb = final_rss_bytes / (1024 * 1024)
        growth_mb = final_mb - init_mb
        growth_ratio = final_mb / max(0.1, init_mb)

        # 1. Absolute RSS Growth
        rss_passed = growth_mb <= self.criteria.max_rss_growth_mb
        if not rss_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="RSS Memory Growth (MB)",
                target=f"<= {self.criteria.max_rss_growth_mb:.1f} MB",
                actual=f"{growth_mb:+.2f} MB ({init_mb:.1f} -> {final_mb:.1f} MB)",
                passed=rss_passed,
                details=f"Peak: {self._peak_rss / (1024 * 1024):.1f} MB",
            )
        )

        # 2. Relative RSS Growth Ratio
        ratio_passed = growth_ratio <= self.criteria.max_rss_growth_ratio
        if not ratio_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="RSS Growth Ratio",
                target=f"<= {self.criteria.max_rss_growth_ratio:.1f}x",
                actual=f"{growth_ratio:.2f}x",
                passed=ratio_passed,
                details=f"Initial: {init_mb:.1f} MB, Final: {final_mb:.1f} MB",
            )
        )

        # 3. Permanent Thread Growth
        thread_growth = final_threads - self._initial_threads
        thread_passed = thread_growth <= self.criteria.max_thread_growth
        if not thread_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Permanent Thread Growth",
                target=f"<= +{self.criteria.max_thread_growth}",
                actual=f"{thread_growth:+d} ({self._initial_threads} -> {final_threads})",
                passed=thread_passed,
                details=f"Peak active threads: {self._peak_threads}",
            )
        )

        # 4. Unexpected Exceptions
        exc_count = metrics_snap.unexpected_exceptions
        exc_passed = exc_count <= self.criteria.max_unexpected_exceptions
        if not exc_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Unexpected Exceptions",
                target=f"<= {self.criteria.max_unexpected_exceptions}",
                actual=exc_count,
                passed=exc_passed,
                details="Unhandled worker exceptions",
            )
        )

        # 5. Retry Count
        retry_count = metrics_snap.retry_count
        retry_passed = retry_count <= self.criteria.max_retry_count
        if not retry_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Retry Count",
                target=f"<= {self.criteria.max_retry_count}",
                actual=retry_count,
                passed=retry_passed,
                details="Transient network / persistence retries",
            )
        )

        # 6. Queue High Watermark
        q_hwm = metrics_snap.queue_high_watermark
        q_passed = q_hwm <= self.criteria.max_queue_high_watermark
        if not q_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Queue High Watermark",
                target=f"<= {self.criteria.max_queue_high_watermark}",
                actual=q_hwm,
                passed=q_passed,
                details=f"Queue drops: {metrics_snap.queue_dropped_count}",
            )
        )

        # 7. Persistence Failures
        persist_count = metrics_snap.persistence_failures
        persist_passed = persist_count <= self.criteria.max_persistence_failures
        if not persist_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Persistence Failures",
                target=f"<= {self.criteria.max_persistence_failures}",
                actual=persist_count,
                passed=persist_passed,
                details=f"Recoveries: {metrics_snap.persistence_recoveries}",
            )
        )

        # 8. Unrecovered Sensor Failures
        unrecovered = max(0, metrics_snap.sensor_failures - metrics_snap.sensor_recoveries)
        sensor_passed = unrecovered <= self.criteria.max_unrecovered_sensor_failures
        if not sensor_passed:
            all_passed = False
        evals.append(
            ThresholdEvaluation(
                name="Unrecovered Sensor Failures",
                target=f"<= {self.criteria.max_unrecovered_sensor_failures}",
                actual=unrecovered,
                passed=sensor_passed,
                details=f"Sensor failures: {metrics_snap.sensor_failures}, recoveries: {metrics_snap.sensor_recoveries}",
            )
        )

        verdict = "PASSED" if all_passed else "FAILED"
        return verdict, all_passed, evals

    def run(self) -> SoakResult:
        """Execute the soak test run up to duration_seconds or until stopped.

        Returns:
            SoakResult with comprehensive metrics, acceptance checks, and outcome.
        """
        self._setup_signal_handlers()
        reset_reliability_metrics()

        logger.info(
            "=== STARTING DEVICE GUARDIAN SOAK TEST (Mode: %s, Duration: %.1fs) ===",
            self.mode.upper(),
            self.duration_seconds,
        )
        logger.info("Soak workspace directory: %s", self.work_dir)

        config = self._create_isolated_config()
        mock_dispatcher = self._create_mock_alert_dispatcher()

        soak_monitor = SoakSyntheticMonitor(self._stop_event)

        detection_mgr = DetectionManager(
            config=config,
            monitor=soak_monitor,
            alert_dispatcher=mock_dispatcher,
        )

        lock = SingleInstanceLock(lock_file_path=self.lock_file)
        runtime = GuardianRuntime(
            config=config,
            detection_manager=detection_mgr,
            single_instance_lock=lock,
            status_file_path=self.status_file,
            poll_interval=0.5,
        )

        started = runtime.start(blocking=False)
        if not started:
            logger.error("Failed to start runtime controller for soak test.")
            fail_evals = [
                ThresholdEvaluation(
                    name="Runtime Initialization",
                    target="STARTED",
                    actual="FAILED",
                    passed=False,
                    details="Could not start GuardianRuntime",
                )
            ]
            return SoakResult(
                mode=self.mode,
                status="FAILED",
                acceptance_verdict="FAILED",
                success=False,
                duration_seconds=0.0,
                target_duration_seconds=self.duration_seconds,
                checkpoints_count=0,
                initial_rss_mb=round(self._initial_rss / (1024 * 1024), 2),
                final_rss_mb=round(get_current_rss_bytes() / (1024 * 1024), 2),
                peak_rss_mb=round(self._peak_rss / (1024 * 1024), 2),
                rss_growth_mb=0.0,
                rss_growth_ratio=1.0,
                memory_accepted=False,
                initial_thread_count=self._initial_threads,
                final_thread_count=get_current_thread_count(),
                peak_thread_count=self._peak_threads,
                thread_growth=0,
                threads_accepted=True,
                total_events_injected=0,
                total_events_processed=0,
                total_alerts_triggered=0,
                total_alerts_suppressed=0,
                queue_high_watermark=0,
                queue_dropped_count=0,
                queue_accepted=True,
                total_retries=0,
                total_unexpected_exceptions=1,
                total_sensor_failures=0,
                total_sensor_recoveries=0,
                total_persistence_failures=0,
                errors_accepted=False,
                criteria=self.criteria.to_dict(),
                evaluations=[e.to_dict() for e in fail_evals],
                output_directory=str(self.work_dir),
                summary_message="Failed to start runtime controller.",
            )

        start_time = time.time()
        last_checkpoint_time = start_time
        last_event_time = start_time
        self._status = "RUNNING"

        # Record initial baseline checkpoint
        self._record_checkpoint(0.0, "STARTING", detection_mgr)

        try:
            while not self._stop_event.is_set():
                now = time.time()
                elapsed = now - start_time

                if elapsed >= self.duration_seconds:
                    logger.info("Soak duration (%.1fs) successfully completed.", self.duration_seconds)
                    self._status = "COMPLETED"
                    break

                # Periodic synthetic event injection into the real detection pipeline
                if (now - last_event_time) >= self.event_interval:
                    self._events_injected += 1
                    event = AuthenticationFailureEvent(
                        timestamp=datetime.now(),
                        platform="soak_test",
                        source="SoakSyntheticMonitor",
                        username=f"user_{self._events_injected % 3}",
                        remote_address="127.0.0.1",
                        authentication_type="soak",
                        details={"soak_run": True, "seq": self._events_injected},
                    )
                    soak_monitor.enqueue(event)
                    last_event_time = now

                # Periodic diagnostic checkpoint
                if (now - last_checkpoint_time) >= self.checkpoint_interval:
                    self._record_checkpoint(elapsed, "RUNNING", detection_mgr)
                    last_checkpoint_time = now

                # Responsive wait
                self._stop_event.wait(timeout=0.2)

        except KeyboardInterrupt:
            logger.info("Soak test interrupted via keyboard.")
            self._interrupted = True
            self._status = "INTERRUPTED"
        except Exception as exc:
            logger.error("Unhandled exception during soak execution: %s", exc)
            self._status = "FAILED"
        finally:
            end_time = time.time()
            total_elapsed = end_time - start_time
            if self._interrupted and self._status != "FAILED":
                self._status = "INTERRUPTED"

            # Clean shutdown of runtime controller
            runtime.stop(timeout=5.0)
            self.alert_queue.close()

            # Record final checkpoint
            final_cp = self._record_checkpoint(total_elapsed, self._status, detection_mgr)

            # Sample post-shutdown resources for leak evaluation
            final_threads = get_current_thread_count()
            final_rss = final_cp.rss_bytes
            metrics_snap = get_reliability_metrics().snapshot()

            init_mb = round(self._initial_rss / (1024 * 1024), 2)
            final_mb = round(final_rss / (1024 * 1024), 2)
            peak_mb = round(self._peak_rss / (1024 * 1024), 2)
            growth_mb = round(final_mb - init_mb, 2)
            growth_ratio = round(final_mb / max(0.1, init_mb), 2)
            thread_growth = final_threads - self._initial_threads

            # Evaluate against defined acceptance criteria
            if self._status == "COMPLETED":
                verdict, accepted, evaluations = self._evaluate_acceptance(
                    final_rss_bytes=final_rss,
                    final_threads=final_threads,
                    metrics_snap=metrics_snap,
                )
                success = accepted
            elif self._status == "INTERRUPTED":
                verdict = "NOT_EVALUATED"
                success = False
                evaluations = [
                    ThresholdEvaluation(
                        name="Execution Completion",
                        target="COMPLETED",
                        actual="INTERRUPTED",
                        passed=False,
                        details="Soak was interrupted prior to target duration",
                    )
                ]
            else:
                verdict = "FAILED"
                success = False
                evaluations = [
                    ThresholdEvaluation(
                        name="Execution Completion",
                        target="COMPLETED",
                        actual=self._status,
                        passed=False,
                        details="Runtime or worker failed during execution",
                    )
                ]

            memory_accepted = (
                growth_mb <= self.criteria.max_rss_growth_mb
                and growth_ratio <= self.criteria.max_rss_growth_ratio
            )
            threads_accepted = thread_growth <= self.criteria.max_thread_growth
            queue_accepted = metrics_snap.queue_high_watermark <= self.criteria.max_queue_high_watermark
            errors_accepted = metrics_snap.unexpected_exceptions <= self.criteria.max_unexpected_exceptions

            events_processed = detection_mgr.total_events_processed

            if success:
                summary_msg = (
                    f"Soak test ({self.mode}) COMPLETED and PASSED acceptance criteria in {total_elapsed:.1f}s. "
                    f"Events: {self._events_injected} injected, {events_processed} processed; "
                    f"Alerts: {metrics_snap.alerts_delivered} delivered, "
                    f"{metrics_snap.alerts_suppressed_cooldown + metrics_snap.alerts_suppressed_filter} suppressed. "
                    f"Memory: {init_mb}MB -> {final_mb}MB (Growth: {growth_mb:+.2f}MB, Peak: {peak_mb}MB). "
                    f"Threads: {self._initial_threads} -> {final_threads} (Growth: {thread_growth:+d})."
                )
            else:
                failed_crit = [e.name for e in evaluations if not e.passed]
                summary_msg = (
                    f"Soak test ({self.mode}) {self._status} — Acceptance {verdict}. "
                    f"Breached criteria: {', '.join(failed_crit) if failed_crit else self._status}. "
                    f"Duration: {total_elapsed:.1f}s/{self.duration_seconds:.1f}s. "
                    f"Events: {self._events_injected} injected, {events_processed} processed."
                )

            summary = SoakResult(
                mode=self.mode,
                status=self._status,
                acceptance_verdict=verdict,
                success=success,
                duration_seconds=round(total_elapsed, 2),
                target_duration_seconds=self.duration_seconds,
                checkpoints_count=len(self._checkpoints),
                initial_rss_mb=init_mb,
                final_rss_mb=final_mb,
                peak_rss_mb=peak_mb,
                rss_growth_mb=growth_mb,
                rss_growth_ratio=growth_ratio,
                memory_accepted=memory_accepted,
                initial_thread_count=self._initial_threads,
                final_thread_count=final_threads,
                peak_thread_count=self._peak_threads,
                thread_growth=thread_growth,
                threads_accepted=threads_accepted,
                total_events_injected=self._events_injected,
                total_events_processed=events_processed,
                total_alerts_triggered=metrics_snap.alerts_delivered,
                total_alerts_suppressed=metrics_snap.alerts_suppressed_cooldown + metrics_snap.alerts_suppressed_filter,
                queue_high_watermark=metrics_snap.queue_high_watermark,
                queue_dropped_count=metrics_snap.queue_dropped_count,
                queue_accepted=queue_accepted,
                total_retries=metrics_snap.retry_count,
                total_unexpected_exceptions=metrics_snap.unexpected_exceptions,
                total_sensor_failures=metrics_snap.sensor_failures,
                total_sensor_recoveries=metrics_snap.sensor_recoveries,
                total_persistence_failures=metrics_snap.persistence_failures,
                errors_accepted=errors_accepted,
                criteria=self.criteria.to_dict(),
                evaluations=[e.to_dict() for e in evaluations],
                output_directory=str(self.work_dir),
                summary_message=summary_msg,
            )

            # Persist summary JSON
            try:
                self.summary_file.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
            except Exception as exc:
                logger.debug("Failed to write soak summary JSON: %s", exc)

            logger.info("=== SOAK TEST VERDICT: %s (Execution: %s) ===", verdict, self._status)
            logger.info("%s", summary.summary_message)

            if self.cleanup_on_exit and self._owns_work_dir and self.work_dir.exists():
                try:
                    shutil.rmtree(self.work_dir)
                except Exception:
                    pass

            return summary


def main() -> int:
    """CLI entry point for running standalone soak tests."""
    parser = argparse.ArgumentParser(
        prog="device-guardian-soak",
        description="Device Guardian Continuous Soak & Reliability Test Runner (Phase 14)",
    )
    parser.add_argument(
        "--mode",
        choices=["smoke", "short", "extended", "production"],
        default="smoke",
        help="Soak execution mode (smoke=30s, short=5m, extended=30m, production=24h)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Explicit duration override in seconds",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=float,
        default=5.0,
        help="Seconds between metric checkpoints (default: 5.0)",
    )
    parser.add_argument(
        "--event-interval",
        type=float,
        default=2.0,
        help="Seconds between synthetic event injections (default: 2.0)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save soak checkpoints and summary JSON",
    )
    parser.add_argument(
        "--max-rss-growth-mb",
        type=float,
        default=80.0,
        help="Maximum allowed RSS memory growth in MB (default: 80.0)",
    )
    parser.add_argument(
        "--max-thread-growth",
        type=int,
        default=1,
        help="Maximum allowed permanent thread growth (default: 1)",
    )
    parser.add_argument(
        "--max-exceptions",
        type=int,
        default=0,
        help="Maximum allowed unexpected exceptions (default: 0)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=10,
        help="Maximum allowed retries (default: 10)",
    )
    args = parser.parse_args()

    setup_logging(log_level="INFO")

    criteria = SoakAcceptanceCriteria(
        max_rss_growth_mb=args.max_rss_growth_mb,
        max_thread_growth=args.max_thread_growth,
        max_unexpected_exceptions=args.max_exceptions,
        max_retry_count=args.max_retries,
    )

    runner = SoakTestRunner(
        mode=args.mode,
        duration_seconds=args.duration,
        checkpoint_interval=args.checkpoint_interval,
        event_interval=args.event_interval,
        criteria=criteria,
        output_dir=args.output_dir,
    )

    result = runner.run()
    print("\n" + "=" * 65)
    print("         DEVICE GUARDIAN SOAK EXECUTION SUMMARY")
    print("=" * 65)
    print(f"Mode                 : {result.mode}")
    print(f"Execution Status     : {result.status}")
    print(f"Acceptance Verdict   : {result.acceptance_verdict}")
    print(f"Reliability Passed   : {'YES' if result.success else 'NO'}")
    print(f"Duration             : {result.duration_seconds}s (Target: {result.target_duration_seconds}s)")
    print(f"Checkpoints          : {result.checkpoints_count}")
    print("-" * 65)
    print(f"RSS Memory           : {result.initial_rss_mb} MB -> {result.final_rss_mb} MB (Growth: {result.rss_growth_mb:+.2f} MB, Peak: {result.peak_rss_mb} MB)")
    print(f"Thread Count         : {result.initial_thread_count} -> {result.final_thread_count} (Growth: {result.thread_growth:+d}, Peak: {result.peak_thread_count})")
    print(f"Events Injected      : {result.total_events_injected}")
    print(f"Events Processed     : {result.total_events_processed}")
    print(f"Alerts Triggered     : {result.total_alerts_triggered}")
    print(f"Alerts Suppressed    : {result.total_alerts_suppressed}")
    print(f"Queue High Watermark : {result.queue_high_watermark}")
    print(f"Retries Recorded     : {result.total_retries}")
    print(f"Unexpected Errors    : {result.total_unexpected_exceptions}")
    print("-" * 65)
    print("CRITERIA EVALUATIONS:")
    for ev in result.evaluations:
        status_tag = "[PASS]" if ev["passed"] else "[FAIL]"
        print(f"  {status_tag:<8} {ev['name']:<28} Target: {str(ev['target']):<12} Actual: {str(ev['actual'])}")
    print("-" * 65)
    print(f"Output Directory     : {result.output_directory}")
    print("=" * 65)

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
