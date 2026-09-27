"""Operational reliability metrics tracking for Device Guardian (Phase 14).

Maintains bounded, in-memory counters and gauges for operational reliability,
resource consumption, error rates, and lifecycle events.
Never transmits telemetry; strictly for local diagnostics and soak monitoring.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import os
import sys
import threading
import time
from typing import Any, Optional


def get_current_rss_bytes() -> int:
    """Retrieve current Resident Set Size (RSS) memory in bytes across OS platforms."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            psapi = getattr(ctypes.windll, "psapi", None) or ctypes.windll.kernel32
            fn = getattr(psapi, "GetProcessMemoryInfo", None)
            if fn:
                fn.argtypes = [
                    wintypes.HANDLE,
                    ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                    wintypes.DWORD,
                ]
                fn.restype = wintypes.BOOL
                if fn(handle, ctypes.byref(pmc), pmc.cb):
                    return int(pmc.WorkingSetSize)
        elif sys.platform.startswith("linux"):
            statm_path = "/proc/self/statm"
            if os.path.exists(statm_path):
                with open(statm_path, "r", encoding="ascii") as f:
                    parts = f.read().split()
                    if len(parts) >= 2:
                        rss_pages = int(parts[1])
                        page_size = os.sysconf("SC_PAGE_SIZE")
                        return rss_pages * page_size
        elif sys.platform == "darwin":
            import resource

            # On macOS ru_maxrss is in bytes
            return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        pass
    return 0


def get_current_thread_count() -> int:
    """Retrieve the current active thread count of the Python process."""
    return threading.active_count()


@dataclass
class ReliabilityMetrics:
    """Snapshot of system reliability metrics."""

    uptime_seconds: float = 0.0
    start_time_iso: str = ""
    snapshot_time_iso: str = ""

    # Event metrics
    events_processed: int = 0
    synthetic_events_processed: int = 0

    # Alert metrics
    alerts_generated: int = 0
    alerts_delivered: int = 0
    alerts_failed: int = 0
    alerts_suppressed_cooldown: int = 0
    alerts_suppressed_filter: int = 0

    # Retries and queues
    retry_count: int = 0
    queue_depth: int = 0
    queue_high_watermark: int = 0
    queue_dropped_count: int = 0

    # Workers and threads
    worker_count: int = 0
    thread_count: int = 0
    peak_thread_count: int = 0

    # Memory (bytes)
    memory_baseline_bytes: int = 0
    memory_current_bytes: int = 0
    memory_high_watermark_bytes: int = 0

    # Subsystem errors / recoveries
    sensor_failures: int = 0
    sensor_recoveries: int = 0
    persistence_failures: int = 0
    persistence_recoveries: int = 0
    ipc_failures: int = 0
    unexpected_exceptions: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert snapshot to dictionary for JSON persistence or reporting."""
        d = asdict(self)
        # Add convenient human-readable MB conversions
        d["memory_current_mb"] = round(self.memory_current_bytes / (1024 * 1024), 2)
        d["memory_peak_mb"] = round(self.memory_high_watermark_bytes / (1024 * 1024), 2)
        d["memory_baseline_mb"] = round(self.memory_baseline_bytes / (1024 * 1024), 2)
        return d


class ReliabilityMetricsTracker:
    """Thread-safe operational reliability metrics tracker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time = time.time()
        self._start_time_iso = datetime.now(timezone.utc).isoformat()

        # Event metrics
        self._events_processed: int = 0
        self._synthetic_events_processed: int = 0

        # Alert metrics
        self._alerts_generated: int = 0
        self._alerts_delivered: int = 0
        self._alerts_failed: int = 0
        self._alerts_suppressed_cooldown: int = 0
        self._alerts_suppressed_filter: int = 0

        # Retries & queues
        self._retry_count: int = 0
        self._queue_depth: int = 0
        self._queue_high_watermark: int = 0
        self._queue_dropped_count: int = 0

        # Workers & threads
        self._worker_count: int = 0
        self._peak_thread_count: int = get_current_thread_count()

        # Memory tracking
        initial_rss = get_current_rss_bytes()
        self._memory_baseline_bytes: int = initial_rss
        self._memory_current_bytes: int = initial_rss
        self._memory_high_watermark_bytes: int = initial_rss

        # Failures & recoveries
        self._sensor_failures: int = 0
        self._sensor_recoveries: int = 0
        self._persistence_failures: int = 0
        self._persistence_recoveries: int = 0
        self._ipc_failures: int = 0
        self._unexpected_exceptions: int = 0

    def sample_system_resources(self) -> None:
        """Sample active process memory and thread counts."""
        rss = get_current_rss_bytes()
        threads = get_current_thread_count()
        with self._lock:
            if self._memory_baseline_bytes == 0 and rss > 0:
                self._memory_baseline_bytes = rss
            self._memory_current_bytes = rss
            if rss > self._memory_high_watermark_bytes:
                self._memory_high_watermark_bytes = rss
            if threads > self._peak_thread_count:
                self._peak_thread_count = threads

    def record_event(self, is_synthetic: bool = False) -> None:
        with self._lock:
            self._events_processed += 1
            if is_synthetic:
                self._synthetic_events_processed += 1

    def record_alert_generated(self) -> None:
        with self._lock:
            self._alerts_generated += 1

    def record_alert_delivered(self) -> None:
        with self._lock:
            self._alerts_delivered += 1

    def record_alert_failed(self) -> None:
        with self._lock:
            self._alerts_failed += 1

    def record_alert_suppressed_cooldown(self) -> None:
        with self._lock:
            self._alerts_suppressed_cooldown += 1

    def record_alert_suppressed_filter(self) -> None:
        with self._lock:
            self._alerts_suppressed_filter += 1

    def record_retry(self) -> None:
        with self._lock:
            self._retry_count += 1

    def update_queue_depth(self, depth: int) -> None:
        with self._lock:
            self._queue_depth = depth
            if depth > self._queue_high_watermark:
                self._queue_high_watermark = depth

    def record_queue_drop(self) -> None:
        with self._lock:
            self._queue_dropped_count += 1

    def set_worker_count(self, count: int) -> None:
        with self._lock:
            self._worker_count = count

    def record_sensor_failure(self, sensor_name: str = "") -> None:
        with self._lock:
            self._sensor_failures += 1

    def record_sensor_recovery(self, sensor_name: str = "") -> None:
        with self._lock:
            self._sensor_recoveries += 1

    def record_persistence_failure(self, target: str = "") -> None:
        with self._lock:
            self._persistence_failures += 1

    def record_persistence_recovery(self, target: str = "") -> None:
        with self._lock:
            self._persistence_recoveries += 1

    def record_ipc_failure(self) -> None:
        with self._lock:
            self._ipc_failures += 1

    def record_unexpected_exception(self, exc: Optional[Any] = None) -> None:
        with self._lock:
            self._unexpected_exceptions += 1

    def snapshot(self) -> ReliabilityMetrics:
        """Create a point-in-time immutable snapshot of all metrics."""
        self.sample_system_resources()
        now = time.time()
        with self._lock:
            return ReliabilityMetrics(
                uptime_seconds=round(now - self._start_time, 2),
                start_time_iso=self._start_time_iso,
                snapshot_time_iso=datetime.now(timezone.utc).isoformat(),
                events_processed=self._events_processed,
                synthetic_events_processed=self._synthetic_events_processed,
                alerts_generated=self._alerts_generated,
                alerts_delivered=self._alerts_delivered,
                alerts_failed=self._alerts_failed,
                alerts_suppressed_cooldown=self._alerts_suppressed_cooldown,
                alerts_suppressed_filter=self._alerts_suppressed_filter,
                retry_count=self._retry_count,
                queue_depth=self._queue_depth,
                queue_high_watermark=self._queue_high_watermark,
                queue_dropped_count=self._queue_dropped_count,
                worker_count=self._worker_count,
                thread_count=get_current_thread_count(),
                peak_thread_count=self._peak_thread_count,
                memory_baseline_bytes=self._memory_baseline_bytes,
                memory_current_bytes=self._memory_current_bytes,
                memory_high_watermark_bytes=self._memory_high_watermark_bytes,
                sensor_failures=self._sensor_failures,
                sensor_recoveries=self._sensor_recoveries,
                persistence_failures=self._persistence_failures,
                persistence_recoveries=self._persistence_recoveries,
                ipc_failures=self._ipc_failures,
                unexpected_exceptions=self._unexpected_exceptions,
            )

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        with self._lock:
            self._start_time = time.time()
            self._start_time_iso = datetime.now(timezone.utc).isoformat()
            self._events_processed = 0
            self._synthetic_events_processed = 0
            self._alerts_generated = 0
            self._alerts_delivered = 0
            self._alerts_failed = 0
            self._alerts_suppressed_cooldown = 0
            self._alerts_suppressed_filter = 0
            self._retry_count = 0
            self._queue_depth = 0
            self._queue_high_watermark = 0
            self._queue_dropped_count = 0
            self._worker_count = 0
            self._peak_thread_count = get_current_thread_count()
            initial_rss = get_current_rss_bytes()
            self._memory_baseline_bytes = initial_rss
            self._memory_current_bytes = initial_rss
            self._memory_high_watermark_bytes = initial_rss
            self._sensor_failures = 0
            self._sensor_recoveries = 0
            self._persistence_failures = 0
            self._persistence_recoveries = 0
            self._ipc_failures = 0
            self._unexpected_exceptions = 0


_GLOBAL_TRACKER: Optional[ReliabilityMetricsTracker] = None
_GLOBAL_TRACKER_LOCK = threading.Lock()


def get_reliability_metrics() -> ReliabilityMetricsTracker:
    """Get the process-wide reliability metrics tracker singleton."""
    global _GLOBAL_TRACKER
    if _GLOBAL_TRACKER is None:
        with _GLOBAL_TRACKER_LOCK:
            if _GLOBAL_TRACKER is None:
                _GLOBAL_TRACKER = ReliabilityMetricsTracker()
    return _GLOBAL_TRACKER


def reset_reliability_metrics() -> None:
    """Reset the global reliability metrics tracker (for testing isolation)."""
    global _GLOBAL_TRACKER
    with _GLOBAL_TRACKER_LOCK:
        if _GLOBAL_TRACKER is not None:
            _GLOBAL_TRACKER.reset()
        else:
            _GLOBAL_TRACKER = ReliabilityMetricsTracker()
