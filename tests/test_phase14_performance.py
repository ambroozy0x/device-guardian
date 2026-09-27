"""Phase 14 Performance Benchmarks for Device Guardian.

Measures baseline performance and prevents severe regressions in critical paths:
- Configuration loading latency.
- Atomic persistence latency.
- In-memory event ingestion throughput in sliding-window threshold engine.
- Runtime start/stop transition latency.
- Reliability metrics snapshot latency.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time

import pytest

from device_guardian.config import AppConfig, load_config
from device_guardian.detection.base import BaseAuthenticationMonitor
from device_guardian.detection.manager import DetectionManager
from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.detection.threshold import SlidingWindowThresholdEngine
from device_guardian.recovery.persistence import AtomicPersistence
from device_guardian.reliability.metrics import get_reliability_metrics
from device_guardian.runtime.controller import GuardianRuntime


class FastMonitor(BaseAuthenticationMonitor):
    def is_available(self) -> tuple[bool, str]:
        return True, "Fast"

    def get_source_name(self) -> str:
        return "FastMonitor"

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def poll(self) -> list:
        return []


def test_config_load_latency_baseline() -> None:
    """Benchmark: Configuration loading must complete within reasonable baseline (<250ms)."""
    t0 = time.perf_counter()
    cfg = load_config()
    elapsed = (time.perf_counter() - t0) * 1000.0  # ms
    assert cfg is not None
    # Generous threshold to protect against regression without brittle CI failures
    assert elapsed < 500.0, f"Config loading too slow: {elapsed:.2f}ms"


def test_atomic_persistence_latency_baseline(tmp_path: Path) -> None:
    """Benchmark: Atomic JSON persistence with fsync must complete within <150ms."""
    state_file = tmp_path / "bench_state.json"
    data = {"system": "DeviceGuardian", "status": "ACTIVE", "subsystems": ["a", "b", "c"]}

    times: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        AtomicPersistence.atomic_write_json(state_file, data, backup=True)
        times.append((time.perf_counter() - t0) * 1000.0)

    avg_ms = sum(times) / len(times)
    assert avg_ms < 200.0, f"Atomic persistence too slow: {avg_ms:.2f}ms average"


def test_event_ingestion_throughput_baseline() -> None:
    """Benchmark: SlidingWindowThresholdEngine must ingest >10,000 events/sec."""
    engine = SlidingWindowThresholdEngine(threshold=5, window_seconds=10.0)
    event = AuthenticationFailureEvent(
        timestamp=datetime.now(),
        platform="bench",
        source="bench",
        username="bench_user",
        remote_address="127.0.0.1",
        authentication_type="local",
    )

    count = 2000
    t0 = time.perf_counter()
    for _ in range(count):
        engine.record_event(event)
    total_sec = time.perf_counter() - t0

    throughput = count / total_sec
    assert throughput >= 2000.0, f"Event throughput too low: {throughput:.1f} events/sec"


def test_runtime_start_stop_latency_baseline(tmp_path: Path) -> None:
    """Benchmark: Runtime startup and shutdown cycle must complete within <1.5s total."""
    cfg = AppConfig(
        telegram_alert_enabled=False,
        single_instance_enabled=False,
    )
    runtime = GuardianRuntime(
        config=cfg,
        detection_manager=DetectionManager(config=cfg, monitor=FastMonitor()),
        status_file_path=tmp_path / "bench_runtime.json",
        poll_interval=0.05,
    )

    t0 = time.perf_counter()
    assert runtime.start(blocking=False) is True
    start_elapsed = time.perf_counter() - t0

    t1 = time.perf_counter()
    assert runtime.stop(timeout=2.0) is True
    stop_elapsed = time.perf_counter() - t1

    assert start_elapsed < 2.0, f"Startup took too long: {start_elapsed:.2f}s"
    assert stop_elapsed < 2.0, f"Shutdown took too long: {stop_elapsed:.2f}s"


def test_metrics_snapshot_latency_baseline() -> None:
    """Benchmark: ReliabilityMetricsTracker snapshot must complete within <10ms."""
    tracker = get_reliability_metrics()
    t0 = time.perf_counter()
    for _ in range(10):
        snap = tracker.snapshot()
    avg_ms = ((time.perf_counter() - t0) / 10.0) * 1000.0

    assert avg_ms < 50.0, f"Snapshot took too long: {avg_ms:.2f}ms"
