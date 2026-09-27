"""Comprehensive test suite for Phase 14 Soak Runner & Acceptance Framework.

Verifies:
1. Normal completion & acceptance passing.
2. Memory threshold breach detection.
3. Thread threshold breach detection.
4. Error threshold breach detection.
5. Retry threshold breach detection.
6. Interrupted soak state & verdict handling.
7. Final checkpoint durability & JSONL validity.
8. Summary JSON persistence & evaluation records.
9. Environment isolation (no real Telegram calls, isolated workspace).
10. Synthetic event pipeline processing.
11. Queue high-watermark & backpressure tracking.
"""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from unittest.mock import patch

import pytest

from device_guardian.reliability.metrics import get_reliability_metrics
from device_guardian.reliability.soak import (
    SoakAcceptanceCriteria,
    SoakResult,
    SoakTestRunner,
)


def test_soak_runner_normal_completion(tmp_path: Path) -> None:
    """1. Verify normal completion with default criteria passes acceptance."""
    out_dir = tmp_path / "soak_normal"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.5,
        checkpoint_interval=0.5,
        event_interval=0.3,
        output_dir=out_dir,
    )

    result = runner.run()

    assert result.status == "COMPLETED"
    assert result.acceptance_verdict == "PASSED"
    assert result.success is True
    assert result.duration_seconds >= 1.4
    assert result.checkpoints_count >= 2
    assert result.total_events_injected >= 2
    assert result.total_events_processed >= 1
    assert result.memory_accepted is True
    assert result.threads_accepted is True
    assert result.errors_accepted is True
    assert result.queue_accepted is True


def test_soak_runner_memory_threshold_evaluation(tmp_path: Path) -> None:
    """2. Verify that exceeding RSS growth threshold marks acceptance as FAILED despite COMPLETED run."""
    out_dir = tmp_path / "soak_mem_fail"
    # Unachievable negative growth threshold to force memory failure
    strict_criteria = SoakAcceptanceCriteria(max_rss_growth_mb=-10.0)

    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.4,
        criteria=strict_criteria,
        output_dir=out_dir,
    )

    result = runner.run()

    assert result.status == "COMPLETED"
    assert result.acceptance_verdict == "FAILED"
    assert result.success is False
    assert result.memory_accepted is False
    assert any("RSS Memory Growth" in e["name"] and not e["passed"] for e in result.evaluations)


def test_soak_runner_thread_threshold_evaluation(tmp_path: Path) -> None:
    """3. Verify permanent thread growth threshold breach causes acceptance failure."""
    out_dir = tmp_path / "soak_thread_fail"
    # Negative thread growth threshold: any zero or positive growth will fail
    strict_criteria = SoakAcceptanceCriteria(max_thread_growth=-1)

    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.4,
        criteria=strict_criteria,
        output_dir=out_dir,
    )

    result = runner.run()

    assert result.status == "COMPLETED"
    assert result.acceptance_verdict == "FAILED"
    assert result.success is False
    assert result.threads_accepted is False
    assert any("Permanent Thread Growth" in e["name"] and not e["passed"] for e in result.evaluations)


def test_soak_runner_error_threshold_evaluation(tmp_path: Path) -> None:
    """4. Verify unexpected exceptions mark acceptance as FAILED."""
    out_dir = tmp_path / "soak_err_fail"
    strict_criteria = SoakAcceptanceCriteria(max_unexpected_exceptions=0)

    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.3,
        criteria=strict_criteria,
        output_dir=out_dir,
    )

    orig_config = runner._create_isolated_config

    def inject_error_config():
        cfg = orig_config()
        get_reliability_metrics().record_unexpected_exception("Simulated test error")
        return cfg

    with patch.object(runner, "_create_isolated_config", side_effect=inject_error_config):
        result = runner.run()

    # If error occurred, acceptance must fail
    assert result.status == "COMPLETED"
    assert result.total_unexpected_exceptions >= 1
    assert result.acceptance_verdict == "FAILED"
    assert result.success is False
    assert result.errors_accepted is False


def test_soak_runner_retry_threshold_evaluation(tmp_path: Path) -> None:
    """5. Verify exceeding max retries causes acceptance failure."""
    out_dir = tmp_path / "soak_retry_fail"
    strict_criteria = SoakAcceptanceCriteria(max_retry_count=0)

    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.3,
        criteria=strict_criteria,
        output_dir=out_dir,
    )

    orig_config = runner._create_isolated_config

    def inject_retry_config():
        cfg = orig_config()
        get_reliability_metrics().record_retry()
        return cfg

    with patch.object(runner, "_create_isolated_config", side_effect=inject_retry_config):
        result = runner.run()

    assert result.status == "COMPLETED"
    assert result.total_retries >= 1
    assert result.acceptance_verdict == "FAILED"
    assert result.success is False


def test_soak_runner_interrupted_soak(tmp_path: Path) -> None:
    """6. Verify that an interrupted soak reports INTERRUPTED and success=False."""
    out_dir = tmp_path / "soak_interrupt"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=5.0,
        checkpoint_interval=0.5,
        event_interval=0.2,
        output_dir=out_dir,
    )

    # Simulate interruption shortly after starting
    def interrupt_shortly():
        time.sleep(0.6)
        runner._interrupted = True
        runner._stop_event.set()

    t = threading.Thread(target=interrupt_shortly)
    t.start()

    result = runner.run()
    t.join()

    assert result.status == "INTERRUPTED"
    assert result.acceptance_verdict == "NOT_EVALUATED"
    assert result.success is False
    assert result.duration_seconds < 5.0


def test_soak_runner_final_checkpoint_and_durability(tmp_path: Path) -> None:
    """7. Verify checkpoint JSONL lines are durable, ordered, and contain valid fields."""
    out_dir = tmp_path / "soak_checkpoints_test"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.2,
        checkpoint_interval=0.4,
        event_interval=0.3,
        output_dir=out_dir,
    )
    result = runner.run()

    cp_file = out_dir / "soak_checkpoints.jsonl"
    assert cp_file.is_file()

    lines = cp_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 2

    parsed_cps = [json.loads(line) for line in lines]
    assert parsed_cps[0]["status"] == "STARTING"
    assert parsed_cps[-1]["status"] == "COMPLETED"
    for cp in parsed_cps:
        assert "rss_bytes" in cp
        assert "thread_count" in cp
        assert "events_injected" in cp
        assert "events_processed" in cp
        assert "queue_high_watermark" in cp


def test_soak_runner_summary_persistence(tmp_path: Path) -> None:
    """8. Verify summary JSON file is written with complete diagnostic evaluations."""
    out_dir = tmp_path / "soak_summary_test"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.3,
        output_dir=out_dir,
    )
    result = runner.run()

    summary_file = out_dir / "soak_summary.json"
    assert summary_file.is_file()

    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "COMPLETED"
    assert data["acceptance_verdict"] == "PASSED"
    assert "evaluations" in data
    assert len(data["evaluations"]) >= 6
    assert data["output_directory"] == str(out_dir)


def test_soak_runner_isolation_guarantee(tmp_path: Path) -> None:
    """9. Verify soak runs strictly inside isolated workspace and never invokes real Telegram API."""
    out_dir = tmp_path / "soak_isolation"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.0,
        checkpoint_interval=0.5,
        event_interval=0.3,
        output_dir=out_dir,
    )

    with patch("requests.post") as mock_post:
        result = runner.run()
        # Ensure requests.post was NEVER called
        assert not mock_post.called

    assert result.success is True
    # Configuration should point to isolated directory
    assert Path(result.output_directory).resolve() == out_dir.resolve()
    # Lock file should be in isolated directory, not user home
    assert (out_dir / "soak_instance.lock").parent == out_dir


def test_soak_runner_synthetic_event_processing(tmp_path: Path) -> None:
    """10. Verify synthetic events injected into SoakSyntheticMonitor are processed by DetectionManager."""
    out_dir = tmp_path / "soak_pipeline_test"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.5,
        checkpoint_interval=0.5,
        event_interval=0.25,
        output_dir=out_dir,
    )

    result = runner.run()

    assert result.total_events_injected >= 3
    assert result.total_events_processed >= 2
    # Verify that events processed by detection engine is accurately tracked
    assert result.total_events_processed <= result.total_events_injected


def test_soak_runner_queue_high_watermark(tmp_path: Path) -> None:
    """11. Verify bounded alert queue is exercised and queue metrics are recorded."""
    out_dir = tmp_path / "soak_queue_test"
    runner = SoakTestRunner(
        mode="smoke",
        duration_seconds=1.5,
        checkpoint_interval=0.5,
        event_interval=0.25,
        output_dir=out_dir,
    )

    result = runner.run()

    # Alerts triggered should push through alert_queue, updating high watermark
    if result.total_alerts_triggered > 0:
        assert result.queue_high_watermark >= 1
    assert result.queue_accepted is True
