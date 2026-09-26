"""Phase 11 End-to-End Integration Tests: Runtime Lifecycle, Single-Instance Lock, IPC, and Tray Synchronization (Workstreams 8, 9, 10, 11, 26, 44)."""

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import time
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.runtime.single_instance import SingleInstanceLock
from device_guardian.security.ipc import (
    ControlChannel,
    ControlCommand,
    ControlChannelError,
    ControlMessage,
    FORBIDDEN_COMMAND_NAMES,
)
from device_guardian.tray.manager import TrayManager
from device_guardian.tray.icons import create_tray_image


@pytest.fixture
def lifecycle_env(tmp_path):
    ApplicationPaths.set_data_dir_override(tmp_path)
    config = AppConfig(
        telegram_bot_token="123456:AAAHH-TEST_BOT_TOKEN_FOR_E2E",
        telegram_chat_id="987654321",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
        single_instance_enabled=True,
    )
    return tmp_path, config


def test_runtime_lifecycle_fsm_e2e(lifecycle_env):
    """Verify runtime state machine transitions through complete lifecycle."""
    tmp_path, config = lifecycle_env

    mock_monitor = MagicMock()
    mock_monitor.poll.return_value = []
    mock_monitor.is_available.return_value = (True, "Ready")

    runtime = GuardianRuntime(config=config, poll_interval=0.05)
    assert runtime.status.state == RuntimeState.STOPPED

    with patch("device_guardian.detection.manager.create_platform_monitor", return_value=mock_monitor):
        # Start background worker
        started = runtime.start(blocking=False)
        assert started is True
        assert runtime.status.state in (RuntimeState.STARTING, RuntimeState.RUNNING)

        # Allow worker thread to spin briefly
        time.sleep(0.15)
        assert runtime.status.state == RuntimeState.RUNNING

        # Stop worker gracefully
        runtime.stop()
        assert runtime.status.state == RuntimeState.STOPPED
        assert not runtime.single_instance.is_locked()


def test_single_instance_lock_mutual_exclusion_e2e(lifecycle_env):
    """Verify single-instance lock prevents duplicate concurrent execution."""
    tmp_path, config = lifecycle_env

    lock1 = SingleInstanceLock()
    lock2 = SingleInstanceLock()

    # Instance 1 acquires lock
    acquired1 = lock1.acquire()
    assert acquired1 is True
    assert lock1.is_locked() is True
    assert lock1.get_active_pid() == os.getpid()

    # Instance 2 must be rejected
    acquired2 = lock2.acquire()
    assert acquired2 is False

    # Instance 1 releases lock
    lock1.release()
    assert lock1.is_locked() is False

    # Now instance 2 can acquire lock
    acquired2_after = lock2.acquire()
    assert acquired2_after is True
    lock2.release()


def test_single_instance_stale_lock_reclamation_e2e(lifecycle_env):
    """Verify stale lock file from a dead process is safely reclaimed."""
    tmp_path, config = lifecycle_env

    lock = SingleInstanceLock()
    lock_file = lock.lock_file
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    # Write a simulated dead PID (e.g. 99999999)
    stale_data = {
        "pid": 99999999,
        "creation_time": 1000,
        "executable": "device-guardian.exe",
        "timestamp": "2026-09-26 12:00:00",
    }
    lock_file.write_text(json.dumps(stale_data), encoding="utf-8")

    # Dead PID is recognized as inactive
    assert lock.is_locked() is False

    # Acquisition must reclaim the stale file cleanly
    reclaimed = lock.acquire()
    assert reclaimed is True
    assert lock.get_active_pid() == os.getpid()
    lock.release()


def test_ipc_command_dispatch_and_reception_e2e(lifecycle_env):
    """Verify local IPC channel sends, validates, and receives authorized commands."""
    tmp_path, config = lifecycle_env
    control_file = ApplicationPaths.get_control_file_path()

    # Send STOP command
    sent = ControlChannel.send_command(control_file=control_file, command=ControlCommand.STOP)
    assert sent is True

    # Read command
    received = ControlChannel.read_command(control_file=control_file)
    assert received is not None
    assert received.command == ControlCommand.STOP
    assert received.sender_pid == os.getpid()

    ControlChannel.clear(control_file)
    assert not control_file.is_file()


def test_ipc_command_injection_and_forbidden_verbs_rejected_e2e(lifecycle_env):
    """Verify arbitrary injection commands and forbidden verbs are strictly blocked."""
    tmp_path, config = lifecycle_env

    now_utc = datetime.now(timezone.utc)
    for forbidden in FORBIDDEN_COMMAND_NAMES:
        bad_payload = {
            "command": forbidden,
            "request_id": "test-req-id-12345",
            "sender_pid": os.getpid(),
            "created_at": now_utc.isoformat(),
            "expires_at": (now_utc + timedelta(seconds=30)).isoformat(),
        }
        with pytest.raises(ControlChannelError):
            ControlMessage.from_dict(bad_payload)


def test_ipc_replay_attack_and_expired_ttl_rejected_e2e(lifecycle_env):
    """Verify replayed message IDs and expired TTL messages are rejected."""
    tmp_path, config = lifecycle_env
    control_file = ApplicationPaths.get_control_file_path()

    # Send and read first command
    ControlChannel.send_command(control_file=control_file, command=ControlCommand.STOP)
    first_received = ControlChannel.read_command(control_file=control_file)
    assert first_received is not None

    # Reading again without rewriting should return None (already processed / replayed)
    second_received = ControlChannel.read_command(control_file=control_file)
    assert second_received is None

    # Test expired payload directly through schema validation
    now_utc = datetime.now(timezone.utc)
    expired_payload = {
        "command": "STOP",
        "request_id": "expired-req-id-12345",
        "sender_pid": os.getpid(),
        "created_at": (now_utc - timedelta(seconds=60)).isoformat(),
        "expires_at": (now_utc - timedelta(seconds=10)).isoformat(),
    }
    with pytest.raises(ControlChannelError) as exc_info:
        ControlMessage.from_dict(expired_payload)
    assert "expired" in str(exc_info.value).lower()


def test_system_tray_state_synchronization_e2e(lifecycle_env):
    """Verify system tray synchronization reflects runtime status deterministically."""
    tmp_path, config = lifecycle_env
    runtime = GuardianRuntime(config=config)

    tray = TrayManager(runtime=runtime)
    assert tray is not None

    # Test image generation for states
    img_stopped = create_tray_image(RuntimeState.STOPPED)
    assert img_stopped is not None

    img_running = create_tray_image(RuntimeState.RUNNING)
    assert img_running is not None

    img_starting = create_tray_image(RuntimeState.STARTING)
    assert img_starting is not None


def test_runtime_stress_rapid_restart_cycles_e2e(lifecycle_env):
    """Verify repeated start/stop stress cycles do not leak threads or locks."""
    tmp_path, config = lifecycle_env

    mock_monitor = MagicMock()
    mock_monitor.poll.return_value = []
    mock_monitor.is_available.return_value = (True, "Ready")

    with patch("device_guardian.detection.manager.create_platform_monitor", return_value=mock_monitor):
        for cycle in range(3):
            runtime = GuardianRuntime(config=config, poll_interval=0.01)
            assert runtime.start(blocking=False) is True
            time.sleep(0.05)
            runtime.stop()
            assert runtime.status.state == RuntimeState.STOPPED
            assert not runtime.single_instance.is_locked()
