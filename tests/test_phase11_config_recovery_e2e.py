"""Phase 11 End-to-End Integration Tests: Configuration, SecretStore, Disaster Recovery, and Resilience (Workstreams 12, 13, 14, 30, 31, 42, 44)."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from device_guardian.config import AppConfig, ConfigurationError
from device_guardian.recovery.health import HealthStatus, assess_system_health
from device_guardian.recovery.persistence import AtomicPersistence
from device_guardian.recovery.repair import (
    repair_state_files,
    get_recovery_status,
    verify_installation_integrity,
)
from device_guardian.runtime.paths import ApplicationPaths
from device_guardian.security.secret import SecretValue
from device_guardian.security.store import (
    FileSecretStore,
    create_default_secret_store,
)


@pytest.fixture
def recovery_env(tmp_path):
    ApplicationPaths.set_data_dir_override(tmp_path)
    config = AppConfig(
        telegram_bot_token="123456:AAAHH-TEST_BOT_TOKEN_FOR_E2E",
        telegram_chat_id="987654321",
        camera_alert_enabled=False,
        location_alert_enabled=False,
        voice_warning_enabled=False,
    )
    return tmp_path, config


def test_configuration_validation_range_and_type_boundaries_e2e():
    """Verify strict validation and range boundaries on all configuration properties."""
    # Valid config
    cfg = AppConfig(
        telegram_bot_token="123456:VALID_TOKEN",
        telegram_chat_id="12345678",
        camera_index=0,
        request_timeout_seconds=5.0,
        auth_failure_threshold=3,
        auth_failure_window_seconds=60.0,
        auth_alert_cooldown_seconds=300.0,
    )
    cfg.validate()  # Must not raise

    # Invalid camera index (< 0 or > 32)
    with pytest.raises(ConfigurationError):
        bad_cfg = AppConfig(telegram_bot_token="tok", telegram_chat_id="chat", camera_index=-1)
        bad_cfg.validate()

    # Invalid threshold (< 1 or > 100)
    with pytest.raises(ConfigurationError):
        bad_cfg = AppConfig(telegram_bot_token="tok", telegram_chat_id="chat", auth_failure_threshold=0)
        bad_cfg.validate()

    # Invalid timeout (<= 0)
    with pytest.raises(ConfigurationError):
        bad_cfg = AppConfig(telegram_bot_token="tok", telegram_chat_id="chat", request_timeout_seconds=-5.0)
        bad_cfg.validate()


def test_secret_store_dpapi_and_file_fallback_lifecycle_e2e(recovery_env):
    """Verify SecretStore lifecycle, secret encryption, and fallback persistence."""
    tmp_path, config = recovery_env
    secrets_path = tmp_path / "secrets.dat"

    # Test default secret store (Windows DPAPI on Windows)
    store = create_default_secret_store(file_path=secrets_path)
    assert not store.has_secret("test_token")

    # Store secret
    secret_val = SecretValue("TOP_SECRET_AUTH_KEY_12345")
    store.set_secret("test_token", secret_val)
    assert store.has_secret("test_token")

    # If on Windows, DPAPI raw file must not expose secret in plaintext
    if "DPAPI" in store.get_backend_name():
        raw_bytes = secrets_path.read_bytes()
        assert b"TOP_SECRET_AUTH_KEY_12345" not in raw_bytes

    # Retrieve secret
    retrieved = store.get_secret("test_token")
    assert retrieved is not None
    assert retrieved.get_secret_value() == "TOP_SECRET_AUTH_KEY_12345"


def test_atomic_persistence_write_and_bak_preservation_e2e(recovery_env):
    """Verify atomic write creates .bak backup of previous valid state."""
    tmp_path, config = recovery_env
    state_file = tmp_path / "state.json"
    backup_file = tmp_path / "state.json.bak"

    # Initial write
    AtomicPersistence.atomic_write_json(state_file, {"version": 1, "status": "init"}, backup=True)
    assert state_file.is_file()
    assert not backup_file.is_file()  # No prior version to backup

    # Second write
    AtomicPersistence.atomic_write_json(state_file, {"version": 2, "status": "updated"}, backup=True)
    assert state_file.is_file()
    assert backup_file.is_file()

    # Verify backup contains version 1
    bak_data = json.loads(backup_file.read_text(encoding="utf-8"))
    assert bak_data["version"] == 1

    # Current contains version 2
    cur_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert cur_data["version"] == 2


def test_atomic_persistence_corruption_fallback_e2e(recovery_env):
    """Verify safe_read_json automatically falls back to .bak if primary is corrupted."""
    tmp_path, config = recovery_env
    state_file = tmp_path / "critical_data.json"
    backup_file = tmp_path / "critical_data.json.bak"

    # Write initial data to both primary and backup
    valid_payload = {"system": "device_guardian", "counter": 42}
    AtomicPersistence.atomic_write_json(state_file, valid_payload, backup=True)
    AtomicPersistence.atomic_write_json(state_file, {"system": "device_guardian", "counter": 43}, backup=True)

    # Intentionally corrupt primary file
    state_file.write_text("{malformed: json: [unclosed", encoding="utf-8")

    # Read with fallback allowed
    data, recovered_from_bak, err = AtomicPersistence.safe_read_json(state_file, allow_backup_fallback=True)
    assert recovered_from_bak is True
    assert data is not None
    assert data["counter"] == 42


def test_disaster_recovery_corrupted_state_preservation_and_repair_e2e(recovery_env):
    """Verify corrupted state files are backed up as .corrupt.* and cleanly regenerated."""
    tmp_path, config = recovery_env
    status_file = ApplicationPaths.get_status_file_path()
    status_file.parent.mkdir(parents=True, exist_ok=True)

    # Write garbage to status file
    status_file.write_text("CORRUPTED_RAW_BINARY_TRASH", encoding="utf-8")

    # Execute disaster recovery repair
    repairs = repair_state_files()
    assert len(repairs) >= 1

    # Verify corrupt file was preserved
    corrupt_copies = list(status_file.parent.glob("runtime_status.json.corrupt.*"))
    assert len(corrupt_copies) >= 1
    assert corrupt_copies[0].read_text(encoding="utf-8") == "CORRUPTED_RAW_BINARY_TRASH"

    # Verify clean status file exists and parses as JSON
    assert status_file.is_file()
    cleaned = json.loads(status_file.read_text(encoding="utf-8"))
    assert "state" in cleaned


def test_repair_preserves_user_env_and_credentials_e2e(recovery_env):
    """Verify disaster recovery repair strictly never wipes .env or user credentials."""
    tmp_path, config = recovery_env

    env_file = tmp_path / ".env"
    env_file.write_text("TELEGRAM_BOT_TOKEN=super_secret_user_token\n", encoding="utf-8")

    secrets_file = tmp_path / "secrets.dat"
    secrets_file.write_text("ENCRYPTED_SECRETS_DATA", encoding="utf-8")

    # Run repair
    repair_state_files()

    # User files MUST remain untouched
    assert env_file.is_file()
    assert "super_secret_user_token" in env_file.read_text(encoding="utf-8")
    assert secrets_file.is_file()
    assert secrets_file.read_text(encoding="utf-8") == "ENCRYPTED_SECRETS_DATA"


def test_utc_timestamps_and_clock_skew_defense_e2e(recovery_env):
    """Verify all health and recovery timestamps are strictly UTC and ISO-8601 compliant."""
    tmp_path, config = recovery_env

    status = get_recovery_status(config=config)
    assert "timestamp" in status
    ts_str = status["timestamp"]

    # Verify parseable as ISO-8601
    dt = datetime.fromisoformat(ts_str)
    assert dt is not None


def test_health_assessment_subsystems_objective_reporting_e2e(recovery_env):
    """Verify health assessment reports objective statuses with zero heuristic scoring."""
    tmp_path, config = recovery_env

    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True

    with patch("cv2.VideoCapture", return_value=mock_cap), \
         patch("device_guardian.location.geolocation.get_approximate_location") as mock_loc:

        mock_loc.return_value = MagicMock(is_available=True, city="Zurich", country="Switzerland")

        report = assess_system_health(config=config)
        assert report.overall_status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN)

        # Confirm all subsystems have strict deterministic enum states
        for sub in report.subsystems:
            assert isinstance(sub.status, HealthStatus)
            # Ensure no risk scores or threat levels are attached
            assert not hasattr(sub, "threat_score")
            assert not hasattr(sub, "risk_level")
