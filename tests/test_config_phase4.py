"""Unit tests for Phase 4 Configuration Loading and Storage Formatting."""

from __future__ import annotations

import os
from pathlib import Path

from device_guardian.config import AppConfig, load_config
from device_guardian.setup.storage import format_env_file


def test_load_config_phase4_defaults(tmp_path: Path) -> None:
    """Verify Phase 4 default settings when loading config without extra env vars."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567\n"
        "TELEGRAM_CHAT_ID=987654321\n",
        encoding="utf-8",
    )

    cfg = load_config(env_path=env_file)
    assert cfg.smart_filtering_enabled is True
    assert cfg.trusted_users == []
    assert cfg.trusted_networks == []
    assert cfg.trusted_auth_types == []
    assert cfg.environmental_triggers_enabled is True
    assert cfg.network_context_enabled is True
    assert cfg.device_state_context_enabled is True
    assert cfg.require_context_for_alert is False
    assert cfg.camera_alert_enabled is True
    assert cfg.location_alert_enabled is True
    assert cfg.telegram_alert_enabled is True


def test_load_config_phase4_custom_values(tmp_path: Path) -> None:
    """Verify Phase 4 environment variables and CSV parsing."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567\n"
        "TELEGRAM_CHAT_ID=987654321\n"
        "SMART_FILTERING_ENABLED=false\n"
        "DEVICE_GUARDIAN_TRUSTED_USERS=alice, bob, charlie\n"
        "DEVICE_GUARDIAN_TRUSTED_NETWORKS=home_wifi, net_10.0.0.0/24\n"
        "DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES=local\n"
        "REQUIRE_CONTEXT_FOR_ALERT=true\n"
        "CAMERA_ALERT_ENABLED=false\n"
        "LOCATION_ALERT_ENABLED=false\n"
        "TELEGRAM_ALERT_ENABLED=false\n",
        encoding="utf-8",
    )

    cfg = load_config(env_path=env_file)
    assert cfg.smart_filtering_enabled is False
    assert cfg.trusted_users == ["alice", "bob", "charlie"]
    assert cfg.trusted_networks == ["home_wifi", "net_10.0.0.0/24"]
    assert cfg.trusted_auth_types == ["local"]
    assert cfg.require_context_for_alert is True
    assert cfg.camera_alert_enabled is False
    assert cfg.location_alert_enabled is False
    assert cfg.telegram_alert_enabled is False


def test_format_env_file_phase4_keys() -> None:
    """Verify format_env_file serializes Phase 4 configuration settings."""
    cfg = AppConfig(
        telegram_bot_token="123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567",
        telegram_chat_id="987654321",
        trusted_users=["alice", "bob"],
        trusted_networks=["office_lan"],
        trusted_auth_types=["local"],
        smart_filtering_enabled=True,
        require_context_for_alert=False,
    )
    rendered = format_env_file(cfg)
    assert "SMART_FILTERING_ENABLED=true" in rendered
    assert "DEVICE_GUARDIAN_TRUSTED_USERS=alice,bob" in rendered
    assert "DEVICE_GUARDIAN_TRUSTED_NETWORKS=office_lan" in rendered
    assert "DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES=local" in rendered
    assert "CAMERA_ALERT_ENABLED=true" in rendered
