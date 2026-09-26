"""Configuration management for Device Guardian.

Loads settings from environment variables and .env files securely.
Ensures secrets such as Telegram bot tokens are never logged or exposed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

from device_guardian.security.secret import SecretValue
from device_guardian.security.redactor import get_redactor


class ConfigurationError(Exception):
    """Raised when application configuration is invalid or missing."""
    pass


def mask_token(token: Optional[str | SecretValue]) -> str:
    """Mask sensitive tokens to prevent accidental exposure in logs.

    Args:
        token: The raw token string, SecretValue, or None.

    Returns:
        Masked token string (e.g. '1234***abcd' or '***EMPTY***').
    """
    if token is None:
        return "***EMPTY***"
    if hasattr(token, "mask"):
        return token.mask()
    s = str(token).strip()
    if not s:
        return "***EMPTY***"
    if len(s) <= 8:
        return "***REDACTED***"
    return f"{s[:4]}***{s[-4:]}"


def mask_chat_id(chat_id: Optional[str | SecretValue]) -> str:
    """Mask Telegram chat ID for privacy when displaying to users.

    Args:
        chat_id: The raw chat ID string, SecretValue, or None.

    Returns:
        Masked chat ID (e.g. '*****1234' or '***EMPTY***').
    """
    if chat_id is None:
        return "***EMPTY***"
    if hasattr(chat_id, "get_secret_value"):
        s = chat_id.get_secret_value().strip()
    else:
        s = str(chat_id).strip()
    if not s:
        return "***EMPTY***"
    if len(s) <= 4:
        return "****"
    return f"{'*' * (len(s) - 4)}{s[-4:]}"


@dataclass
class AppConfig:
    """Device Guardian application configuration settings."""

    telegram_bot_token: str | SecretValue = ""
    telegram_chat_id: str | SecretValue = ""
    location_api_url: str = "https://ipapi.co/json/"
    camera_index: int = 0
    request_timeout_seconds: float = 10.0
    log_level: str = "INFO"
    auth_failure_threshold: int = 3
    auth_failure_window_seconds: float = 60.0
    auth_alert_cooldown_seconds: float = 300.0
    voice_warning_enabled: bool = True
    voice_warning_text: str = (
        "Warning. Multiple failed authentication attempts have been detected on this device."
    )
    voice_warning_cooldown_seconds: float = 300.0
    # Phase 4: Smart Filtering & Environmental Triggers
    smart_filtering_enabled: bool = True
    trusted_users: list[str] = field(default_factory=list)
    trusted_networks: list[str] = field(default_factory=list)
    trusted_auth_types: list[str] = field(default_factory=list)
    environmental_triggers_enabled: bool = True
    network_context_enabled: bool = True
    device_state_context_enabled: bool = True
    require_context_for_alert: bool = False
    camera_alert_enabled: bool = True
    location_alert_enabled: bool = True
    telegram_alert_enabled: bool = True
    # Phase 5: Packaging, Background Services & System Tray Integration
    background_mode_enabled: bool = False
    tray_enabled: bool = True
    start_with_system: bool = False
    single_instance_enabled: bool = True
    auto_restart_enabled: bool = True
    max_restart_attempts: int = 3
    restart_backoff_seconds: float = 2.0
    env_file_path: Optional[Path] = None

    def __post_init__(self) -> None:
        """Register secrets and ensure SecretValue types."""
        if not isinstance(self.telegram_bot_token, SecretValue):
            self.telegram_bot_token = SecretValue(str(self.telegram_bot_token or ""))
        if not isinstance(self.telegram_chat_id, SecretValue):
            self.telegram_chat_id = SecretValue(str(self.telegram_chat_id or ""))

        try:
            redactor = get_redactor()
            if not self.telegram_bot_token.is_empty():
                redactor.register_secret(self.telegram_bot_token.get_secret_value())
            if not self.telegram_chat_id.is_empty():
                redactor.register_secret(self.telegram_chat_id.get_secret_value())
        except Exception:
            pass

    def get_secret_token(self) -> str:
        """Retrieve the raw Telegram bot token string."""
        if isinstance(self.telegram_bot_token, SecretValue):
            return self.telegram_bot_token.get_secret_value()
        return str(self.telegram_bot_token or "")

    def get_secret_chat_id(self) -> str:
        """Retrieve the raw Telegram chat ID string."""
        if isinstance(self.telegram_chat_id, SecretValue):
            return self.telegram_chat_id.get_secret_value()
        return str(self.telegram_chat_id or "")

    def validate_readiness(self):
        """Perform comprehensive subsystem validation.

        Returns:
            ConfigValidationReport with granular readiness findings.
        """
        from device_guardian.security.validation import validate_subsystems
        return validate_subsystems(self)

    def to_sanitized_dict(self) -> dict[str, Any]:
        """Return a clean dictionary representation with masked secrets."""
        return {
            "telegram_bot_token": mask_token(self.telegram_bot_token),
            "telegram_chat_id": mask_chat_id(self.telegram_chat_id),
            "location_api_url": self.location_api_url,
            "camera_index": self.camera_index,
            "request_timeout_seconds": self.request_timeout_seconds,
            "log_level": self.log_level,
            "auth_failure_threshold": self.auth_failure_threshold,
            "auth_failure_window_seconds": self.auth_failure_window_seconds,
            "auth_alert_cooldown_seconds": self.auth_alert_cooldown_seconds,
            "voice_warning_enabled": self.voice_warning_enabled,
            "voice_warning_text": self.voice_warning_text,
            "voice_warning_cooldown_seconds": self.voice_warning_cooldown_seconds,
            "smart_filtering_enabled": self.smart_filtering_enabled,
            "trusted_users": list(self.trusted_users),
            "trusted_networks": list(self.trusted_networks),
            "trusted_auth_types": list(self.trusted_auth_types),
            "environmental_triggers_enabled": self.environmental_triggers_enabled,
            "network_context_enabled": self.network_context_enabled,
            "device_state_context_enabled": self.device_state_context_enabled,
            "require_context_for_alert": self.require_context_for_alert,
            "camera_alert_enabled": self.camera_alert_enabled,
            "location_alert_enabled": self.location_alert_enabled,
            "telegram_alert_enabled": self.telegram_alert_enabled,
            "background_mode_enabled": self.background_mode_enabled,
            "tray_enabled": self.tray_enabled,
            "start_with_system": self.start_with_system,
            "single_instance_enabled": self.single_instance_enabled,
            "auto_restart_enabled": self.auto_restart_enabled,
            "max_restart_attempts": self.max_restart_attempts,
            "restart_backoff_seconds": self.restart_backoff_seconds,
            "env_file_path": str(self.env_file_path) if self.env_file_path else None,
        }

    def __repr__(self) -> str:
        """Safe representation masking sensitive credentials."""
        return (
            f"AppConfig("
            f"telegram_bot_token='{mask_token(self.telegram_bot_token)}', "
            f"telegram_chat_id='{mask_chat_id(self.telegram_chat_id)}', "
            f"location_api_url='{self.location_api_url}', "
            f"camera_index={self.camera_index}, "
            f"request_timeout_seconds={self.request_timeout_seconds}, "
            f"log_level='{self.log_level}', "
            f"auth_failure_threshold={self.auth_failure_threshold}, "
            f"auth_failure_window_seconds={self.auth_failure_window_seconds}, "
            f"auth_alert_cooldown_seconds={self.auth_alert_cooldown_seconds}, "
            f"voice_warning_enabled={self.voice_warning_enabled})"
        )

    def validate(self) -> None:
        """Validate configuration values.

        Raises:
            ConfigurationError: If any required setting is missing or invalid.
        """
        errors: list[str] = []

        # Validate Telegram Bot Token
        if self.telegram_alert_enabled:
            if not self.telegram_bot_token or not self.telegram_bot_token.strip():
                errors.append(
                    "TELEGRAM_BOT_TOKEN is missing. Please set it in your .env file."
                )
            elif self.telegram_bot_token.strip() in {
                "your_telegram_bot_token_here",
                "YOUR_BOT_TOKEN",
                "CHANGE_ME",
            }:
                errors.append(
                    "TELEGRAM_BOT_TOKEN contains placeholder value. Please set a valid Telegram bot token in .env."
                )

            # Validate Telegram Chat ID
            if not self.telegram_chat_id or not self.telegram_chat_id.strip():
                errors.append(
                    "TELEGRAM_CHAT_ID is missing. Please set it in your .env file."
                )
            elif self.telegram_chat_id.strip() in {
                "your_telegram_chat_id_here",
                "YOUR_CHAT_ID",
                "CHANGE_ME",
            }:
                errors.append(
                    "TELEGRAM_CHAT_ID contains placeholder value. Please set a valid Telegram chat ID in .env."
                )
        else:
            if self.telegram_bot_token and self.telegram_bot_token.strip() in {
                "your_telegram_bot_token_here",
                "YOUR_BOT_TOKEN",
                "CHANGE_ME",
            }:
                errors.append(
                    "TELEGRAM_BOT_TOKEN contains placeholder value. Please set a valid Telegram bot token in .env."
                )
            if self.telegram_chat_id and self.telegram_chat_id.strip() in {
                "your_telegram_chat_id_here",
                "YOUR_CHAT_ID",
                "CHANGE_ME",
            }:
                errors.append(
                    "TELEGRAM_CHAT_ID contains placeholder value. Please set a valid Telegram chat ID in .env."
                )

        # Validate Camera Index
        if self.camera_index < 0:
            errors.append(
                f"CAMERA_INDEX must be a non-negative integer, got: {self.camera_index}"
            )
        elif self.camera_index > 32:
            errors.append(
                f"CAMERA_INDEX exceeds maximum allowed index (32), got: {self.camera_index}"
            )

        # Validate Timeout
        if self.request_timeout_seconds <= 0:
            errors.append(
                f"REQUEST_TIMEOUT_SECONDS must be positive, got: {self.request_timeout_seconds}"
            )
        elif self.request_timeout_seconds > 300.0:
            errors.append(
                f"REQUEST_TIMEOUT_SECONDS exceeds maximum allowed timeout (300.0s), got: {self.request_timeout_seconds}"
            )

        # Validate Location API URL
        if not self.location_api_url or not self.location_api_url.startswith(("http://", "https://")):
            errors.append(
                f"LOCATION_API_URL must be a valid HTTP/HTTPS URL, got: '{self.location_api_url}'"
            )
        elif len(self.location_api_url) > 2048:
            errors.append(
                "LOCATION_API_URL exceeds maximum length of 2048 characters"
            )

        # Validate Auth Failure Threshold
        if self.auth_failure_threshold < 1:
            errors.append(
                f"AUTH_FAILURE_THRESHOLD must be at least 1, got: {self.auth_failure_threshold}"
            )
        elif self.auth_failure_threshold > 100:
            errors.append(
                f"AUTH_FAILURE_THRESHOLD exceeds maximum allowed value (100), got: {self.auth_failure_threshold}"
            )

        # Validate Auth Failure Window Seconds
        if self.auth_failure_window_seconds <= 0:
            errors.append(
                f"AUTH_FAILURE_WINDOW_SECONDS must be positive, got: {self.auth_failure_window_seconds}"
            )
        elif self.auth_failure_window_seconds > 86400.0:
            errors.append(
                f"AUTH_FAILURE_WINDOW_SECONDS exceeds maximum allowed window (86400s), got: {self.auth_failure_window_seconds}"
            )

        # Validate Cooldowns
        if self.auth_alert_cooldown_seconds < 0:
            errors.append(
                f"AUTH_ALERT_COOLDOWN_SECONDS must be non-negative, got: {self.auth_alert_cooldown_seconds}"
            )
        elif self.auth_alert_cooldown_seconds > 86400.0:
            errors.append(
                f"AUTH_ALERT_COOLDOWN_SECONDS exceeds maximum allowed cooldown (86400s), got: {self.auth_alert_cooldown_seconds}"
            )

        if self.voice_warning_cooldown_seconds < 0:
            errors.append(
                f"VOICE_WARNING_COOLDOWN_SECONDS must be non-negative, got: {self.voice_warning_cooldown_seconds}"
            )
        elif self.voice_warning_cooldown_seconds > 86400.0:
            errors.append(
                f"VOICE_WARNING_COOLDOWN_SECONDS exceeds maximum allowed cooldown (86400s), got: {self.voice_warning_cooldown_seconds}"
            )

        if self.max_restart_attempts < 0:
            errors.append(
                f"MAX_RESTART_ATTEMPTS must be non-negative, got: {self.max_restart_attempts}"
            )
        elif self.max_restart_attempts > 100:
            errors.append(
                f"MAX_RESTART_ATTEMPTS exceeds maximum allowed attempts (100), got: {self.max_restart_attempts}"
            )

        if self.restart_backoff_seconds < 0:
            errors.append(
                f"RESTART_BACKOFF_SECONDS must be non-negative, got: {self.restart_backoff_seconds}"
            )
        elif self.restart_backoff_seconds > 3600.0:
            errors.append(
                f"RESTART_BACKOFF_SECONDS exceeds maximum allowed backoff (3600s), got: {self.restart_backoff_seconds}"
            )

        # Validate Log Level
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level not in valid_log_levels:
            errors.append(
                f"LOG_LEVEL must be one of {valid_log_levels}, got: '{self.log_level}'"
            )

        if errors:
            raise ConfigurationError(
                "Configuration validation failed:\n" + "\n".join(f"- {err}" for err in errors)
            )


def load_config(env_path: Optional[Path | str] = None) -> AppConfig:
    """Load configuration from environment variables and an optional .env file.

    Args:
        env_path: Optional explicit path to the .env file.

    Returns:
        Loaded AppConfig instance.

    Raises:
        ConfigurationError: If configuration is invalid.
    """
    resolved_env_path: Optional[Path] = None

    if env_path is not None:
        resolved_env_path = Path(env_path).resolve()
        if resolved_env_path.is_file():
            load_dotenv(dotenv_path=resolved_env_path, override=True)
    else:
        # Check current working directory, then user data directory
        cwd_env = Path.cwd() / ".env"
        if cwd_env.is_file():
            resolved_env_path = cwd_env
            load_dotenv(dotenv_path=cwd_env, override=True)
        else:
            try:
                from device_guardian.runtime.paths import ApplicationPaths
                user_env = ApplicationPaths.get_user_data_dir() / ".env"
                if user_env.is_file():
                    resolved_env_path = user_env
                    load_dotenv(dotenv_path=user_env, override=True)
                else:
                    load_dotenv(override=False)
            except Exception:
                load_dotenv(override=False)

    # Parse camera index
    raw_camera_index = os.getenv("CAMERA_INDEX", "0")
    try:
        camera_index = int(raw_camera_index)
    except ValueError:
        raise ConfigurationError(
            f"Invalid CAMERA_INDEX: '{raw_camera_index}'. Must be an integer."
        )

    # Parse request timeout
    raw_timeout = os.getenv("REQUEST_TIMEOUT_SECONDS", "10")
    try:
        timeout_seconds = float(raw_timeout)
    except ValueError:
        raise ConfigurationError(
            f"Invalid REQUEST_TIMEOUT_SECONDS: '{raw_timeout}'. Must be a number."
        )

    # Parse auth failure threshold
    raw_threshold = os.getenv("AUTH_FAILURE_THRESHOLD", "3")
    try:
        auth_failure_threshold = int(raw_threshold)
    except ValueError:
        raise ConfigurationError(
            f"Invalid AUTH_FAILURE_THRESHOLD: '{raw_threshold}'. Must be an integer."
        )

    # Parse auth failure window seconds
    raw_window = os.getenv("AUTH_FAILURE_WINDOW_SECONDS", "60")
    try:
        auth_failure_window = float(raw_window)
    except ValueError:
        raise ConfigurationError(
            f"Invalid AUTH_FAILURE_WINDOW_SECONDS: '{raw_window}'. Must be a number."
        )

    # Parse auth alert cooldown seconds
    raw_cooldown = os.getenv("AUTH_ALERT_COOLDOWN_SECONDS", "300")
    try:
        auth_alert_cooldown = float(raw_cooldown)
    except ValueError:
        raise ConfigurationError(
            f"Invalid AUTH_ALERT_COOLDOWN_SECONDS: '{raw_cooldown}'. Must be a number."
        )

    # Strict boolean parser
    def _parse_bool(val: Optional[str], default: bool, var_name: str = "") -> bool:
        if val is None or not str(val).strip():
            return default
        cleaned = str(val).lower().strip()
        if cleaned in {"true", "1", "yes", "on"}:
            return True
        if cleaned in {"false", "0", "no", "off"}:
            return False
        name_str = f" for {var_name}" if var_name else ""
        raise ConfigurationError(
            f"Invalid boolean value '{val}'{name_str}. Must be one of: true, false, 1, 0, yes, no, on, off."
        )

    def _parse_csv(val: Optional[str]) -> list[str]:
        if not val or not str(val).strip():
            return []
        return [item.strip() for item in str(val).split(",") if item.strip()]

    # Parse voice warning settings
    voice_warning_enabled = _parse_bool(
        os.getenv("VOICE_WARNING_ENABLED"), True, var_name="VOICE_WARNING_ENABLED"
    )

    voice_warning_text = os.getenv(
        "VOICE_WARNING_TEXT",
        "Warning. Multiple failed authentication attempts have been detected on this device.",
    ).strip()

    raw_voice_cooldown = os.getenv("VOICE_WARNING_COOLDOWN_SECONDS", "300")
    try:
        voice_warning_cooldown = float(raw_voice_cooldown)
    except ValueError:
        raise ConfigurationError(
            f"Invalid VOICE_WARNING_COOLDOWN_SECONDS: '{raw_voice_cooldown}'. Must be a number."
        )

    # Phase 4: Smart Filtering & Environmental Triggers parsing
    smart_filtering_enabled = _parse_bool(
        os.getenv("SMART_FILTERING_ENABLED"), True, var_name="SMART_FILTERING_ENABLED"
    )
    trusted_users = _parse_csv(
        os.getenv("DEVICE_GUARDIAN_TRUSTED_USERS") or os.getenv("TRUSTED_USERS")
    )
    trusted_networks = _parse_csv(
        os.getenv("DEVICE_GUARDIAN_TRUSTED_NETWORKS") or os.getenv("TRUSTED_NETWORKS")
    )
    trusted_auth_types = _parse_csv(
        os.getenv("DEVICE_GUARDIAN_TRUSTED_AUTH_TYPES") or os.getenv("TRUSTED_AUTH_TYPES")
    )
    environmental_triggers_enabled = _parse_bool(
        os.getenv("ENVIRONMENTAL_TRIGGERS_ENABLED"), True, var_name="ENVIRONMENTAL_TRIGGERS_ENABLED"
    )
    network_context_enabled = _parse_bool(
        os.getenv("NETWORK_CONTEXT_ENABLED"), True, var_name="NETWORK_CONTEXT_ENABLED"
    )
    device_state_context_enabled = _parse_bool(
        os.getenv("DEVICE_STATE_CONTEXT_ENABLED"), True, var_name="DEVICE_STATE_CONTEXT_ENABLED"
    )
    require_context_for_alert = _parse_bool(
        os.getenv("REQUIRE_CONTEXT_FOR_ALERT"), False, var_name="REQUIRE_CONTEXT_FOR_ALERT"
    )
    camera_alert_enabled = _parse_bool(
        os.getenv("CAMERA_ALERT_ENABLED"), True, var_name="CAMERA_ALERT_ENABLED"
    )
    location_alert_enabled = _parse_bool(
        os.getenv("LOCATION_ALERT_ENABLED"), True, var_name="LOCATION_ALERT_ENABLED"
    )
    telegram_alert_enabled = _parse_bool(
        os.getenv("TELEGRAM_ALERT_ENABLED"), True, var_name="TELEGRAM_ALERT_ENABLED"
    )

    # Phase 5: Packaging, Background Services & System Tray Integration
    background_mode_enabled = _parse_bool(
        os.getenv("BACKGROUND_MODE_ENABLED"), False, var_name="BACKGROUND_MODE_ENABLED"
    )
    tray_enabled = _parse_bool(
        os.getenv("TRAY_ENABLED"), True, var_name="TRAY_ENABLED"
    )
    start_with_system = _parse_bool(
        os.getenv("START_WITH_SYSTEM"), False, var_name="START_WITH_SYSTEM"
    )
    single_instance_enabled = _parse_bool(
        os.getenv("SINGLE_INSTANCE_ENABLED"), True, var_name="SINGLE_INSTANCE_ENABLED"
    )
    auto_restart_enabled = _parse_bool(
        os.getenv("AUTO_RESTART_ENABLED"), True, var_name="AUTO_RESTART_ENABLED"
    )

    raw_max_restarts = os.getenv("MAX_RESTART_ATTEMPTS", "3")
    try:
        max_restart_attempts = int(raw_max_restarts)
    except ValueError:
        raise ConfigurationError(
            f"Invalid MAX_RESTART_ATTEMPTS: '{raw_max_restarts}'. Must be an integer."
        )

    raw_restart_backoff = os.getenv("RESTART_BACKOFF_SECONDS", "2.0")
    try:
        restart_backoff_seconds = float(raw_restart_backoff)
    except ValueError:
        raise ConfigurationError(
            f"Invalid RESTART_BACKOFF_SECONDS: '{raw_restart_backoff}'. Must be a number."
        )

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    if not bot_token or not chat_id:
        try:
            from device_guardian.security.store import create_default_secret_store
            store = create_default_secret_store()
            if not bot_token:
                stored_token = store.get_secret("TELEGRAM_BOT_TOKEN")
                if stored_token:
                    bot_token = stored_token.strip()
            if not chat_id:
                stored_chat_id = store.get_secret("TELEGRAM_CHAT_ID")
                if stored_chat_id:
                    chat_id = stored_chat_id.strip()
        except Exception:
            pass

    config = AppConfig(
        telegram_bot_token=bot_token,
        telegram_chat_id=chat_id,
        location_api_url=os.getenv("LOCATION_API_URL", "https://ipapi.co/json/").strip(),
        camera_index=camera_index,
        request_timeout_seconds=timeout_seconds,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper().strip(),
        auth_failure_threshold=auth_failure_threshold,
        auth_failure_window_seconds=auth_failure_window,
        auth_alert_cooldown_seconds=auth_alert_cooldown,
        voice_warning_enabled=voice_warning_enabled,
        voice_warning_text=voice_warning_text,
        voice_warning_cooldown_seconds=voice_warning_cooldown,
        smart_filtering_enabled=smart_filtering_enabled,
        trusted_users=trusted_users,
        trusted_networks=trusted_networks,
        trusted_auth_types=trusted_auth_types,
        environmental_triggers_enabled=environmental_triggers_enabled,
        network_context_enabled=network_context_enabled,
        device_state_context_enabled=device_state_context_enabled,
        require_context_for_alert=require_context_for_alert,
        camera_alert_enabled=camera_alert_enabled,
        location_alert_enabled=location_alert_enabled,
        telegram_alert_enabled=telegram_alert_enabled,
        background_mode_enabled=background_mode_enabled,
        tray_enabled=tray_enabled,
        start_with_system=start_with_system,
        single_instance_enabled=single_instance_enabled,
        auto_restart_enabled=auto_restart_enabled,
        max_restart_attempts=max_restart_attempts,
        restart_backoff_seconds=restart_backoff_seconds,
        env_file_path=resolved_env_path,
    )

    return config
