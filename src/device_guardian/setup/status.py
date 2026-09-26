"""Setup state determination for Device Guardian.

Evaluates configuration completeness without external dependencies or databases.
Determines whether Device Guardian is NOT_CONFIGURED, PARTIALLY_CONFIGURED,
or fully CONFIGURED.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from device_guardian.config import AppConfig, ConfigurationError, load_config

_PLACEHOLDERS = {
    "your_telegram_bot_token_here",
    "YOUR_BOT_TOKEN",
    "CHANGE_ME",
    "your_telegram_chat_id_here",
    "YOUR_CHAT_ID",
    "",
}


class SetupStatus(str, Enum):
    """Configuration lifecycle states for Device Guardian."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    PARTIALLY_CONFIGURED = "PARTIALLY_CONFIGURED"
    CONFIGURED = "CONFIGURED"


def determine_setup_status(
    config: Optional[AppConfig] = None,
    env_path: Optional[Path | str] = None,
) -> SetupStatus:
    """Determine the current configuration state of Device Guardian.

    Args:
        config: Optional pre-loaded AppConfig instance.
        env_path: Optional path to .env file to inspect.

    Returns:
        SetupStatus indicating NOT_CONFIGURED, PARTIALLY_CONFIGURED, or CONFIGURED.
    """
    if config is None:
        if env_path is not None:
            resolved_env = Path(env_path).resolve()
            if not resolved_env.is_file():
                return SetupStatus.NOT_CONFIGURED

        try:
            config = load_config(env_path=env_path)
        except ConfigurationError:
            return SetupStatus.PARTIALLY_CONFIGURED
        except Exception:
            return SetupStatus.NOT_CONFIGURED

    token = (config.telegram_bot_token or "").strip()
    chat_id = (config.telegram_chat_id or "").strip()

    has_token = bool(token and token not in _PLACEHOLDERS)
    has_chat_id = bool(chat_id and chat_id not in _PLACEHOLDERS)

    if not has_token and not has_chat_id:
        return SetupStatus.NOT_CONFIGURED

    if not has_token or not has_chat_id:
        return SetupStatus.PARTIALLY_CONFIGURED

    # Both token and chat_id are present; validate full settings
    try:
        config.validate()
        return SetupStatus.CONFIGURED
    except ConfigurationError:
        return SetupStatus.PARTIALLY_CONFIGURED
