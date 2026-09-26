"""Telegram Chat ID detection for Device Guardian Setup Wizard.

Safely queries the Telegram Bot API getUpdates endpoint to identify the
user's chat identifier. Adheres to strict data minimization:
- Only extracts chat ID, type, and minimal username/title.
- Message contents, media, and timestamps are completely ignored and discarded.
- Polling is strictly bounded to prevent infinite loops.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from device_guardian.config import mask_chat_id
from device_guardian.logger import get_logger
from device_guardian.telegram.bot import TelegramClient

logger = get_logger("setup.chat_detector")


@dataclass
class DetectedChat:
    """Minimal representation of a detected Telegram chat destination."""

    chat_id: str
    chat_type: str = "private"
    display_name: str = ""

    @property
    def masked_id(self) -> str:
        """Return masked chat ID for privacy."""
        return mask_chat_id(self.chat_id)

    def summary(self) -> str:
        """Formatted human-readable line."""
        info = f"Chat {self.masked_id}"
        if self.display_name:
            info += f" ({self.display_name})"
        if self.chat_type and self.chat_type != "private":
            info += f" [{self.chat_type}]"
        return info


def extract_chats_from_updates(updates: list[dict[str, Any]]) -> list[DetectedChat]:
    """Extract distinct chat destinations from Telegram update records.

    Strict Data Minimization:
    - Extracts ONLY chat ID, type, and display username/title.
    - Drops all message text, attachments, photos, locations, and personal metadata.

    Args:
        updates: Raw list of update dicts from Telegram getUpdates.

    Returns:
        List of unique DetectedChat objects.
    """
    seen_ids: set[str] = set()
    detected: list[DetectedChat] = []

    for item in updates:
        if not isinstance(item, dict):
            continue

        # Inspect standard message objects
        msg = (
            item.get("message")
            or item.get("edited_message")
            or item.get("channel_post")
        )
        if not isinstance(msg, dict):
            continue

        chat = msg.get("chat")
        if not isinstance(chat, dict):
            continue

        raw_id = chat.get("id")
        if raw_id is None:
            continue

        chat_id_str = str(raw_id).strip()
        if not chat_id_str or chat_id_str in seen_ids:
            continue

        seen_ids.add(chat_id_str)
        chat_type = str(chat.get("type") or "private")

        # Determine minimal non-sensitive display handle
        display_name = ""
        if chat.get("username"):
            display_name = f"@{chat['username']}"
        elif chat.get("title"):
            display_name = str(chat["title"])[:30]
        elif chat.get("first_name"):
            display_name = str(chat["first_name"])[:20]

        detected.append(
            DetectedChat(
                chat_id=chat_id_str,
                chat_type=chat_type,
                display_name=display_name,
            )
        )

    return detected


def poll_for_chat_id(
    telegram_client: TelegramClient,
    max_attempts: int = 10,
    poll_interval: float = 2.0,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> list[DetectedChat]:
    """Poll Telegram getUpdates with bounded attempts to detect user chat ID.

    Args:
        telegram_client: Initialized TelegramClient with valid bot token.
        max_attempts: Maximum number of polling requests (bounded loop).
        poll_interval: Wait time between attempts in seconds.
        progress_callback: Optional callback reporting current attempt and total.

    Returns:
        List of DetectedChat instances, or empty list if no messages were received.
    """
    logger.info(
        "Beginning bounded Telegram chat ID detection (max %d attempts)...",
        max_attempts,
    )

    for attempt in range(1, max_attempts + 1):
        if progress_callback:
            progress_callback(attempt, max_attempts)

        resp = telegram_client.get_updates(timeout=int(poll_interval), limit=20)
        if resp.success and isinstance(resp.data, list) and resp.data:
            chats = extract_chats_from_updates(resp.data)
            if chats:
                logger.info("Successfully detected %d Telegram chat(s).", len(chats))
                return chats

        if attempt < max_attempts:
            time.sleep(poll_interval)

    logger.warning("Chat ID detection completed without finding any messages.")
    return []
