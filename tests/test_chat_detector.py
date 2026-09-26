"""Unit tests for Telegram chat ID detection and data minimization."""

from unittest.mock import MagicMock
import pytest

from device_guardian.config import mask_chat_id
from device_guardian.setup.chat_detector import (
    DetectedChat,
    extract_chats_from_updates,
    poll_for_chat_id,
)
from device_guardian.telegram.bot import TelegramClient, TelegramResponse


def test_mask_chat_id_formatting():
    """Verify mask_chat_id hides leading digits for privacy."""
    assert mask_chat_id(None) == "***EMPTY***"
    assert mask_chat_id("") == "***EMPTY***"
    assert mask_chat_id("123") == "****"
    assert mask_chat_id("1234") == "****"
    assert mask_chat_id("987654321") == "*****4321"
    assert mask_chat_id("-100123456789") == "*********6789"


def test_extract_chats_data_minimization():
    """Verify that extract_chats_from_updates drops text, photos, and personal contents."""
    updates = [
        {
            "update_id": 1001,
            "message": {
                "message_id": 1,
                "from": {"id": 111, "first_name": "Alice", "username": "alice_w"},
                "chat": {"id": 111, "type": "private", "username": "alice_w"},
                "text": "CONFIDENTIAL PASSWORD OR SENSITIVE MESSAGE",
                "date": 1727280000,
                "photo": [{"file_id": "secret_photo_id"}],
                "contact": {"phone_number": "+1234567890"},
            },
        }
    ]

    chats = extract_chats_from_updates(updates)
    assert len(chats) == 1
    chat = chats[0]
    assert chat.chat_id == "111"
    assert chat.chat_type == "private"
    assert chat.display_name == "@alice_w"

    # Verify no message content or private data leaked into the DetectedChat object
    chat_repr = repr(chat)
    assert "CONFIDENTIAL" not in chat_repr
    assert "secret_photo_id" not in chat_repr
    assert "+1234567890" not in chat_repr


def test_extract_chats_multiple_distinct_sources():
    """Verify handling multiple distinct chats with deduplication."""
    updates = [
        {
            "update_id": 1,
            "message": {
                "chat": {"id": 100, "type": "private", "first_name": "Bob"},
                "text": "Hello 1",
            },
        },
        {
            "update_id": 2,
            "message": {
                "chat": {"id": 200, "type": "group", "title": "Home Security"},
                "text": "Hello 2",
            },
        },
        {
            "update_id": 3,
            "message": {
                # Duplicate chat 100
                "chat": {"id": 100, "type": "private", "first_name": "Bob"},
                "text": "Hello 3",
            },
        },
    ]

    chats = extract_chats_from_updates(updates)
    assert len(chats) == 2
    chat_ids = {c.chat_id for c in chats}
    assert chat_ids == {"100", "200"}


def test_poll_for_chat_id_success():
    """Verify poll_for_chat_id succeeds when an update is returned."""
    mock_client = MagicMock(spec=TelegramClient)
    mock_client.get_updates.return_value = TelegramResponse(
        success=True,
        data=[
            {
                "update_id": 1,
                "message": {
                    "chat": {"id": 987654321, "type": "private", "username": "guardian_user"},
                },
            }
        ],
    )

    progress_calls = []

    def progress_tracker(current, total):
        progress_calls.append((current, total))

    chats = poll_for_chat_id(
        telegram_client=mock_client,
        max_attempts=3,
        poll_interval=0.01,
        progress_callback=progress_tracker,
    )

    assert len(chats) == 1
    assert chats[0].chat_id == "987654321"
    assert len(progress_calls) >= 1
    mock_client.get_updates.assert_called_once()


def test_poll_for_chat_id_bounded_timeout():
    """Verify poll_for_chat_id terminates and returns empty list after max_attempts."""
    mock_client = MagicMock(spec=TelegramClient)
    mock_client.get_updates.return_value = TelegramResponse(
        success=True,
        data=[],  # Empty updates
    )

    chats = poll_for_chat_id(
        telegram_client=mock_client,
        max_attempts=3,
        poll_interval=0.01,
    )

    assert chats == []
    assert mock_client.get_updates.call_count == 3
