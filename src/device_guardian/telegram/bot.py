"""Telegram Bot API integration client for Device Guardian.

Communicates with Telegram Bot API over HTTPS to deliver alert messages
and photographs. Never leaks the bot token in logs, exceptions, or error messages.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from device_guardian.logger import get_logger

logger = get_logger("telegram")

_TELEGRAM_BASE_URL = "https://api.telegram.org"


@dataclass
class TelegramResponse:
    """Structured response from Telegram API operations."""

    success: bool
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    data: Optional[dict[str, Any]] = None

    def __repr__(self) -> str:
        return (
            f"TelegramResponse(success={self.success}, "
            f"status_code={self.status_code}, "
            f"error_message={repr(self.error_message)})"
        )


class TelegramClient:
    """Client for dispatching notifications via the official Telegram Bot API."""

    def __init__(
        self,
        bot_token: str | Any,
        chat_id: str | Any,
        timeout: float = 10.0,
        max_retries: int = 2,
        retry_backoff: float = 0.25,
    ) -> None:
        """Initialize the Telegram Bot client.

        Args:
            bot_token: Secret bot token obtained from @BotFather.
            chat_id: Destination chat/user ID.
            timeout: Network request timeout in seconds.
            max_retries: Maximum number of retry attempts for transient errors.
            retry_backoff: Base exponential backoff delay in seconds.
        """
        if hasattr(bot_token, "get_secret_value"):
            raw_token = bot_token.get_secret_value()
        else:
            raw_token = str(bot_token or "")

        if hasattr(chat_id, "get_secret_value"):
            raw_chat_id = chat_id.get_secret_value()
        else:
            raw_chat_id = str(chat_id or "")

        if not raw_token or not raw_token.strip():
            raise ValueError("Telegram bot token cannot be empty.")
        if not raw_chat_id or not raw_chat_id.strip():
            raise ValueError("Telegram chat ID cannot be empty.")

        self._token = raw_token.strip()
        self._chat_id = raw_chat_id.strip()
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff

        try:
            from device_guardian.security.redactor import get_redactor
            get_redactor().register_secret(self._token)
            get_redactor().register_secret(self._chat_id)
        except Exception:
            pass

    @property
    def _base_url(self) -> str:
        """Construct the base endpoint URL for this bot."""
        return f"{_TELEGRAM_BASE_URL}/bot{self._token}"

    def _sanitize(self, message: str) -> str:
        """Scrub token and sensitive secrets from any exception or error message."""
        if not message:
            return message
        try:
            from device_guardian.security.redactor import get_redactor
            return get_redactor().redact(message)
        except Exception:
            return message.replace(self._token, "[REDACTED_TOKEN]")

    def _execute_with_retry(
        self,
        request_func: Callable[[], requests.Response],
        op_name: str,
        timeout_error_msg: str,
        reset_func: Optional[Callable[[], None]] = None,
    ) -> TelegramResponse:
        """Execute an HTTP request with bounded retries for transient errors.

        Retries on:
        - HTTP 429 (rate limited)
        - HTTP 5xx (server error)
        - requests.exceptions.Timeout
        - requests.exceptions.ConnectionError / RequestException

        Does NOT retry on:
        - HTTP 400 (bad request, e.g. invalid chat ID)
        - HTTP 401 (unauthorized, invalid bot token)
        - HTTP 403 (forbidden, bot blocked)
        """
        last_error_message = ""
        for attempt in range(self._max_retries + 1):
            if attempt > 0 and reset_func:
                try:
                    reset_func()
                except Exception:
                    pass
            try:
                response = request_func()
                # If success (2xx) or permanent client error (4xx except 429), return immediately without retrying
                if response.status_code < 400 or (response.status_code < 500 and response.status_code != 429):
                    return self._handle_response(response)

                # Transient HTTP error (429 or 5xx)
                if attempt < self._max_retries:
                    backoff = self._retry_backoff * (2 ** attempt)
                    logger.warning(
                        "Transient HTTP %d during %s (attempt %d/%d). Retrying in %.2fs...",
                        response.status_code,
                        op_name,
                        attempt + 1,
                        self._max_retries + 1,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue
                else:
                    return self._handle_response(response)

            except requests.exceptions.Timeout:
                last_error_message = timeout_error_msg
                if attempt < self._max_retries:
                    backoff = self._retry_backoff * (2 ** attempt)
                    logger.warning(
                        "%s timed out (attempt %d/%d). Retrying in %.2fs...",
                        op_name,
                        attempt + 1,
                        self._max_retries + 1,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue
                else:
                    logger.error(timeout_error_msg)
                    return TelegramResponse(success=False, error_message=timeout_error_msg)

            except requests.exceptions.RequestException as exc:
                sanitized_err = self._sanitize(str(exc))
                last_error_message = f"Network error: {sanitized_err}"
                if attempt < self._max_retries:
                    backoff = self._retry_backoff * (2 ** attempt)
                    logger.warning(
                        "%s network error: %s (attempt %d/%d). Retrying in %.2fs...",
                        op_name,
                        sanitized_err,
                        attempt + 1,
                        self._max_retries + 1,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue
                else:
                    logger.error("Telegram network error: %s", sanitized_err)
                    return TelegramResponse(success=False, error_message=last_error_message)

        return TelegramResponse(success=False, error_message=last_error_message or "Unknown failure after retries.")

    def verify_credentials(self) -> TelegramResponse:
        """Verify the bot token by calling getMe.

        Returns:
            TelegramResponse indicating whether the bot credentials are valid.
        """
        url = f"{self._base_url}/getMe"
        logger.debug("Verifying Telegram bot token credentials...")
        return self._execute_with_retry(
            request_func=lambda: requests.get(url, timeout=self._timeout),
            op_name="Verifying Telegram credentials",
            timeout_error_msg=f"Network error verifying Telegram credentials: Request timed out after {self._timeout:.1f}s",
        )

    def get_updates(
        self,
        offset: Optional[int] = None,
        limit: int = 10,
        timeout: int = 5,
    ) -> TelegramResponse:
        """Fetch incoming updates from the Telegram Bot API.

        Used strictly during setup wizard to detect the user's chat ID.
        Communicates over HTTPS, applies request timeouts, and sanitizes errors.

        Args:
            offset: Identifier of the first update to be returned.
            limit: Maximum number of updates to retrieve (1-100).
            timeout: Long polling timeout in seconds for Telegram server.

        Returns:
            TelegramResponse with list of update dictionaries or error details.
        """
        url = f"{self._base_url}/getUpdates"
        params: dict[str, Any] = {
            "limit": max(1, min(limit, 100)),
            "timeout": timeout,
        }
        if offset is not None:
            params["offset"] = offset

        logger.debug("Querying Telegram getUpdates...")

        try:
            client_timeout = max(self._timeout, float(timeout) + 5.0)
            response = requests.get(url, params=params, timeout=client_timeout)
            return self._handle_response(response)
        except requests.exceptions.Timeout:
            err = f"Telegram getUpdates request timed out."
            logger.debug(err)
            return TelegramResponse(success=False, error_message=err)
        except requests.exceptions.RequestException as exc:
            sanitized_err = self._sanitize(str(exc))
            logger.error("Telegram getUpdates network error: %s", sanitized_err)
            return TelegramResponse(
                success=False,
                error_message=f"Network error: {sanitized_err}",
            )

    def send_message(
        self,
        text: str,
        parse_mode: Optional[str] = None,
    ) -> TelegramResponse:
        """Send a plain text message to the configured Telegram chat.

        Args:
            text: Message body to send.
            parse_mode: Optional Telegram parse mode (e.g. 'HTML', 'MarkdownV2').

        Returns:
            TelegramResponse with delivery result.
        """
        url = f"{self._base_url}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": self._chat_id,
            "text": text,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode

        logger.info("Sending Telegram text message to configured chat...")

        timeout_msg = f"Telegram request timed out after {self._timeout:.1f}s."
        result = self._execute_with_retry(
            request_func=lambda: requests.post(url, json=payload, timeout=self._timeout),
            op_name="Telegram message delivery",
            timeout_error_msg=timeout_msg,
        )
        if result.success:
            logger.info("Telegram message delivered successfully.")
        else:
            logger.error("Telegram message delivery failed: %s", result.error_message)
        return result

    def send_test_notification(self, custom_message: Optional[str] = None) -> TelegramResponse:
        """Send an explicit test notification to the configured Telegram destination.

        Returns:
            TelegramResponse with status, error_message, and data.
        """
        message = (
            custom_message
            or "🔔 <b>Device Guardian — Test Notification</b>\n\n"
               "This is a verified test alert confirming your Telegram notification pipeline "
               "is operational.\n\n"
               "<i>No intrusion detected. This was triggered on demand.</i>"
        )
        return self.send_message(text=message, parse_mode="HTML")

    def send_photo(
        self,
        photo_path: Path | str,
        caption: Optional[str] = None,
        parse_mode: Optional[str] = None,
    ) -> TelegramResponse:
        """Send a photograph with an optional caption to the configured chat.

        Args:
            photo_path: Path to the image file to send.
            caption: Optional caption text accompanying the photo.
            parse_mode: Optional parse mode for the caption.

        Returns:
            TelegramResponse with delivery result.
        """
        path = Path(photo_path).resolve()
        if not path.is_file():
            err = f"Image file not found at '{path}'."
            logger.error(err)
            return TelegramResponse(success=False, error_message=err)

        url = f"{self._base_url}/sendPhoto"
        data: dict[str, Any] = {"chat_id": self._chat_id}
        if caption:
            # Telegram captions are limited to 1024 characters
            if len(caption) > 1024:
                logger.warning(
                    "Caption exceeds 1024 characters (%d chars); truncating caption.",
                    len(caption),
                )
                caption = caption[:1020] + "..."
            data["caption"] = caption
        if parse_mode:
            data["parse_mode"] = parse_mode

        logger.info(
            "Uploading photo '%s' to configured Telegram chat...", path.name
        )

        with open(path, "rb") as photo_file:
            def _upload() -> requests.Response:
                files = {"photo": (path.name, photo_file, "image/jpeg")}
                return requests.post(
                    url,
                    data=data,
                    files=files,
                    timeout=self._timeout * 2,  # Give upload extra time
                )

            result = self._execute_with_retry(
                request_func=_upload,
                op_name="Telegram photo upload",
                timeout_error_msg="Telegram photo upload timed out.",
                reset_func=lambda: photo_file.seek(0),
            )

        if result.success:
            logger.info("Telegram photo delivered successfully.")
        else:
            logger.error("Telegram photo upload failed: %s", result.error_message)
        return result

    def _handle_response(self, response: requests.Response) -> TelegramResponse:
        """Parse Telegram API response and detect errors securely."""
        status_code = response.status_code
        try:
            data = response.json()
        except Exception:
            data = None

        if status_code == 200 and isinstance(data, dict) and data.get("ok") is True:
            return TelegramResponse(
                success=True,
                status_code=status_code,
                data=data.get("result"),
            )

        # Handle failure cases
        error_description = "Unknown Telegram API error"
        if isinstance(data, dict) and "description" in data:
            error_description = self._sanitize(str(data["description"]))
        elif response.text:
            error_description = self._sanitize(response.text[:200])

        if status_code == 401:
            friendly_msg = f"Unauthorized (401): Invalid Telegram Bot Token. ({error_description})"
        elif status_code == 400:
            friendly_msg = f"Bad Request (400): {error_description}. Please verify your chat ID."
        elif status_code == 403:
            friendly_msg = (
                f"Forbidden (403): Bot was blocked by user or cannot initiate conversation. "
                f"Make sure you clicked 'Start' in your chat with the bot."
            )
        elif status_code == 429:
            friendly_msg = f"Too Many Requests (429): Rate limited by Telegram. ({error_description})"
        else:
            friendly_msg = f"HTTP {status_code}: {error_description}"

        return TelegramResponse(
            success=False,
            status_code=status_code,
            error_message=friendly_msg,
            data=data,
        )
