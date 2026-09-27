"""Core Alert Pipeline for Device Guardian.

Coordinates configuration validation, camera capture, approximate geolocation,
message assembly, and Telegram dispatch into a unified, reusable workflow.
Designed to be invoked by future automated detection triggers (Phase 2+).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from device_guardian.alerts.models import AlertEvent
from device_guardian.camera.capture import CameraError, capture_photo, capture_photos
from device_guardian.config import AppConfig, ConfigurationError, load_config
from device_guardian.location.geolocation import LocationInfo, get_approximate_location
from device_guardian.logger import get_logger
from device_guardian.telegram.bot import TelegramClient, TelegramResponse

logger = get_logger("pipeline")


@dataclass
class AlertResult:
    """Detailed outcome of an alert pipeline execution."""

    success: bool
    reason: str
    camera_success: bool = False
    location_success: bool = False
    telegram_success: bool = False
    event: Optional[AlertEvent] = None
    error_message: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """User-friendly summary of the pipeline execution."""
        status = "SUCCESS" if self.success else "FAILED"
        cam_status = "Captured" if self.camera_success else "Unavailable"
        loc_status = "Acquired" if self.location_success else "Unavailable"
        tg_status = "Delivered" if self.telegram_success else "Failed"

        lines = [
            f"Alert Pipeline Execution: {status}",
            f"- Camera: {cam_status}",
            f"- Geolocation: {loc_status}",
            f"- Telegram Alert: {tg_status}",
        ]
        if self.error_message:
            lines.append(f"- Error: {self.error_message}")
        return "\n".join(lines)


def _cleanup_temporary_image(image_path: Optional[Path]) -> None:
    """Safely delete temporary capture image to protect privacy.

    Args:
        image_path: Path to the image file to delete.
    """
    if image_path is None:
        return

    try:
        path = Path(image_path)
        if path.is_file():
            path.unlink()
            logger.info("Temporary image successfully deleted: %s", path)
    except Exception as exc:
        logger.warning(
            "WARNING: Temporary image could not be deleted from '%s': %s",
            image_path,
            exc,
        )


def trigger_alert(
    reason: str = "Manual Test Alert",
    config: Optional[AppConfig] = None,
    cleanup_image_on_success: bool = True,
    output_dir: Optional[Path | str] = None,
) -> AlertResult:
    """Execute the complete Device Guardian alert pipeline.

    Workflow:
        1. Validate local configuration.
        2. Record alert timestamp.
        3. Attempt single-frame webcam capture.
        4. Query approximate IP geolocation.
        5. Build AlertEvent metadata and message.
        6. Dispatch notification to Telegram (photo + metadata).
        7. Clean up temporary photo upon successful delivery.
        8. Return structured AlertResult.

    Args:
        reason: Description of the trigger event.
        config: Optional pre-loaded AppConfig instance.
        cleanup_image_on_success: If True, delete local photo after Telegram transmission.
        output_dir: Directory for temporary captures (defaults to system temp).

    Returns:
        AlertResult containing diagnostic information and status.
    """
    logger.info("Initiating alert pipeline with reason: '%s'", reason)
    timestamp = datetime.now()

    # Step 1: Validate configuration
    if config is None:
        try:
            config = load_config()
        except ConfigurationError as exc:
            logger.error("Configuration loading failed: %s", exc)
            return AlertResult(
                success=False,
                reason=reason,
                error_message=f"Configuration error: {exc}",
            )

    try:
        config.validate()
    except ConfigurationError as exc:
        logger.error("Configuration validation failed: %s", exc)
        return AlertResult(
            success=False,
            reason=reason,
            error_message=str(exc),
        )

    # Step 2: Initialize Telegram client if alerts enabled
    telegram_client: Optional[TelegramClient] = None
    if getattr(config, "telegram_alert_enabled", True):
        telegram_client = TelegramClient(
            bot_token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            timeout=config.request_timeout_seconds,
        )

    # Step 3: Capture webcam photograph(s)
    captured_image_path: Optional[Path] = None
    captured_image_paths: list[Path] = []
    camera_success = False
    if getattr(config, "camera_alert_enabled", True):
        photo_count = max(1, getattr(config, "camera_photo_count", 3))
        try:
            captured_image_path = capture_photo(
                camera_index=config.camera_index,
                output_dir=output_dir,
            )
            captured_image_paths = [captured_image_path] if captured_image_path else []
            camera_success = True
            logger.info("Primary webcam photo captured at: %s", captured_image_path)

            if photo_count > 1 and captured_image_path:
                try:
                    extra_photos = capture_photos(
                        camera_index=config.camera_index,
                        count=photo_count - 1,
                        output_dir=output_dir,
                    )
                    captured_image_paths.extend(extra_photos)
                    logger.info("Captured %d additional burst photo(s).", len(extra_photos))
                except Exception as burst_exc:
                    logger.debug("Additional burst capture skipped: %s", burst_exc)

        except CameraError as exc:
            logger.warning("Camera capture unavailable: %s", exc)
            captured_image_path = None
            captured_image_paths = []
            camera_success = False
    else:
        logger.info("Camera capture skipped (CAMERA_ALERT_ENABLED=False).")

    # Step 4: Obtain approximate or exact geolocation
    location_info: LocationInfo
    if getattr(config, "location_alert_enabled", True):
        try:
            location_info = get_approximate_location(
                api_url=config.location_api_url,
                timeout=config.request_timeout_seconds,
                exact_latitude=getattr(config, "exact_latitude", None),
                exact_longitude=getattr(config, "exact_longitude", None),
                exact_location_name=getattr(config, "exact_location_name", ""),
            )
            location_success = location_info.is_available
        except Exception as exc:
            logger.warning("Unexpected geolocation exception: %s", exc)
            location_info = LocationInfo()
            location_success = False
    else:
        logger.info("Geolocation skipped (LOCATION_ALERT_ENABLED=False).")
        location_info = LocationInfo()
        location_success = False

    # Step 5: Build alert event metadata
    event = AlertEvent(
        reason=reason,
        timestamp=timestamp,
        image_path=captured_image_path,
        image_paths=captured_image_paths,
        location=location_info,
    )
    formatted_message = event.format_telegram_message()

    # Step 6: Dispatch to Telegram
    telegram_success = False
    error_message: Optional[str] = None
    delivery_details: dict[str, Any] = {}

    if not getattr(config, "telegram_alert_enabled", True):
        logger.info("Telegram dispatch skipped (TELEGRAM_ALERT_ENABLED=False).")
        telegram_success = True
        delivery_details["skipped"] = "TELEGRAM_ALERT_ENABLED=False"
    elif captured_image_path is not None and captured_image_path.is_file():
        # Deliver photo with full metadata as caption
        logger.info("Sending photo alert with metadata caption to Telegram...")
        photo_resp = telegram_client.send_photo(
            photo_path=captured_image_path,
            caption=formatted_message,
        )
        delivery_details["photo_response"] = photo_resp

        if photo_resp.success:
            telegram_success = True
            logger.info("Telegram alert with primary photograph delivered successfully.")
            # Dispatch any additional burst photos
            for idx, extra_path in enumerate(captured_image_paths[1:], start=2):
                try:
                    if extra_path and extra_path.is_file():
                        burst_caption = f"📷 Snapshot {idx}/{len(captured_image_paths)} (Intrusion Burst Capture)"
                        telegram_client.send_photo(
                            photo_path=extra_path,
                            caption=burst_caption,
                        )
                except Exception as extra_err:
                    logger.debug("Extra burst photo delivery skipped: %s", extra_err)
        else:
            logger.warning(
                "Photo delivery failed (%s). Attempting fallback text message...",
                photo_resp.error_message,
            )
            # Fallback to plain text message so the alert is not lost
            msg_resp = telegram_client.send_message(text=formatted_message)
            delivery_details["message_fallback_response"] = msg_resp
            if msg_resp.success:
                telegram_success = True
                error_message = (
                    f"Photo upload failed ({photo_resp.error_message}), "
                    f"but text alert was delivered."
                )
            else:
                telegram_success = False
                error_message = photo_resp.error_message or msg_resp.error_message
    else:
        # Camera was unavailable; send text message
        logger.info("Camera unavailable; dispatching text-only alert to Telegram...")
        msg_resp = telegram_client.send_message(text=formatted_message)
        delivery_details["message_response"] = msg_resp
        if msg_resp.success:
            telegram_success = True
            logger.info("Telegram text alert delivered successfully.")
        else:
            telegram_success = False
            error_message = msg_resp.error_message

    # Step 7: Clean up temporary resources
    if telegram_success and cleanup_image_on_success and captured_image_paths:
        for img_path in captured_image_paths:
            _cleanup_temporary_image(img_path)
    elif not telegram_success and captured_image_path:
        logger.info(
            "Retaining temporary capture for diagnostic inspection at: %s",
            captured_image_path,
        )

    # Step 8: Return structured result
    return AlertResult(
        success=telegram_success,
        reason=reason,
        camera_success=camera_success,
        location_success=location_success,
        telegram_success=telegram_success,
        event=event,
        error_message=error_message,
        details=delivery_details,
    )
