"""Webcam capture module for Device Guardian.

Safely captures a single still photograph from the configured camera device.
Ensures hardware resources are immediately released and temporary files
are handled securely.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from device_guardian.logger import get_logger

logger = get_logger("camera")


class CameraError(Exception):
    """Raised when camera capture fails due to hardware, permissions, or missing frames."""
    pass


def _get_platform_capture_backend() -> int:
    """Determine the optimal OpenCV video capture backend for the current OS.

    Returns:
        OpenCV VideoCapture backend flag.
    """
    import cv2

    system = platform.system()
    if system == "Windows":
        # DirectShow is typically faster and more reliable on modern Windows
        return cv2.CAP_DSHOW
    elif system == "Darwin":
        # AVFoundation on macOS
        return getattr(cv2, "CAP_AVFOUNDATION", cv2.CAP_ANY)
    elif system == "Linux":
        # Video4Linux2 on Linux
        return getattr(cv2, "CAP_V4L2", cv2.CAP_ANY)
    return cv2.CAP_ANY


def capture_photo(
    camera_index: int = 0,
    output_dir: Optional[Path | str] = None,
    warmup_frames: int = 3,
) -> Path:
    """Capture a single still frame from the webcam and save to a temporary file.

    Hardware lifecycle guarantees:
    - Camera is opened only for the duration of this function call.
    - Resources are always released in a `finally` block.
    - No video or continuous streaming is recorded.

    Args:
        camera_index: Zero-indexed camera device index.
        output_dir: Optional directory to store the capture. If None, uses a secure temp dir.
        warmup_frames: Number of discard frames to read for camera sensor auto-exposure.

    Returns:
        Path to the saved temporary image file.

    Raises:
        CameraError: If the camera cannot be opened, frame capture fails, or image save fails.
    """
    try:
        import cv2
    except ImportError as exc:
        raise CameraError(
            "OpenCV is not installed or available. Please install 'opencv-python'."
        ) from exc

    logger.info("Attempting single-frame capture on camera index %d...", camera_index)

    # Determine destination directory
    if output_dir:
        target_dir = Path(output_dir).resolve()
    else:
        # Use a device_guardian subdirectory in the system temporary directory
        target_dir = Path(tempfile.gettempdir()) / "device_guardian_captures"

    target_dir.mkdir(parents=True, exist_ok=True)

    # Generate timestamped filename: capture_YYYY-MM-DD_HHMMSS.jpg
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_path = target_dir / f"capture_{timestamp}.jpg"

    backend = _get_platform_capture_backend()
    cap = None

    try:
        # Attempt opening with optimal platform backend
        cap = cv2.VideoCapture(camera_index, backend)
        if not cap.isOpened() and backend != cv2.CAP_ANY:
            logger.debug(
                "Camera open with backend %s failed, falling back to CAP_ANY...", backend
            )
            if cap is not None:
                cap.release()
            cap = cv2.VideoCapture(camera_index, cv2.CAP_ANY)

        if not cap.isOpened():
            raise CameraError(
                f"Unable to open camera index {camera_index}. "
                "The device may be disconnected, in use by another application, "
                "or access permission has been denied."
            )

        # Allow camera sensor auto-exposure and white balance to stabilize with a few warm-up frames
        frame = None
        for frame_num in range(max(1, warmup_frames)):
            ret, candidate_frame = cap.read()
            if ret and candidate_frame is not None and candidate_frame.size > 0:
                frame = candidate_frame
            time.sleep(0.05)

        if frame is None or frame.size == 0:
            raise CameraError(
                f"Camera index {camera_index} opened, but failed to capture a valid image frame."
            )

        # Save frame as JPEG
        success = cv2.imwrite(str(output_path), frame)
        if not success or not output_path.exists() or output_path.stat().st_size == 0:
            raise CameraError(
                f"Failed to write captured image to disk at '{output_path}'."
            )

        logger.info("Camera capture successful. Saved to: %s", output_path)
        return output_path

    except CameraError:
        raise
    except Exception as exc:
        raise CameraError(f"Unexpected error during camera capture: {exc}") from exc

    finally:
        # Guarantee immediate hardware release
        if cap is not None:
            try:
                cap.release()
            except Exception as e:
                logger.debug("Exception while releasing camera: %s", e)
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass
        logger.debug("Camera resources released successfully.")
