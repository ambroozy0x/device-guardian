"""Camera detection and lifecycle verification for Setup Wizard.

Enumerates available video devices conservatively and tests single-frame
capture while strictly ensuring hardware handles are immediately freed.
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Optional

from device_guardian.camera.capture import (
    CameraError,
    _get_platform_capture_backend,
    capture_photo,
)
from device_guardian.logger import get_logger

logger = get_logger("setup.camera_detector")


def detect_available_cameras(max_to_check: int = 4) -> list[int]:
    """Conservatively enumerate working webcam device indexes.

    Checks device indexes sequentially. Immediately releases any opened
    devices to prevent blocking other applications.

    Args:
        max_to_check: Maximum number of device indexes to probe (0 to max_to_check - 1).

    Returns:
        List of working device index integers (e.g. [0, 1]).
    """
    try:
        import cv2
    except ImportError:
        logger.warning("OpenCV not installed; camera detection unavailable.")
        return []

    available: list[int] = []
    backend = _get_platform_capture_backend()

    for idx in range(max_to_check):
        cap = None
        try:
            cap = cv2.VideoCapture(idx, backend)
            if not cap.isOpened() and backend != cv2.CAP_ANY:
                if cap is not None:
                    cap.release()
                cap = cv2.VideoCapture(idx, cv2.CAP_ANY)

            if cap.isOpened():
                # Attempt reading a test frame to verify device actually streams
                ret, frame = cap.read()
                if ret and frame is not None and frame.size > 0:
                    available.append(idx)
                    logger.debug("Camera index %d is functional.", idx)
                else:
                    logger.debug("Camera index %d opened but returned no frame.", idx)
        except Exception as exc:
            logger.debug("Camera index %d check encountered error: %s", idx, exc)
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass

    try:
        cv2.destroyAllWindows()
    except Exception:
        pass

    return available


def verify_camera_lifecycle(
    camera_index: int,
) -> tuple[bool, list[str], Optional[str]]:
    """Execute a single-frame capture test and verify camera lifecycle.

    Reuses existing Phase 1 capture_photo to ensure zero code duplication.
    Cleans up temporary test snapshot immediately upon test completion.

    Args:
        camera_index: Hardware device index to test.

    Returns:
        Tuple of (success: bool, steps_log: list[str], error_message: Optional[str]).
    """
    steps: list[str] = []
    saved_path: Optional[Path] = None

    try:
        steps.append("Opening camera...")
        saved_path = capture_photo(camera_index=camera_index, warmup_frames=2)
        steps.append("Camera opened successfully.")
        steps.append("Frame captured.")
        steps.append("Image encoded and verified.")
        steps.append("Camera hardware released.")

        # Clean up temporary test photo
        if saved_path and saved_path.is_file():
            saved_path.unlink()
            steps.append("Temporary test image cleaned up.")

        return True, steps, None

    except CameraError as exc:
        steps.append(f"Camera failure: {exc}")
        return False, steps, str(exc)
    except Exception as exc:
        steps.append(f"Unexpected camera error: {exc}")
        return False, steps, str(exc)
    finally:
        # Guarantee cleanup in case of unexpected exception
        if saved_path and saved_path.is_file():
            try:
                saved_path.unlink()
            except Exception:
                pass


def get_permission_guidance() -> str:
    """Return platform-specific instructions for granting camera access."""
    system = platform.system()
    if system == "Windows":
        return (
            "Windows Camera Permission Guide:\n"
            "1. Open Windows Settings > Privacy & security > Camera.\n"
            "2. Ensure 'Camera access' is turned ON.\n"
            "3. Ensure 'Let desktop apps access your camera' is turned ON."
        )
    elif system == "Darwin":
        return (
            "macOS Camera Permission Guide:\n"
            "1. Open System Settings > Privacy & Security > Camera.\n"
            "2. Ensure Terminal or your Python environment has camera permissions enabled."
        )
    elif system == "Linux":
        return (
            "Linux Camera Permission Guide:\n"
            "1. Ensure your user account is in the 'video' group:\n"
            "   sudo usermod -aG video $USER\n"
            "2. Log out and log back in to apply group changes."
        )
    return "Please check your operating system settings to ensure camera permissions are granted."
