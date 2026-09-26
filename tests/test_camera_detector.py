"""Unit tests for camera detection, enumeration, and lifecycle testing."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import numpy as np
import pytest

from device_guardian.camera.capture import CameraError
from device_guardian.setup.camera_detector import (
    detect_available_cameras,
    get_permission_guidance,
    verify_camera_lifecycle,
)


@patch("cv2.VideoCapture")
def test_detect_available_cameras_success(mock_vc):
    """Verify detect_available_cameras correctly identifies functional cameras."""
    dummy_frame = np.zeros((100, 100, 3), dtype=np.uint8)

    # Simulate camera 0 working, camera 1 failing to open
    def side_effect(idx, *args, **kwargs):
        cap = MagicMock()
        if idx == 0:
            cap.isOpened.return_value = True
            cap.read.return_value = (True, dummy_frame)
        else:
            cap.isOpened.return_value = False
            cap.read.return_value = (False, None)
        return cap

    mock_vc.side_effect = side_effect

    found = detect_available_cameras(max_to_check=2)
    assert found == [0]


@patch("cv2.VideoCapture")
def test_detect_available_cameras_handles_empty_frame(mock_vc):
    """Verify camera that opens but fails frame read is not marked available."""
    cap = MagicMock()
    cap.isOpened.return_value = True
    cap.read.return_value = (False, None)
    mock_vc.return_value = cap

    found = detect_available_cameras(max_to_check=1)
    assert found == []


@patch("device_guardian.setup.camera_detector.capture_photo")
def test_test_camera_lifecycle_success(mock_capture, tmp_path: Path):
    """Verify camera lifecycle test flow and temp image cleanup."""
    temp_img = tmp_path / "test_snapshot.jpg"
    temp_img.write_bytes(b"dummy image data")
    mock_capture.return_value = temp_img

    success, steps, err = verify_camera_lifecycle(camera_index=0)
    assert success is True
    assert err is None
    assert any("Camera hardware released" in step for step in steps)
    # Temporary test snapshot should be deleted
    assert not temp_img.exists()


@patch("device_guardian.setup.camera_detector.capture_photo")
def test_test_camera_lifecycle_failure(mock_capture):
    """Verify camera failure is handled gracefully with error report."""
    mock_capture.side_effect = CameraError("Device in use by another app")

    success, steps, err = verify_camera_lifecycle(camera_index=0)
    assert success is False
    assert "Device in use" in str(err)


def test_get_permission_guidance():
    """Verify permission guidance provides non-empty instructions."""
    guidance = get_permission_guidance()
    assert isinstance(guidance, str)
    assert len(guidance) > 20
