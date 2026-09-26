"""Unit tests for camera capture module."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import numpy as np
import pytest

from device_guardian.camera.capture import CameraError, capture_photo


def test_capture_photo_fails_when_camera_cannot_open():
    """Verify CameraError is raised if VideoCapture cannot open device."""
    with patch("cv2.VideoCapture") as mock_vc:
        mock_cap = MagicMock()
        mock_cap.isOpened.return_value = False
        mock_vc.return_value = mock_cap

        with pytest.raises(CameraError) as exc_info:
            capture_photo(camera_index=99)

        assert "Unable to open camera index 99" in str(exc_info.value)
        # Ensure resources were released
        mock_cap.release.assert_called()


def test_capture_photo_fails_when_frame_is_empty():
    """Verify CameraError is raised if camera yields empty frames."""
    with patch("cv2.VideoCapture") as mock_vc:
        mock_cap = MagicMock()
        mock_cap.isOpened.return_value = True
        mock_cap.read.return_value = (False, None)
        mock_vc.return_value = mock_cap

        with pytest.raises(CameraError) as exc_info:
            capture_photo(camera_index=0, warmup_frames=1)

        assert "failed to capture a valid image frame" in str(exc_info.value)
        mock_cap.release.assert_called()


def test_capture_photo_success_flow(tmp_path: Path):
    """Verify successful capture creates file and releases camera."""
    dummy_frame = np.zeros((100, 100, 3), dtype=np.uint8)

    with patch("cv2.VideoCapture") as mock_vc, patch("cv2.imwrite") as mock_imwrite:
        mock_cap = MagicMock()
        mock_cap.isOpened.return_value = True
        mock_cap.read.return_value = (True, dummy_frame)
        mock_vc.return_value = mock_cap

        def fake_imwrite(filepath, img):
            Path(filepath).write_bytes(b"dummy jpeg data")
            return True

        mock_imwrite.side_effect = fake_imwrite

        saved_path = capture_photo(
            camera_index=0,
            output_dir=tmp_path,
            warmup_frames=1,
        )

        assert saved_path.exists()
        assert saved_path.name.startswith("capture_")
        assert saved_path.suffix == ".jpg"
        mock_cap.release.assert_called()
