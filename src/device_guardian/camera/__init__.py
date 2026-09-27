"""Camera module for Device Guardian."""

from .capture import capture_photo, capture_photos, CameraError

__all__ = ["capture_photo", "capture_photos", "CameraError"]
