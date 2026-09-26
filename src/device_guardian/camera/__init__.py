"""Camera module for Device Guardian."""

from .capture import capture_photo, CameraError

__all__ = ["capture_photo", "CameraError"]
