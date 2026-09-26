"""Setup and first-run configuration module for Device Guardian."""

from .camera_detector import detect_available_cameras, verify_camera_lifecycle
from .chat_detector import DetectedChat, extract_chats_from_updates, poll_for_chat_id
from .status import SetupStatus, determine_setup_status
from .storage import format_env_file, safe_save_config
from .wizard import SetupWizard, run_setup_wizard

__all__ = [
    "SetupWizard",
    "run_setup_wizard",
    "SetupStatus",
    "determine_setup_status",
    "safe_save_config",
    "format_env_file",
    "poll_for_chat_id",
    "extract_chats_from_updates",
    "DetectedChat",
    "detect_available_cameras",
    "verify_camera_lifecycle",
]
