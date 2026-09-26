"""Tests for dynamic tray icon generator and tray manager (Phase 5)."""

from PIL import Image
import pytest

from device_guardian.config import AppConfig
from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.tray.icons import STATE_COLORS, create_tray_image
from device_guardian.tray.manager import TrayManager


@pytest.fixture
def mock_runtime():
    config = AppConfig(
        telegram_bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        telegram_chat_id="123456789",
    )
    return GuardianRuntime(config=config)


def test_tray_icon_generation_for_all_states():
    """Verify create_tray_image produces valid PIL Image in RGBA format for all states."""
    for state in RuntimeState:
        img = create_tray_image(state=state, size=(64, 64))
        assert isinstance(img, Image.Image)
        assert img.size == (64, 64)
        assert img.mode == "RGBA"
        # Ensure image is not completely transparent / blank
        extrema = img.getextrema()
        assert extrema[3][1] > 0  # Alpha channel has opaque pixels


def test_tray_manager_initialization(mock_runtime):
    """Verify TrayManager initializes with runtime reference."""
    tray = TrayManager(runtime=mock_runtime)
    assert tray.runtime == mock_runtime
    assert tray._icon is None


def test_tray_manager_setup_icon(mock_runtime):
    """Verify setup_icon configures pystray Icon and dynamic menu."""
    tray = TrayManager(runtime=mock_runtime)
    # In Windows test environment, setup_icon should succeed
    success = tray.setup_icon()
    if not tray.is_headless():
        assert success is True
        assert tray._icon is not None
        assert "Device Guardian" in tray._icon.title
    else:
        assert success is False
