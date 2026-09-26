"""Tests for Phase 10 system tray accessibility, geometric glyphs, and menu safety."""

from unittest.mock import MagicMock, patch
import pytest
from PIL import Image

from device_guardian.runtime.controller import GuardianRuntime
from device_guardian.runtime.models import RuntimeState
from device_guardian.tray.icons import (
    STATE_SHAPES,
    create_tray_image,
    get_shape_name_for_state,
)
from device_guardian.tray.manager import TrayManager


def test_tray_geometric_shapes_per_state():
    """Verify each runtime state maps to a distinct, color-independent geometric shape."""
    expected = {
        RuntimeState.RUNNING: "CIRCLE",
        RuntimeState.STOPPED: "SQUARE",
        RuntimeState.STARTING: "TRIANGLE",
        RuntimeState.STOPPING: "PAUSE_BARS",
        RuntimeState.FAILED: "CROSS",
    }
    for state, expected_shape in expected.items():
        assert get_shape_name_for_state(state) == expected_shape
        assert STATE_SHAPES[state] == expected_shape

    # Ensure all shapes are unique across the states
    unique_shapes = set(expected.values())
    assert len(unique_shapes) == len(expected)


def test_tray_icon_image_generation_and_dimensions():
    """Verify PIL image generation produces RGBA images with valid dimensions."""
    for state in RuntimeState:
        img_64 = create_tray_image(state=state, size=(64, 64))
        assert isinstance(img_64, Image.Image)
        assert img_64.size == (64, 64)
        assert img_64.mode == "RGBA"

        img_128 = create_tray_image(state=state, size=(128, 128))
        assert img_128.size == (128, 128)


def test_tray_colorblind_shape_distinction():
    """Verify that states remain visually distinguishable when converted to monochrome (grayscale)."""
    # Compare pixel data of images in grayscale
    images_l = {
        state: create_tray_image(state=state, size=(32, 32)).convert("L")
        for state in RuntimeState
    }

    # Verify that different states produce different luminance distributions (not identical masks)
    states = list(RuntimeState)
    for i in range(len(states)):
        for j in range(i + 1, len(states)):
            s1, s2 = states[i], states[j]
            get_data_fn = getattr(images_l[s1], "get_flattened_data", images_l[s1].getdata)
            data1 = list(get_data_fn())
            get_data_fn2 = getattr(images_l[s2], "get_flattened_data", images_l[s2].getdata)
            data2 = list(get_data_fn2())
            assert data1 != data2, f"Monochrome representation of {s1} and {s2} must not be identical"


def test_tray_manager_menu_actions_and_safety():
    """Verify TrayManager sets up safe diagnostic, status, and control menu items."""
    mock_runtime = MagicMock(spec=GuardianRuntime)
    mock_runtime.status.state = RuntimeState.STOPPED
    mock_runtime.is_running.return_value = False

    manager = TrayManager(runtime=mock_runtime)

    with patch("device_guardian.tray.manager.create_startup_manager") as mock_sm_cls:
        mock_sm = MagicMock()
        mock_sm.is_enabled.return_value = True
        mock_sm_cls.return_value = mock_sm

        with patch.object(manager, "is_headless", return_value=False):
            ok = manager.setup_icon()
            assert ok is True
            assert manager._icon is not None

            # Verify tooltip reflects status
            assert "Device Guardian (STOPPED)" in manager._icon.title

            # Test safe callback invocations
            with patch("threading.Thread") as mock_thread:
                manager._on_diagnostics(None, None)
                assert mock_thread.called

                manager._on_update_status(None, None)
                assert mock_thread.called
