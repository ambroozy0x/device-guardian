"""Dynamic system tray icon generator for Device Guardian (Phase 5 & 10).

Generates crisp, high-visibility, color-independent status icons using Pillow.
Adheres to Phase 10 Accessibility Standards:
- Never relies on color alone.
- Renders distinct geometric shapes inside the shield for each state:
    RUNNING:  Solid Circle
    STOPPED:  Solid Square
    STARTING: Upward Triangle
    STOPPING: Parallel Pause Bars
    FAILED:   Bold Diagonal Cross (X)
"""

from __future__ import annotations

from typing import Tuple

from PIL import Image, ImageDraw

from device_guardian.runtime.models import RuntimeState

# Distinct, high-contrast palette for state indicators
STATE_COLORS: dict[RuntimeState, tuple[int, int, int]] = {
    RuntimeState.RUNNING: (34, 197, 94),     # Vibrant Green
    RuntimeState.STOPPED: (156, 163, 175),   # Cool Slate Gray
    RuntimeState.STARTING: (59, 130, 246),   # Azure Blue
    RuntimeState.STOPPING: (245, 158, 11),   # Warm Amber
    RuntimeState.FAILED: (239, 68, 68),      # Crimson Red
}

STATE_SHAPES: dict[RuntimeState, str] = {
    RuntimeState.RUNNING: "CIRCLE",
    RuntimeState.STOPPED: "SQUARE",
    RuntimeState.STARTING: "TRIANGLE",
    RuntimeState.STOPPING: "PAUSE_BARS",
    RuntimeState.FAILED: "CROSS",
}


def get_shape_name_for_state(state: RuntimeState) -> str:
    """Return the geometric shape identifier rendered for the state."""
    return STATE_SHAPES.get(state, "CIRCLE")


def create_tray_image(
    state: RuntimeState = RuntimeState.STOPPED,
    size: tuple[int, int] = (64, 64),
) -> Image.Image:
    """Generate a high-resolution PIL icon image representing the runtime state.

    Renders a stylized shield emblem with a color-blind accessible geometric shape:
    - RUNNING: Circle
    - STOPPED: Square
    - STARTING: Triangle
    - STOPPING: Pause Bars
    - FAILED: Diagonal Cross

    Args:
        state: The active RuntimeState to represent visually.
        size: Width and height of the icon image.

    Returns:
        PIL Image object in RGBA format.
    """
    width, height = size
    image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    accent_color = STATE_COLORS.get(state, (156, 163, 175))

    # Outer shield polygon coordinates
    shield_points = [
        (width * 0.5, height * 0.08),    # Top point
        (width * 0.88, height * 0.22),   # Top right
        (width * 0.88, height * 0.60),   # Bottom right curve
        (width * 0.5, height * 0.94),    # Bottom point
        (width * 0.12, height * 0.60),   # Bottom left curve
        (width * 0.12, height * 0.22),   # Top left
    ]

    # Draw dark background shield body with subtle border
    bg_color = (20, 24, 33, 240)
    draw.polygon(shield_points, fill=bg_color, outline=(255, 255, 255, 80), width=2)

    center_x = width * 0.5
    center_y = height * 0.52
    r = width * 0.16

    # Draw color-independent geometric shape inside the shield
    shape = get_shape_name_for_state(state)
    fill_color = (*accent_color, 255)

    if shape == "CIRCLE":
        # Draw outer ring and inner circle
        draw.ellipse(
            [(center_x - r * 1.4, center_y - r * 1.4), (center_x + r * 1.4, center_y + r * 1.4)],
            outline=(*accent_color, 120),
            width=2,
        )
        draw.ellipse(
            [(center_x - r, center_y - r), (center_x + r, center_y + r)],
            fill=fill_color,
        )
    elif shape == "SQUARE":
        # Solid square for stopped state
        draw.rectangle(
            [(center_x - r, center_y - r), (center_x + r, center_y + r)],
            fill=fill_color,
            outline=(255, 255, 255, 100),
            width=1,
        )
    elif shape == "TRIANGLE":
        # Upward pointing triangle for starting state
        triangle_points = [
            (center_x, center_y - r * 1.2),
            (center_x + r * 1.1, center_y + r * 0.9),
            (center_x - r * 1.1, center_y + r * 0.9),
        ]
        draw.polygon(triangle_points, fill=fill_color)
    elif shape == "PAUSE_BARS":
        # Two vertical bars for stopping state
        bar_w = r * 0.4
        draw.rectangle(
            [(center_x - r, center_y - r), (center_x - r + bar_w, center_y + r)],
            fill=fill_color,
        )
        draw.rectangle(
            [(center_x + r - bar_w, center_y - r), (center_x + r, center_y + r)],
            fill=fill_color,
        )
    elif shape == "CROSS":
        # Bold diagonal cross for failed state
        line_w = max(2, int(width * 0.08))
        draw.line(
            [(center_x - r, center_y - r), (center_x + r, center_y + r)],
            fill=fill_color,
            width=line_w,
        )
        draw.line(
            [(center_x - r, center_y + r), (center_x + r, center_y - r)],
            fill=fill_color,
            width=line_w,
        )

    return image
