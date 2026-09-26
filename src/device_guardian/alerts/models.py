"""Alert data models for Device Guardian.

Encapsulates trigger context, timestamps, captured images, and approximate
geolocation into structured event objects without database dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from device_guardian.location.geolocation import LocationInfo


@dataclass
class AlertEvent:
    """Represents a security/test alert event dispatched by Device Guardian."""

    reason: str
    timestamp: datetime = field(default_factory=datetime.now)
    image_path: Optional[Path] = None
    location: LocationInfo = field(default_factory=LocationInfo)

    @property
    def camera_path(self) -> Optional[Path]:
        """Alias for image_path representing camera capture output."""
        return self.image_path

    @property
    def formatted_timestamp(self) -> str:
        """Return human-readable timestamp (YYYY-MM-DD HH:MM:SS)."""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def format_telegram_message(self) -> str:
        """Generate a formatted notification message for Telegram.

        Adheres strictly to Phase 1 privacy rules:
        - Objective language (never uses terms like 'hacker', 'attacker', 'criminal').
        - Transparently states 'Unavailable' for missing location or camera data.
        - Includes approximate coordinates and map link only when available.
        """
        lines = [
            "🚨 DEVICE GUARDIAN ALERT",
            "",
            f"Reason: {self.reason}",
            "",
            f"Time: {self.formatted_timestamp}",
            "",
            "Location:",
            f"City: {self.location.city}",
            f"Region: {self.location.region}",
            f"Country: {self.location.country}",
        ]

        if self.location.latitude is not None and self.location.longitude is not None:
            lines.extend([
                "",
                "Coordinates (Approximate):",
                f"{self.location.latitude:.6f}, {self.location.longitude:.6f}",
                "",
                "Map:",
                f"{self.location.map_url}",
            ])
        else:
            lines.extend([
                "",
                "Coordinates:",
                "Unavailable",
            ])

        if self.image_path is None:
            lines.extend([
                "",
                "Camera:",
                "Photograph unavailable (camera busy, disabled, or not found)",
            ])

        return "\n".join(lines)
