"""Approximate IP-based geolocation module for Device Guardian.

Queries an external geolocation service to retrieve estimated city, region,
and country coordinates based on the external public IP address.

IMPORTANT PRIVACY & ACCURACY NOTICE:
- Geolocation is strictly APPROXIMATE (city/metro level based on ISP routing).
- This is NOT GPS-level accuracy and must never be represented as precise coordinates.
- No local Wi-Fi networks, Bluetooth beacons, or hardware GPS sensors are accessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import requests
from device_guardian.logger import get_logger

logger = get_logger("location")

DEFAULT_LOCATION_API = "https://ipapi.co/json/"


@dataclass
class LocationInfo:
    """Represents approximate geolocation information derived from public IP."""

    ip: str = "Unavailable"
    city: str = "Unavailable"
    region: str = "Unavailable"
    country: str = "Unavailable"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_available: bool = False
    raw_data: Optional[dict[str, Any]] = None

    @property
    def map_url(self) -> Optional[str]:
        """Generate a Google Maps link if valid coordinates are present."""
        if self.latitude is not None and self.longitude is not None:
            return f"https://maps.google.com/?q={self.latitude:.6f},{self.longitude:.6f}"
        return None

    def summary_lines(self) -> list[str]:
        """Format location as human-readable lines for alert messages."""
        lines = [
            f"City: {self.city}",
            f"Region: {self.region}",
            f"Country: {self.country}",
        ]
        if self.latitude is not None and self.longitude is not None:
            lines.append(f"\nCoordinates (Approximate):\n{self.latitude:.6f}, {self.longitude:.6f}")
            lines.append(f"\nMap:\n{self.map_url}")
        else:
            lines.append("\nCoordinates:\nUnavailable")
        return lines


def _parse_location_payload(data: dict[str, Any]) -> LocationInfo:
    """Parse JSON payload from standard IP geolocation APIs into LocationInfo.

    Supports common providers such as ipapi.co and ip-api.com.
    """
    # Extract IP
    ip = str(data.get("ip") or data.get("query") or "Unavailable")

    # Extract City, Region, Country
    city = str(data.get("city") or "Unavailable")
    region = str(data.get("region") or data.get("regionName") or "Unavailable")
    country = str(data.get("country_name") or data.get("country") or "Unavailable")

    # Extract Latitude and Longitude safely
    lat_raw = data.get("latitude") if "latitude" in data else data.get("lat")
    lon_raw = data.get("longitude") if "longitude" in data else data.get("lon")

    latitude: Optional[float] = None
    longitude: Optional[float] = None

    if lat_raw is not None:
        try:
            latitude = float(lat_raw)
        except (ValueError, TypeError):
            latitude = None

    if lon_raw is not None:
        try:
            longitude = float(lon_raw)
        except (ValueError, TypeError):
            longitude = None

    # Determine if we got at least some meaningful location data
    has_meaningful_data = (
        city != "Unavailable" or country != "Unavailable" or latitude is not None
    )

    return LocationInfo(
        ip=ip,
        city=city,
        region=region,
        country=country,
        latitude=latitude,
        longitude=longitude,
        is_available=has_meaningful_data,
        raw_data=data,
    )


def get_approximate_location(
    api_url: str = DEFAULT_LOCATION_API,
    timeout: float = 10.0,
) -> LocationInfo:
    """Retrieve approximate IP-based location via an HTTP REST endpoint.

    Fails gracefully without raising exceptions; on any error, returns
    a LocationInfo instance marked as unavailable.

    Args:
        api_url: The IP geolocation API endpoint.
        timeout: Request timeout in seconds.

    Returns:
        LocationInfo containing approximate coordinates or fallback 'Unavailable' data.
    """
    logger.info("Querying approximate location from: %s", api_url)

    # Some APIs require a User-Agent header to prevent 403 blocks
    headers = {
        "User-Agent": "DeviceGuardian-AlertSystem/0.1.0 (Personal Security Alert Client)"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            logger.warning(
                "Location lookup returned non-200 status code: %d", response.status_code
            )
            return LocationInfo()

        data = response.json()
        if not isinstance(data, dict):
            logger.warning("Location API returned non-dictionary JSON: %s", type(data))
            return LocationInfo()

        # Check for error fields in API response (e.g., ipapi.co error flag or ip-api fail)
        if data.get("error") is True or data.get("status") == "fail":
            reason = data.get("reason") or data.get("message") or "Unknown API error"
            logger.warning("Location API indicated an error: %s", reason)
            return LocationInfo()

        location_info = _parse_location_payload(data)
        logger.info(
            "Approximate location retrieved: %s, %s, %s (Lat: %s, Lon: %s)",
            location_info.city,
            location_info.region,
            location_info.country,
            location_info.latitude,
            location_info.longitude,
        )
        return location_info

    except requests.exceptions.Timeout:
        logger.warning("Location lookup timed out after %.1f seconds.", timeout)
        return LocationInfo()
    except requests.exceptions.ConnectionError as exc:
        logger.warning("Network connection error during location lookup: %s", exc)
        return LocationInfo()
    except requests.exceptions.RequestException as exc:
        logger.warning("HTTP request failed during location lookup: %s", exc)
        return LocationInfo()
    except Exception as exc:
        logger.warning("Unexpected error during location lookup: %s", exc)
        return LocationInfo()
