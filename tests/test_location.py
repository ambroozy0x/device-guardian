"""Unit tests for approximate IP geolocation module."""

from unittest.mock import MagicMock, patch
import pytest
import requests

from device_guardian.location.geolocation import (
    LocationInfo,
    _parse_location_payload,
    get_approximate_location,
)


def test_location_info_properties_with_valid_coordinates():
    """Verify Map URL and summary lines with valid latitude and longitude."""
    loc = LocationInfo(
        ip="203.0.113.1",
        city="Kochi",
        region="Kerala",
        country="India",
        latitude=9.9312,
        longitude=76.2673,
        is_available=True,
    )

    assert loc.map_url == "https://maps.google.com/?q=9.931200,76.267300"
    summary = "\n".join(loc.summary_lines())
    assert "City: Kochi" in summary
    assert "Region: Kerala" in summary
    assert "Country: India" in summary
    assert "9.931200, 76.267300" in summary
    assert "https://maps.google.com/?q=9.931200,76.267300" in summary


def test_location_info_properties_without_coordinates():
    """Verify Map URL is None and summary indicates Unavailable when coordinates missing."""
    loc = LocationInfo(
        city="Kochi",
        region="Kerala",
        country="India",
        latitude=None,
        longitude=None,
        is_available=True,
    )

    assert loc.map_url is None
    summary = "\n".join(loc.summary_lines())
    assert "Coordinates:\nUnavailable" in summary


def test_parse_location_payload_ipapi_format():
    """Verify parsing standard ipapi.co response schema."""
    data = {
        "ip": "198.51.100.5",
        "city": "London",
        "region": "England",
        "country_name": "United Kingdom",
        "latitude": 51.5074,
        "longitude": -0.1278,
    }
    loc = _parse_location_payload(data)
    assert loc.ip == "198.51.100.5"
    assert loc.city == "London"
    assert loc.region == "England"
    assert loc.country == "United Kingdom"
    assert loc.latitude == pytest.approx(51.5074)
    assert loc.longitude == pytest.approx(-0.1278)
    assert loc.is_available is True


def test_parse_location_payload_ip_api_format():
    """Verify parsing standard ip-api.com response schema."""
    data = {
        "query": "198.51.100.6",
        "city": "Berlin",
        "regionName": "Berlin",
        "country": "Germany",
        "lat": 52.5200,
        "lon": 13.4050,
    }
    loc = _parse_location_payload(data)
    assert loc.ip == "198.51.100.6"
    assert loc.city == "Berlin"
    assert loc.region == "Berlin"
    assert loc.country == "Germany"
    assert loc.latitude == pytest.approx(52.5200)
    assert loc.longitude == pytest.approx(13.4050)
    assert loc.is_available is True


@patch("requests.get")
def test_get_approximate_location_success(mock_get):
    """Verify successful location retrieval via mocked requests."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "203.0.113.42",
        "city": "Toronto",
        "region": "Ontario",
        "country_name": "Canada",
        "latitude": 43.6532,
        "longitude": -79.3832,
    }
    mock_get.return_value = mock_resp

    loc = get_approximate_location("https://ipapi.co/json/", timeout=5.0)
    assert loc.is_available is True
    assert loc.city == "Toronto"
    assert loc.country == "Canada"
    assert loc.latitude == pytest.approx(43.6532)


@patch("requests.get")
def test_get_approximate_location_timeout_handling(mock_get):
    """Verify that timeout does not raise exception and returns unavailable location."""
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    loc = get_approximate_location("https://ipapi.co/json/", timeout=2.0)
    assert loc.is_available is False
    assert loc.city == "Unavailable"
    assert loc.latitude is None
    assert loc.map_url is None


@patch("requests.get")
def test_get_approximate_location_http_error(mock_get):
    """Verify non-200 HTTP code returns unavailable location without crash."""
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_get.return_value = mock_resp

    loc = get_approximate_location("https://ipapi.co/json/", timeout=5.0)
    assert loc.is_available is False
    assert loc.city == "Unavailable"


@patch("requests.get")
def test_get_approximate_location_api_error_flag(mock_get):
    """Verify that API payloads with error flag return unavailable location."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "error": True,
        "reason": "Rate limited",
    }
    loc = get_approximate_location("https://ipapi.co/json/", timeout=5.0)
    assert loc.is_available is False


def test_get_approximate_location_exact_coordinates():
    """Verify configured exact coordinates return accurate location without network requests."""
    loc = get_approximate_location(
        exact_latitude=11.074027,
        exact_longitude=75.982030,
        exact_location_name="Cherur, Malappuram",
    )
    assert loc.is_available is True
    assert loc.latitude == 11.074027
    assert loc.longitude == 75.982030
    assert loc.city == "Cherur, Malappuram"
    assert loc.map_url == "https://maps.google.com/?q=11.074027,75.982030"


@patch("requests.get")
def test_get_approximate_location_fallback_to_ip_api(mock_get):
    """Verify fallback to ip-api.com when primary ipapi.co fails."""
    primary_fail = MagicMock()
    primary_fail.status_code = 403

    fallback_ok = MagicMock()
    fallback_ok.status_code = 200
    fallback_ok.json.return_value = {
        "status": "success",
        "city": "Malappuram",
        "regionName": "Kerala",
        "country": "India",
        "lat": 11.0341,
        "lon": 76.0769,
        "query": "157.51.204.98",
    }

    mock_get.side_effect = [primary_fail, fallback_ok]

    loc = get_approximate_location("https://ipapi.co/json/", timeout=5.0)
    assert loc.is_available is True
    assert loc.city == "Malappuram"
    assert loc.region == "Kerala"
    assert loc.latitude == 11.0341
    assert loc.longitude == 76.0769
