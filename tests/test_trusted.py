"""Unit tests for TrustedContext matching and normalization."""

from __future__ import annotations

from device_guardian.detection.models import AuthenticationFailureEvent
from device_guardian.environment.models import EnvironmentalContext, NetworkContext
from device_guardian.filtering.trusted import TrustedContext


def test_trusted_context_normalization() -> None:
    """Verify input collections are stripped, lowercased, and deduplicated."""
    trusted = TrustedContext(
        trusted_users=["  Alice  ", "BOB", "", None, "alice"],
        trusted_networks=["NET_192.168.1.0/24", "  "],
        trusted_auth_types=["LOCAL", "  interactive  "],
    )
    assert trusted.trusted_users == {"alice", "bob"}
    assert trusted.trusted_networks == {"net_192.168.1.0/24"}
    assert trusted.trusted_auth_types == {"local", "interactive"}


def test_trusted_context_user_evaluation() -> None:
    """Verify username trust evaluation with edge cases."""
    trusted = TrustedContext(trusted_users=["alice"])

    assert trusted.is_user_trusted("Alice") is True
    assert trusted.is_user_trusted("alice") is True
    assert trusted.is_user_trusted("bob") is False
    assert trusted.is_user_trusted("") is False
    assert trusted.is_user_trusted(None) is False
    assert trusted.is_user_trusted("Unavailable") is False


def test_trusted_context_network_evaluation() -> None:
    """Verify network identifier trust evaluation."""
    trusted = TrustedContext(trusted_networks=["home_wifi", "net_10.0.0.0/24"])

    assert trusted.is_network_trusted("home_wifi") is True
    assert trusted.is_network_trusted("HOME_WIFI") is True
    assert trusted.is_network_trusted("public_cafe") is False
    assert trusted.is_network_trusted(None) is False


def test_trusted_context_auth_type_evaluation() -> None:
    """Verify authentication type evaluation."""
    trusted = TrustedContext(trusted_auth_types=["local"])

    assert trusted.is_auth_type_trusted("local") is True
    assert trusted.is_auth_type_trusted("LOCAL") is True
    assert trusted.is_auth_type_trusted("remote") is False
    assert trusted.is_auth_type_trusted("") is False
    assert trusted.is_auth_type_trusted(None) is False


def test_evaluate_trust_combined_event() -> None:
    """Verify evaluate_trust returns matched conditions list."""
    trusted = TrustedContext(
        trusted_users=["alice"],
        trusted_auth_types=["local"],
        trusted_networks=["net_192.168.1.0/24"],
    )

    ev_match = AuthenticationFailureEvent(username="alice", authentication_type="local")
    env_match = EnvironmentalContext(
        network_context=NetworkContext(network_identifier="net_192.168.1.0/24")
    )
    is_trusted, reasons = trusted.evaluate_trust(ev_match, env_match)

    assert is_trusted is True
    assert len(reasons) == 3
    assert any("alice" in r for r in reasons)
    assert any("local" in r for r in reasons)
    assert any("net_192.168.1.0/24" in r for r in reasons)

    ev_untrusted = AuthenticationFailureEvent(username="eve", authentication_type="remote")
    env_untrusted = EnvironmentalContext(network_context=NetworkContext(network_identifier="coffee_shop"))
    is_trusted2, reasons2 = trusted.evaluate_trust(ev_untrusted, env_untrusted)

    assert is_trusted2 is False
    assert len(reasons2) == 0


def test_trusted_context_cidr_and_ip_matching() -> None:
    """Verify standard CIDR subnets match host IPs and normalized prefixes."""
    trusted = TrustedContext(trusted_networks=["192.168.1.0/24", "10.0.0.5"])

    # Within subnet
    assert trusted.is_network_trusted("192.168.1.50") is True
    assert trusted.is_network_trusted("net_192.168.1.0/24") is True
    assert trusted.is_network_trusted("192.168.1.0/24") is True
    assert trusted.is_network_trusted("10.0.0.5") is True

    # Outside subnet
    assert trusted.is_network_trusted("192.168.2.1") is False
    assert trusted.is_network_trusted("10.0.0.6") is False
    assert trusted.is_network_trusted("172.16.0.1") is False


def test_trusted_context_malformed_network_rejection() -> None:
    """Verify malformed network definitions are rejected and do not crash."""
    trusted = TrustedContext(trusted_networks=["999.999.999.999/24", "invalid_ip/cidr", ""])

    assert trusted.is_network_trusted("999.999.999.999") is False
    assert trusted.is_network_trusted("invalid_ip/cidr") is False
    assert trusted.is_network_trusted("192.168.1.1") is False


def test_trusted_context_remote_address_matching() -> None:
    """Verify evaluate_trust detects trusted remote source IP addresses."""
    trusted = TrustedContext(trusted_networks=["192.168.1.0/24"])

    ev = AuthenticationFailureEvent(
        username="guest",
        remote_address="192.168.1.105",
        authentication_type="remote",
    )
    env = EnvironmentalContext()

    is_trusted, reasons = trusted.evaluate_trust(ev, env)
    assert is_trusted is True
    assert any("192.168.1.105" in r for r in reasons)

