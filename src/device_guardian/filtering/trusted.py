"""Trusted Context representation and matcher for Device Guardian (Phase 4).

Evaluates whether events or environmental states match explicitly configured
user trust boundaries.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Iterable, Optional

if TYPE_CHECKING:
    from device_guardian.detection.models import AuthenticationFailureEvent
    from device_guardian.environment.models import EnvironmentalContext
from device_guardian.logger import get_logger

logger = get_logger("filtering.trusted")


class TrustedContext:
    """Manages explicitly configured trusted users, networks, and authentication types."""

    def __init__(
        self,
        trusted_users: Optional[Iterable[str]] = None,
        trusted_networks: Optional[Iterable[str]] = None,
        trusted_auth_types: Optional[Iterable[str]] = None,
    ) -> None:
        """Initialize trusted context.

        Args:
            trusted_users: Collection of trusted username strings.
            trusted_networks: Collection of trusted network identifiers or IP prefixes.
            trusted_auth_types: Collection of trusted authentication types (e.g. "local").
        """
        self.trusted_users: set[str] = {
            u.strip().lower() for u in (trusted_users or []) if u and u.strip()
        }
        self.trusted_auth_types: set[str] = {
            a.strip().lower() for a in (trusted_auth_types or []) if a and a.strip()
        }

        # Normalize and validate network definitions
        self.trusted_networks: set[str] = set()
        self._parsed_ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        for item in (trusted_networks or []):
            if not item or not str(item).strip():
                continue
            raw = str(item).strip().lower()
            clean = raw[4:] if raw.startswith("net_") else raw

            # Check if network candidate looks like an IP address or CIDR notation
            is_ip_candidate = any(c in clean for c in [".", ":", "/"])
            if is_ip_candidate:
                try:
                    net_obj = ipaddress.ip_network(clean, strict=False)
                    self._parsed_ip_networks.append(net_obj)
                    self.trusted_networks.add(raw)
                except ValueError:
                    logger.warning("Rejected malformed trusted network CIDR/IP: '%s'", item)
            else:
                # Custom alphanumeric network label or identifier
                self.trusted_networks.add(raw)

    def is_user_trusted(self, username: Optional[str]) -> bool:
        """Check if username matches a configured trusted user."""
        if not username or username.strip() in {"", "-", "Unavailable"}:
            return False
        return username.strip().lower() in self.trusted_users

    def is_network_trusted(self, network_id: Optional[str]) -> bool:
        """Check if network identifier or IP matches a configured trusted network."""
        if not network_id or not network_id.strip():
            return False

        clean = network_id.strip().lower()
        if clean in self.trusted_networks:
            return True

        stripped = clean[4:] if clean.startswith("net_") else clean
        if stripped in self.trusted_networks:
            return True

        # Test IP address against configured subnets
        try:
            ip_str = stripped.split("/")[0] if "/" in stripped else stripped
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self._parsed_ip_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            pass

        return False

    def is_auth_type_trusted(self, auth_type: Optional[str]) -> bool:
        """Check if authentication type matches configured trusted auth types."""
        if not auth_type or auth_type.strip() in {"", "Unavailable", "unknown"}:
            return False
        return auth_type.strip().lower() in self.trusted_auth_types

    def evaluate_trust(
        self,
        event: AuthenticationFailureEvent,
        env_context: EnvironmentalContext,
    ) -> tuple[bool, list[str]]:
        """Evaluate if any trusted context matches the incoming event and environment.

        Returns:
            Tuple of (is_trusted: bool, matched_reasons: list[str]).
        """
        matched: list[str] = []

        if self.is_user_trusted(event.username):
            matched.append(f"Trusted user '{event.username}'")

        if self.is_auth_type_trusted(event.authentication_type):
            matched.append(f"Trusted authentication type '{event.authentication_type}'")

        net_id = env_context.network_context.network_identifier
        if net_id and self.is_network_trusted(net_id):
            matched.append(f"Trusted network '{net_id}'")

        remote_addr = event.remote_address
        if (
            remote_addr
            and remote_addr not in {"Local Console", "Unavailable", "127.0.0.1", "::1"}
            and self.is_network_trusted(remote_addr)
        ):
            matched.append(f"Trusted remote network '{remote_addr}'")

        return bool(matched), matched
