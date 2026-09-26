"""Lightweight network environment detector.

Detects network connectivity state and local interface availability.
Adheres strictly to Phase 4 safety boundaries:
- No packet capture or traffic inspection.
- No network scanning or LAN device enumeration.
- No credential interception or browsing monitoring.
- Completely offline-compatible.
"""

from __future__ import annotations

from datetime import datetime
import ipaddress
import socket
from typing import Callable, Optional

from device_guardian.environment.models import NetworkContext, NetworkState
from device_guardian.logger import get_logger

logger = get_logger("environment.network")


class NetworkDetector:
    """Detects connectivity state and interface availability using standard library socket."""

    def __init__(
        self,
        resolver_hook: Optional[Callable[[], list[str]]] = None,
        connectivity_hook: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        """Initialize the network detector.

        Args:
            resolver_hook: Optional hook to override host address resolution for testing.
            connectivity_hook: Optional hook to override primary outbound route query.
        """
        self._resolver_hook = resolver_hook or self._default_resolve_interfaces
        self._connectivity_hook = connectivity_hook or self._default_query_primary_ip

    def _default_resolve_interfaces(self) -> list[str]:
        """Enumerate local IP addresses assigned to this host."""
        try:
            hostname = socket.gethostname()
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            return [ip for ip in ip_list if ip and not ip.startswith("127.")]
        except Exception as exc:
            logger.debug("Failed to resolve host interface addresses: %s", exc)
            return []

    def _default_query_primary_ip(self) -> Optional[str]:
        """Determine primary local IP using UDP routing table lookup without transmitting packets."""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connecting a UDP socket to an address does not generate network traffic;
            # it merely determines the local interface routing according to OS route tables.
            s.connect(("192.0.2.1", 80))  # RFC 5737 TEST-NET-1 (non-routable documentation IP)
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
            return None
        except OSError:
            # Network is down or route is unreachable
            return None
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    def detect_network_context(self, include_network_id: bool = False) -> NetworkContext:
        """Collect current network state safely and non-invasively.

        Args:
            include_network_id: If True and supported, includes sanitized local subnet prefix.

        Returns:
            NetworkContext describing current connectivity.
        """
        collected_at = datetime.now()

        try:
            interfaces = self._resolver_hook()
            primary_ip = self._connectivity_hook()

            # If primary route exists, consider connected
            connected = bool(primary_ip) or (len(interfaces) > 0)
            state = NetworkState.CONNECTED if connected else NetworkState.DISCONNECTED

            # Determine private network classification
            is_private = False
            target_ip = primary_ip or (interfaces[0] if interfaces else None)
            if target_ip:
                try:
                    ip_obj = ipaddress.ip_address(target_ip)
                    is_private = ip_obj.is_private
                except ValueError:
                    is_private = False

            network_id: Optional[str] = None
            if include_network_id and target_ip:
                try:
                    # Provide an anonymized class-C style prefix rather than the full IP
                    parts = target_ip.split(".")
                    if len(parts) == 4:
                        network_id = f"net_{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                except Exception:
                    network_id = None

            context = NetworkContext(
                connected=connected,
                state=state,
                interface_count=len(interfaces),
                network_identifier=network_id,
                is_private_network=is_private,
                collected_at=collected_at,
                details={
                    "primary_ip_detected": bool(primary_ip),
                    "interface_count": len(interfaces),
                },
            )
            logger.debug(
                "Network context collected: state=%s, interfaces=%d, private=%s",
                state.value,
                len(interfaces),
                is_private,
            )
            return context

        except Exception as exc:
            logger.warning("Error collecting network context: %s", exc)
            return NetworkContext(
                connected=False,
                state=NetworkState.UNKNOWN,
                interface_count=0,
                collected_at=collected_at,
                details={"error": str(exc)},
            )
