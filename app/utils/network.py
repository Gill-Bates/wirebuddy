#!/usr/bin/env python3
#
# app/utils/network.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Network utility functions."""

from __future__ import annotations

import ipaddress
import logging
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

__all__ = [
    "parse_ip",
    "parse_ip_str",
    "allowed_ips_with_dns_routes",
]

_log = logging.getLogger(__name__)


def _split_comma_separated(value: str | None) -> list[str]:
    """Split a comma-separated string into cleaned, non-empty parts."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _strip_dns_decorators(raw: str) -> str:
    """Strip common DNS address suffixes (e.g. '#53', '%eth0')."""
    value = raw.strip()
    if not value:
        return ""
    value = value.split("#", 1)[0]
    value = value.split("%", 1)[0]
    return value.strip()


def _host_prefix(ip: IPv4Address | IPv6Address) -> int:
    """Return the host prefix length for an IP address."""
    return 32 if ip.version == 4 else 128


def _normalize_entry(entry: str) -> str:
    """Normalize CIDR/IP entries for de-duplication comparisons."""
    try:
        return str(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        return entry


class _NetworkIndex:
    """Index that tracks IPv4 and IPv6 networks separately."""

    __slots__ = ("_networks",)

    def __init__(self) -> None:
        self._networks: dict[int, list[IPv4Network | IPv6Network]] = {4: [], 6: []}

    def add(self, network: IPv4Network | IPv6Network) -> None:
        self._networks[network.version].append(network)

    def covers(self, ip_obj: IPv4Address | IPv6Address) -> bool:
        return any(ip_obj in network for network in self._networks[ip_obj.version])


def parse_ip(value: str | None) -> IPv4Address | IPv6Address | None:
    """Parse and normalize IPv4/IPv6 string (including IPv4-mapped IPv6)."""
    if not value:
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


def parse_ip_str(value: str | None) -> str | None:
    """Parse an IP and return its normalized string representation."""
    parsed = parse_ip(value)
    return str(parsed) if parsed is not None else None


def allowed_ips_with_dns_routes(
    allowed_ips: str,
    dns_servers: str,
    use_adblocker: bool,
) -> str:
    """Ensure internal DNS server IPs are routed via tunnel (leak protection).

    When WireBuddy DNS is enabled and client routing is split/custom, DNS IPs may
    not be included in client AllowedIPs. In that case queries can time out or
    fall back outside the tunnel. We enforce host routes for DNS IPs unless they
    are already covered by existing AllowedIPs.

    Note:
        If ``allowed_ips`` is empty and ``use_adblocker`` is True, the result
        contains only DNS host routes (for valid DNS IPs). No default route is
        implicitly added.
    """
    if not use_adblocker:
        return allowed_ips

    items = _split_comma_separated(allowed_ips)

    # Parse existing networks once; ignore malformed entries but keep them as-is.
    index = _NetworkIndex()
    for entry in items:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            _log.warning("ALLOWED_IPS_MALFORMED entry=%r (kept as-is)", entry)
            continue
        index.add(network)

    dns_items = _split_comma_separated(dns_servers)
    new_routes: list[str] = []
    for dns in dns_items:
        ip_obj = parse_ip(_strip_dns_decorators(dns))
        if ip_obj is None:
            _log.warning("DNS_SERVER_MALFORMED entry=%r (ignored for route injection)", dns)
            continue
        if index.covers(ip_obj):
            continue

        prefix = _host_prefix(ip_obj)
        host_route = f"{ip_obj}/{prefix}"
        new_routes.append(host_route)
        index.add(ipaddress.ip_network((ip_obj, prefix), strict=False))

    if not new_routes:
        return allowed_ips

    # De-duplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for entry in items + new_routes:
        normalized = _normalize_entry(entry)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(entry)
    return ", ".join(result)
