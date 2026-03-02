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


def _strip_dns_decorators(raw: str) -> str:
    """Strip common DNS address suffixes (e.g. '#53', '%eth0')."""
    value = str(raw or "").strip()
    if not value:
        return ""
    value = value.split("#", 1)[0]
    value = value.split("%", 1)[0]
    return value.strip()


def _normalize_entry(entry: str) -> str:
    """Normalize CIDR/IP entries for de-duplication comparisons."""
    try:
        return str(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        return str(entry)


def _is_covered(
    ip_obj: IPv4Address | IPv6Address,
    existing_networks_v4: list[IPv4Network],
    existing_networks_v6: list[IPv6Network],
) -> bool:
    """Return True if ip_obj is covered by existing networks."""
    candidates = existing_networks_v4 if ip_obj.version == 4 else existing_networks_v6
    return any(ip_obj in net for net in candidates)


def parse_ip(value: str | None) -> IPv4Address | IPv6Address | None:
    """Parse and normalize IPv4/IPv6 string (including IPv4-mapped IPv6)."""
    if not value:
        return None
    try:
        # Keep str() for runtime robustness in case non-str values leak through.
        parsed = ipaddress.ip_address(str(value).strip())
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

    items = [x.strip() for x in (allowed_ips or "").split(",") if x.strip()]
    original_allowed_ips = allowed_ips

    # Parse existing networks once; ignore malformed entries but keep them as-is.
    existing_networks_v4: list[IPv4Network] = []
    existing_networks_v6: list[IPv6Network] = []
    for entry in items:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            _log.warning("ALLOWED_IPS_MALFORMED entry=%r (kept as-is)", entry)
            continue
        if isinstance(network, IPv4Network):
            existing_networks_v4.append(network)
        elif isinstance(network, IPv6Network):
            existing_networks_v6.append(network)

    dns_items = [x.strip() for x in (dns_servers or "").split(",") if x.strip()]
    routes_added = False
    for dns in dns_items:
        ip_obj = parse_ip(_strip_dns_decorators(dns))
        if ip_obj is None:
            _log.warning("DNS_SERVER_MALFORMED entry=%r (ignored for route injection)", dns)
            continue
        if _is_covered(ip_obj, existing_networks_v4, existing_networks_v6):
            continue

        host_route = f"{ip_obj}/32" if ip_obj.version == 4 else f"{ip_obj}/128"
        items.append(host_route)
        routes_added = True
        if ip_obj.version == 4:
            existing_networks_v4.append(ipaddress.ip_network(host_route, strict=False))
        else:
            existing_networks_v6.append(ipaddress.ip_network(host_route, strict=False))

    if not routes_added:
        return original_allowed_ips

    # De-duplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for entry in items:
        normalized = _normalize_entry(entry)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(entry)
    return ", ".join(result)
