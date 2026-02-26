#!/usr/bin/env python3
#
# app/utils/network.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Network utility functions."""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

__all__ = [
    "parse_ip",
    "parse_ip_str",
    "allowed_ips_with_dns_routes",
]


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

    # Parse existing networks once; ignore malformed entries but keep them as-is.
    existing_networks_v4: list[IPv4Network] = []
    existing_networks_v6: list[IPv6Network] = []
    for entry in items:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            existing_networks_v4.append(network)
        else:
            existing_networks_v6.append(network)

    def _covered(ip_obj: IPv4Address | IPv6Address) -> bool:
        candidates = existing_networks_v4 if ip_obj.version == 4 else existing_networks_v6
        return any(ip_obj in net for net in candidates)

    dns_items = [x.strip() for x in (dns_servers or "").split(",") if x.strip()]
    for dns in dns_items:
        ip_obj = parse_ip(dns)
        if ip_obj is None:
            continue
        if _covered(ip_obj):
            continue

        host_route = f"{ip_obj}/32" if ip_obj.version == 4 else f"{ip_obj}/128"
        items.append(host_route)
        if ip_obj.version == 4:
            existing_networks_v4.append(ipaddress.ip_network(host_route, strict=False))
        else:
            existing_networks_v6.append(ipaddress.ip_network(host_route, strict=False))

    # De-duplicate while preserving order.
    def _normalize_entry(entry: str) -> str:
        try:
            return str(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            return entry

    seen: set[str] = set()
    result: list[str] = []
    for entry in items:
        normalized = _normalize_entry(entry)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return ", ".join(result)
