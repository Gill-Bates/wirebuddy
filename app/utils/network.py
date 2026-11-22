#!/usr/bin/env python3
#
# app/utils/network.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Network utility functions."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING

from .socket_peer import socket_peer_ip

if TYPE_CHECKING:
	from starlette.requests import Request

	from .config import Config

__all__ = [
	"allowed_ips_with_dns_routes",
	"is_unsafe_outbound_address",
	"parse_ip",
	"parse_ip_str",
	"resolve_client_ip",
	"walk_forwarded_chain",
]

_log = logging.getLogger(__name__)


_CGNAT_NETWORK = IPv4Network("100.64.0.0/10")


def is_unsafe_outbound_address(addr: IPv4Address | IPv6Address, *, allow_cgnat: bool = False) -> bool:
	"""True if ``addr`` must never be an outbound connection target (SSRF guard).

	Python >= 3.13 judges IPv4-mapped IPv6 (::ffff:a.b.c.d) by the embedded
	IPv4 address, so no manual unwrapping is needed for the stdlib classes;
	shared address space (CGNAT, 100.64.0.0/10) is neither private nor global
	there and is checked here, also in mapped form. ``allow_cgnat`` is for
	callers that only build a URL and make no request (for example Tailscale).
	NAT64 64:ff9b::/96 is already rejected as reserved by the stdlib.
	"""
	if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
		return True
	if allow_cgnat:
		return False
	embedded = addr.ipv4_mapped if isinstance(addr, IPv6Address) else addr
	return embedded is not None and embedded in _CGNAT_NETWORK


_MAX_DNS_SERVERS_FOR_ROUTES = 16


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


def resolve_client_ip(request: Request) -> str | None:
	"""Return the client IP, trusting proxy headers only from a trusted socket peer.

	SECURITY: Starts from the real TCP peer captured by ``SocketPeerMiddleware``
	(``scope["wb.socket_peer"]``), not from ``scope["client"]``, which uvicorn's
	proxy middleware rewrites from ``X-Forwarded-For``. Returns ``None`` when no
	usable socket address exists (also when the app runs without the wrapper);
	callers decide how to react.
	"""
	from .config import get_config

	socket_ip = socket_peer_ip(request.scope)
	if not socket_ip:
		return None

	config = get_config()
	if config.is_trusted_proxy_ip(socket_ip):
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for:
			client = _client_from_forwarded_chain(forwarded_for, config)
			if client:
				return client

		x_real_ip = request.headers.get("X-Real-IP")
		if x_real_ip:
			candidate = parse_ip_str(x_real_ip)
			if candidate:
				return candidate

	return socket_ip


def walk_forwarded_chain(
	forwarded_for: str,
	is_trusted: Callable[[IPv4Address | IPv6Address], bool],
) -> IPv4Address | IPv6Address | None:
	"""Walk an ``X-Forwarded-For`` chain right-to-left and return the first untrusted hop.

	Each hop was reported by the one to its right, so trusted hops are skipped
	and the first untrusted one is the client; entries to its left are
	attacker-controlled and never read. Returns ``None`` for an empty chain, a
	fully trusted chain, or an unparseable hop (it breaks the chain of trust).
	``is_trusted`` carries the caller's trust set.
	"""
	hops = [part.strip() for part in forwarded_for.split(",") if part.strip()]
	for hop in reversed(hops):
		candidate = parse_ip(hop)
		if candidate is None:
			return None
		if not is_trusted(candidate):
			return candidate
	return None


def _client_from_forwarded_chain(forwarded_for: str, config: Config) -> str | None:
	"""Return the client from an ``X-Forwarded-For`` chain, skipping configured trusted proxies."""
	client = walk_forwarded_chain(forwarded_for, lambda ip: config.is_trusted_proxy_ip(str(ip)))
	return str(client) if client is not None else None


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

	# Parse existing networks once and fail fast on malformed entries.
	index = _NetworkIndex()
	for entry in items:
		try:
			network = ipaddress.ip_network(entry, strict=False)
		except ValueError as exc:
			raise ValueError(f"Malformed AllowedIPs entry: {entry!r}") from exc
		index.add(network)

	dns_items = _split_comma_separated(dns_servers)
	if len(dns_items) > _MAX_DNS_SERVERS_FOR_ROUTES:
		raise ValueError("Too many DNS servers for route injection")
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
