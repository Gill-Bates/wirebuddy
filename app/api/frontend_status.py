#!/usr/bin/env python3
#
# app/api/frontend_status.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Status page route and status-related helpers."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import sqlite3
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_settings import get_setting
from ..dns import ingestion as dns_ingestion
from ..dns import unbound
from ..utils.config import get_config
from ..utils.deps import get_conn
from ..utils.network import parse_ip
from ..utils.rate_limit import RATE_LIMIT_DEFAULT, limiter
from .auth import _get_client_ip, get_current_user_optional
from .frontend_shared import _extract_geo_fields, _lookup_ip_cached, router, templates

_log = logging.getLogger(__name__)

_STATUS_ENABLE_KEY = "enable_status_page"
_STATUS_PROBE_DOMAIN = "cloudflare.com"
_STATUS_TRUTHY = {"1", "true", "yes", "on"}
_STATUS_OUTBOUND_IP_URLS = (
	"https://api64.ipify.org?format=text",
	"https://ifconfig.me/ip",
)
_STATUS_OUTBOUND_CACHE_TTL = 300.0
_STATUS_DNS_PROBE_CACHE_TTL = 60.0
_STATUS_DNS_LEAK_CACHE_TTL = 60.0
_STATUS_DNS_LEAK_VERIFY_WINDOW_SECONDS = 900
_STATUS_DNS_LEAK_VERIFY_MAX_QUERIES = 5000
_STATUS_TRUSTED_PROXY_CIDRS_ENV = "WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS"

_outbound_ip_cache: tuple[str | None, str, float] | None = None
_dns_probe_cache: tuple[bool, str, float, tuple[str, ...]] | None = None
_dns_leak_cache: dict[tuple[str, str], tuple[str, str, float]] = {}
_outbound_ip_cache_lock = asyncio.Lock()
_dns_probe_cache_lock = asyncio.Lock()
_dns_leak_cache_lock = asyncio.Lock()


@dataclass(frozen=True)
class StatusClientContext:
	"""Resolved status-page client context."""
	client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
	matched_iface: sqlite3.Row | None
	auth_ip_source: str
	socket_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
	forwarded_ip: str | None


def _is_status_page_enabled(conn: sqlite3.Connection) -> bool:
	"""Return whether the public internal status page is enabled."""
	value = get_setting(conn, _STATUS_ENABLE_KEY, "0")
	return str(value or "").strip().lower() in _STATUS_TRUTHY


def _parse_interface_network(raw: str | None) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
	"""Parse interface CIDR into an IP network."""
	text = str(raw or "").strip()
	if not text:
		return None
	try:
		return ipaddress.ip_interface(text).network
	except ValueError:
		return None


def _load_status_trusted_proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
	"""Load explicitly trusted proxy CIDRs for /status header trust."""
	value = str(os.environ.get(_STATUS_TRUSTED_PROXY_CIDRS_ENV, "")).strip()
	if not value:
		return ()
	networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
	for raw in value.split(","):
		item = raw.strip()
		if not item:
			continue
		try:
			networks.append(ipaddress.ip_network(item, strict=False))
		except ValueError:
			_log.warning("Ignoring invalid %s entry: %r", _STATUS_TRUSTED_PROXY_CIDRS_ENV, item)
	return tuple(networks)


_STATUS_TRUSTED_PROXY_NETWORKS = _load_status_trusted_proxy_networks()


def _normalize_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
	"""Parse and normalize IPv4/IPv6 string, including IPv4-mapped IPv6."""
	return parse_ip(value)


def _ip_in_networks(
	ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
	networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
	"""Return True when ip belongs to any network (version-aware)."""
	for network in networks:
		if ip_obj.version != network.version:
			continue
		if ip_obj in network:
			return True
	return False


def _is_wireguard_client_subnet_ip(
	conn: sqlite3.Connection,
	ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
	"""Return True when ip belongs to any WireGuard interface subnet."""
	for iface in list_interfaces(conn):
		for key in ("address", "address6"):
			network = _parse_interface_network(iface[key])
			if network is None:
				continue
			if ip_obj.version != network.version:
				continue
			if ip_obj in network:
				return True
	return False


def _find_client_interface(
	conn: sqlite3.Connection,
	client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> sqlite3.Row | None:
	"""Return the matching WireGuard interface row for a client IP, if any."""
	interfaces = list_interfaces(conn)
	_log.debug(
		"/status: checking client_ip=%s against %d interfaces",
		client_ip,
		len(interfaces),
	)
	for iface in interfaces:
		networks = (
			_parse_interface_network(iface["address"]),
			_parse_interface_network(iface["address6"]),
		)
		_log.debug(
			"/status: iface=%s address=%r address6=%r → networks=%s",
			iface["name"],
			iface["address"],
			iface["address6"],
			networks,
		)
		for network in networks:
			if network is None:
				continue
			if client_ip.version != network.version:
				continue
			if client_ip in network:
				_log.debug("/status: matched iface=%s network=%s", iface["name"], network)
				return iface
	_log.debug("/status: no interface matched for client_ip=%s", client_ip)
	return None


def _pick_forwarded_client_ip(
	x_forwarded_for: str,
	trusted_proxies: set[str],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
	"""Return nearest untrusted client IP from X-Forwarded-For chain."""
	if not x_forwarded_for:
		return None
	chain: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
	for raw in x_forwarded_for.split(","):
		ip_obj = _normalize_ip(raw.strip())
		if ip_obj is not None:
			chain.append(ip_obj)
	for ip_obj in reversed(chain):
		if str(ip_obj) not in trusted_proxies:
			return ip_obj
	return None


def _find_peer_public_ip_for_vpn_ip(
	conn: sqlite3.Connection,
	interface_name: str,
	vpn_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str | None:
	"""Resolve peer public endpoint IP from stored peer VPN address + last_client_ip."""
	try:
		rows = conn.execute(
			"""
			SELECT peer_address, last_client_ip
			FROM peers
			WHERE interface = ?
			  AND peer_address IS NOT NULL
			  AND last_client_ip IS NOT NULL
			""",
			(interface_name,),
		).fetchall()
	except Exception:
		return None

	for row in rows:
		peer_address = str(row["peer_address"] or "")
		for part in peer_address.split(","):
			item = part.strip()
			if not item:
				continue
			try:
				peer_ip = ipaddress.ip_interface(item).ip
			except ValueError:
				continue
			if peer_ip != vpn_ip:
				continue
			candidate = _normalize_ip(str(row["last_client_ip"] or "").strip())
			if candidate is None:
				return None
			if candidate.is_private or candidate.is_loopback or candidate.is_link_local:
				return None
			return str(candidate)

	return None


def _resolve_public_client_ip(
	conn: sqlite3.Connection,
	client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
	matched_iface: sqlite3.Row | None,
	forwarded_ip_value: str | None,
) -> str | None:
	"""Best-effort public client IP for GeoIP/ASN display on status page."""
	if not (client_ip.is_private or client_ip.is_loopback or client_ip.is_link_local):
		return str(client_ip)

	forwarded_ip = _normalize_ip(forwarded_ip_value)
	if forwarded_ip and not (forwarded_ip.is_private or forwarded_ip.is_loopback or forwarded_ip.is_link_local):
		return str(forwarded_ip)

	if matched_iface is not None:
		return _find_peer_public_ip_for_vpn_ip(conn, matched_iface["name"], client_ip)

	return None


def _dns_probe_targets(iface: sqlite3.Row | None) -> tuple[str, ...]:
	"""Resolve candidate internal resolver targets for DNS probe."""
	targets: list[str] = []

	def _add(value: str | None) -> None:
		ip_obj = _normalize_ip(value)
		if ip_obj is None:
			return
		normalized = str(ip_obj)
		if normalized not in targets:
			targets.append(normalized)

	if iface is not None:
		for key in ("address", "address6"):
			raw = str(iface[key] or "").strip()
			if not raw:
				continue
			try:
				_add(str(ipaddress.ip_interface(raw).ip))
			except ValueError:
				continue

	_add("127.0.0.1")
	_add("::1")
	return tuple(targets)


def _dns_probe_query(server_ip: str) -> tuple[bool, str]:
	"""Perform one UDP DNS A query against a specific resolver IP."""
	query_id = int.from_bytes(os.urandom(2), "big")
	header = query_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	labels = [part for part in _STATUS_PROBE_DOMAIN.strip(".").split(".") if part]
	qname_parts: list[bytes] = []
	for label in labels:
		encoded = label.encode("idna")
		if len(encoded) == 0 or len(encoded) > 63:
			return False, f"Invalid DNS probe label length in domain {_STATUS_PROBE_DOMAIN!r}"
		qname_parts.append(bytes((len(encoded),)) + encoded)
	qname = b"".join(qname_parts) + b"\x00"
	question = qname + b"\x00\x01\x00\x01"
	packet = header + question

	family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
	try:
		with socket.socket(family, socket.SOCK_DGRAM) as sock:
			sock.settimeout(2.0)
			sock.sendto(packet, (server_ip, 53))
			response, _ = sock.recvfrom(2048)
			if len(response) < 12:
				return False, f"Invalid DNS response from {server_ip}:53"
			if response[0:2] != query_id.to_bytes(2, "big"):
				return False, f"Mismatched DNS response ID from {server_ip}:53"
			flags = int.from_bytes(response[2:4], "big")
			rcode = flags & 0x000F
			ancount = int.from_bytes(response[6:8], "big")
			if rcode != 0:
				return False, f"Resolver {server_ip}:53 returned RCODE={rcode}"
			if ancount <= 0:
				return False, f"Resolver {server_ip}:53 returned no answers"
			return True, f"Resolved {_STATUS_PROBE_DOMAIN} via internal resolver {server_ip}:53"
	except socket.timeout:
		return False, f"Resolver {server_ip}:53 timed out"
	except OSError as exc:
		return False, f"Resolver {server_ip}:53 unreachable ({exc})"


async def _resolve_dns_probe_cached(iface: sqlite3.Row | None) -> tuple[bool, str]:
	"""Run DNS probe with short TTL cache to avoid repeated lookups."""
	global _dns_probe_cache
	target_key = _dns_probe_targets(iface)

	async with _dns_probe_cache_lock:
		now = time.monotonic()
		if (
			_dns_probe_cache
			and _dns_probe_cache[3] == target_key
			and (now - _dns_probe_cache[2]) < _STATUS_DNS_PROBE_CACHE_TTL
		):
			return _dns_probe_cache[0], _dns_probe_cache[1]

		def _probe_all() -> tuple[bool, str]:
			if not target_key:
				return False, "No internal resolver target available"
			last_error = "Internal resolver probe failed"
			for server_ip in target_key:
				ok, detail = _dns_probe_query(server_ip)
				if ok:
					return True, detail
				last_error = detail
			return False, last_error

		result = await asyncio.to_thread(_probe_all)
		_dns_probe_cache = (result[0], result[1], now, target_key)
		return result


async def _detect_outbound_ip() -> tuple[str | None, str]:
	"""Detect outbound/public IP with small timeout and fallback endpoints."""
	timeout = httpx.Timeout(3.0, connect=3.0)
	async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
		for url in _STATUS_OUTBOUND_IP_URLS:
			try:
				resp = await client.get(url)
				resp.raise_for_status()
				candidate = (resp.text or "").strip().splitlines()[0].strip()
				ip_obj = ipaddress.ip_address(candidate)
				if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
					candidate = str(ip_obj.ipv4_mapped)
				return candidate, "Detected via external probe"
			except Exception:
				continue
	return None, "Outbound IP probe unavailable"


async def _detect_outbound_ip_cached() -> tuple[str | None, str]:
	"""Detect outbound IP with TTL cache to reduce latency and external calls."""
	global _outbound_ip_cache

	async with _outbound_ip_cache_lock:
		now = time.monotonic()
		if _outbound_ip_cache and (now - _outbound_ip_cache[2]) < _STATUS_OUTBOUND_CACHE_TTL:
			return _outbound_ip_cache[0], _outbound_ip_cache[1]
		result = await _detect_outbound_ip()
		_outbound_ip_cache = (result[0], result[1], now)
		return result


def _dns_config_indicator(
	iface: sqlite3.Row | None,
) -> tuple[bool | None, str]:
	"""Return a configuration-based DNS leak heuristic (not a runtime leak test)."""
	if iface is None:
		return None, "Not connected via WireGuard – DNS leak check not applicable"

	dns_raw = str(iface["dns"] or "").strip()
	if not dns_raw:
		return False, "Interface has no explicit DNS server configured"

	expected_dns: set[str] = set()
	for key in ("address", "address6"):
		raw = str(iface[key] or "").strip()
		if not raw:
			continue
		try:
			expected_dns.add(str(ipaddress.ip_interface(raw).ip))
		except ValueError:
			continue

	configured_dns = [part.strip() for part in dns_raw.split(",") if part.strip()]
	for dns_entry in configured_dns:
		candidate = dns_entry.split("/")[0].strip()
		try:
			candidate_ip = str(ipaddress.ip_address(candidate))
		except ValueError:
			continue
		if candidate_ip in expected_dns:
			return True, "Peer DNS is configured to use WireBuddy resolver"

	return False, "Interface DNS does not point to local WireBuddy resolver"


def _parse_iso_ts(value: str) -> datetime | None:
	"""Parse ISO timestamp from DNS TSDB rows to timezone-aware UTC datetime."""
	text = str(value or "").strip()
	if not text:
		return None
	if text.endswith("Z"):
		text = text[:-1] + "+00:00"
	try:
		ts = datetime.fromisoformat(text)
	except ValueError:
		return None
	if ts.tzinfo is None:
		return ts.replace(tzinfo=timezone.utc)
	return ts.astimezone(timezone.utc)


async def _dns_leak_indicator(
	client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
	iface: sqlite3.Row | None,
) -> tuple[str, str]:
	"""Return DNS leak status with runtime verification from Unbound-ingested queries."""
	config_ok, config_detail = _dns_config_indicator(iface)
	if config_ok is None:
		return "info", config_detail
	if not config_ok:
		return "warn", config_detail

	cache_key = (str(client_ip), str(iface["name"]) if iface is not None else "")
	now_mono = time.monotonic()
	async with _dns_leak_cache_lock:
		cached = _dns_leak_cache.get(cache_key)
		if cached and (now_mono - cached[2]) < _STATUS_DNS_LEAK_CACHE_TTL:
			return cached[0], cached[1]

	try:
		cfg = get_config()
		queries = await asyncio.to_thread(
			dns_ingestion.read_recent_queries,
			Path(cfg.tsdb_dir),
			_STATUS_DNS_LEAK_VERIFY_MAX_QUERIES,
		)
	except Exception:
		_log.debug("DNS leak runtime verification unavailable", exc_info=True)
		result = ("warn", (
			f"{config_detail}; runtime verification unavailable "
			"(could not read recent DNS logs)"
		))
		async with _dns_leak_cache_lock:
			_dns_leak_cache[cache_key] = (result[0], result[1], now_mono)
		return result

	client_ip_text = str(client_ip)
	now = datetime.now(timezone.utc)
	window = _STATUS_DNS_LEAK_VERIFY_WINDOW_SECONDS

	for row in queries:
		if str(row.get("client", "")).strip() != client_ip_text:
			continue
		ts = _parse_iso_ts(str(row.get("ts", "")))
		if ts is None:
			continue
		age_s = max(0, int((now - ts).total_seconds()))
		if age_s <= window:
			if age_s < 60:
				age_label = "just now"
			else:
				age_label = f"{age_s // 60}m ago"
			result = ("ok", f"Verified via WireBuddy DNS logs ({age_label})")
			async with _dns_leak_cache_lock:
				_dns_leak_cache[cache_key] = (result[0], result[1], now_mono)
			return result
		break

	window_min = max(1, window // 60)
	result = ("warn", (
		f"{config_detail}; no DNS query from this client seen in WireBuddy logs "
		f"within last {window_min} minutes (status currently unknown)"
	))
	async with _dns_leak_cache_lock:
		_dns_leak_cache[cache_key] = (result[0], result[1], now_mono)
	return result


async def _is_trusted_status_proxy_hop(
	conn: sqlite3.Connection,
	socket_ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
) -> bool:
	"""Return True if socket peer should be trusted as reverse-proxy hop for /status."""
	if socket_ip_obj is None:
		return False
	if socket_ip_obj.is_loopback:
		return True
	if _STATUS_TRUSTED_PROXY_NETWORKS:
		return _ip_in_networks(socket_ip_obj, _STATUS_TRUSTED_PROXY_NETWORKS)
	if not (socket_ip_obj.is_private or socket_ip_obj.is_link_local):
		return False
	is_wg_subnet_ip = await asyncio.to_thread(_is_wireguard_client_subnet_ip, conn, socket_ip_obj)
	return not is_wg_subnet_ip


async def _resolve_status_client_context(
	request: Request,
	conn: sqlite3.Connection,
	user: Optional[sqlite3.Row],
) -> StatusClientContext:
	"""Resolve and authorize status page client context."""
	client_ip_obj = _normalize_ip(_get_client_ip(request))
	if client_ip_obj is None:
		_log.warning("/status: could not determine client IP, returning 403")
		raise HTTPException(status_code=403, detail="Forbidden")

	auth_ip_source = "direct"
	forwarded_ip_value: str | None = None
	scope_client = request.scope.get("client")
	socket_ip_obj = _normalize_ip(scope_client[0] if scope_client else None)

	_log.debug(
		"/status: client_ip=%s socket_ip=%s user=%s",
		client_ip_obj,
		socket_ip_obj,
		user["id"] if user else None,
	)

	matched_iface = await asyncio.to_thread(_find_client_interface, conn, client_ip_obj)

	if matched_iface is None:
		forwarded_for = request.headers.get("X-Forwarded-For", "")
		x_real_ip = request.headers.get("X-Real-IP", "")
		_log.debug(
			"/status: proxy headers X-Forwarded-For=%r X-Real-IP=%r socket_ip=%s",
			forwarded_for,
			x_real_ip,
			socket_ip_obj,
		)
		if socket_ip_obj and (forwarded_for or x_real_ip):
			if await _is_trusted_status_proxy_hop(conn, socket_ip_obj):
				fallback_trusted = {str(socket_ip_obj)}
				forwarded_ip_obj = _pick_forwarded_client_ip(forwarded_for, fallback_trusted)
				forwarded_ip_value = str(forwarded_ip_obj) if forwarded_ip_obj is not None else None
				if forwarded_ip_obj is not None:
					forwarded_iface = await asyncio.to_thread(_find_client_interface, conn, forwarded_ip_obj)
					if forwarded_iface is not None:
						client_ip_obj = forwarded_ip_obj
						matched_iface = forwarded_iface
						auth_ip_source = "x-forwarded-for-local-hop"
						_log.debug(
							"/status: accepted forwarded client IP %s via local proxy hop %s",
							client_ip_obj,
							socket_ip_obj,
						)
				if matched_iface is None and x_real_ip:
					real_ip_obj = _normalize_ip(x_real_ip.split(",")[0].strip())
					if real_ip_obj is not None:
						real_ip_iface = await asyncio.to_thread(_find_client_interface, conn, real_ip_obj)
						if real_ip_iface is not None:
							client_ip_obj = real_ip_obj
							matched_iface = real_ip_iface
							auth_ip_source = "x-real-ip-local-hop"
							forwarded_ip_value = str(real_ip_obj)
							_log.debug(
								"/status: accepted X-Real-IP client %s via local proxy hop %s",
								client_ip_obj,
								socket_ip_obj,
							)

	if matched_iface is None and user and user["is_admin"]:
		auth_ip_source = "admin-token"
		_log.debug("/status: admin override access granted for user_id=%s", user["id"])
	elif matched_iface is None:
		raise HTTPException(status_code=403, detail="Forbidden")

	return StatusClientContext(
		client_ip=client_ip_obj,
		matched_iface=matched_iface,
		auth_ip_source=auth_ip_source,
		socket_ip=socket_ip_obj,
		forwarded_ip=forwarded_ip_value,
	)


async def _is_unbound_running_safe() -> bool:
	"""Best-effort unbound running check."""
	try:
		return await unbound.is_running()
	except FileNotFoundError:
		return False
	except Exception:
		return False


async def _run_status_health_checks(
	client_ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
	matched_iface: sqlite3.Row | None,
) -> tuple[list[dict[str, str]], str | None]:
	"""Compute status checks and outbound IP details."""
	app_health = {"state": "ok", "label": "OK", "detail": "Status page request was served successfully"}

	dns_running, dns_probe_result, leak_result, outbound_result = await asyncio.gather(
		_is_unbound_running_safe(),
		_resolve_dns_probe_cached(matched_iface),
		_dns_leak_indicator(client_ip_obj, matched_iface),
		_detect_outbound_ip_cached(),
	)

	dns_probe_ok, dns_probe_detail = dns_probe_result
	if matched_iface is None:
		dns_health = {"state": "info", "label": "N/A", "detail": "Not connected via WireGuard – DNS check not applicable"}
	elif dns_running and dns_probe_ok:
		dns_health = {"state": "ok", "label": "OK", "detail": dns_probe_detail}
	elif dns_probe_ok:
		dns_health = {"state": "warn", "label": "WARN", "detail": "Resolver probe passed, Unbound process not detected"}
	else:
		dns_health = {"state": "error", "label": "ERROR", "detail": dns_probe_detail}

	leak_state, leak_detail = leak_result
	if leak_state == "ok":
		leak_label = "OK"
	elif leak_state == "info":
		leak_label = "N/A"
	else:
		leak_label = "WARN"
	leak_health = {"state": leak_state, "label": leak_label, "detail": leak_detail}

	outbound_ip, outbound_detail = outbound_result
	outbound_state = "ok" if outbound_ip else "warn"
	outbound_label = "OK" if outbound_ip else "WARN"

	checks = [
		{"title": "Status Page", **app_health},
		{"title": "DNS Resolution", **dns_health},
		{"title": "DNS Leak Indicator", **leak_health},
		{"title": "Outbound IP Probe", "state": outbound_state, "label": outbound_label, "detail": outbound_detail},
	]
	return checks, outbound_ip


@router.get("/status", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def status_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Public internal status page (WireGuard clients only)."""
	if not await asyncio.to_thread(_is_status_page_enabled, conn):
		return templates.TemplateResponse(
			"status_disabled.html",
			{"request": request},
			status_code=404,
		)

	context = await _resolve_status_client_context(
		request,
		conn,
		user,
	)

	public_client_ip = await asyncio.to_thread(
		_resolve_public_client_ip,
		conn,
		context.client_ip,
		context.matched_iface,
		context.forwarded_ip,
	)
	client_geo_country_code: str | None = None
	client_geo_city: str | None = None
	client_geo_as_org: str | None = None
	if public_client_ip:
		geo_fields = _extract_geo_fields(await asyncio.to_thread(_lookup_ip_cached, public_client_ip))
		client_geo_country_code = geo_fields["country_code"]
		client_geo_city = geo_fields["city"]
		client_geo_as_org = geo_fields["as_org"]

	checks, outbound_ip = await _run_status_health_checks(context.client_ip, context.matched_iface)

	return templates.TemplateResponse("status.html", {
		"request": request,
		"client_ip": str(context.client_ip),
		"public_client_ip": public_client_ip or "n/a",
		"public_client_country_code": client_geo_country_code,
		"public_client_city": client_geo_city,
		"public_client_as_org": client_geo_as_org,
		"client_ip_source": context.auth_ip_source,
		"socket_ip": str(context.socket_ip) if context.socket_ip is not None else "n/a",
		"forwarded_ip": context.forwarded_ip or "n/a",
		"outbound_ip": outbound_ip or "n/a",
		"interface_name": context.matched_iface["name"] if context.matched_iface is not None else "n/a",
		"checks": checks,
	})
