#!/usr/bin/env python3
#
# app/api/frontend.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Frontend HTML routes."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import re
import sqlite3
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

import httpx
import nh3
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_peers import count_peers, get_peers_paginated
from ..db.sqlite_settings import get_dns_blocklist_enabled, get_setting
from ..db.sqlite_users import get_all_users
from ..dns import ingestion as dns_ingestion
from ..dns import unbound
from ..utils.config import get_config
from ..utils.deps import get_conn
from ..utils.geoip import lookup_ip
from ..utils.network import parse_ip
from ..utils.rate_limit import RATE_LIMIT_DEFAULT, limiter
from ..utils.version import BUILD_INFO, VERSION
from .acme import get_certs_dir, get_challenge_response
from .auth import _get_client_ip, get_current_user_optional

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
_STATUS_DNS_LEAK_VERIFY_WINDOW_SECONDS = 900
_STATUS_DNS_LEAK_VERIFY_MAX_QUERIES = 5000
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_APP_ROOT = Path("/app")
_outbound_ip_cache: tuple[str | None, str, float] | None = None
_dns_probe_cache: tuple[bool, str, float, tuple[str, ...]] | None = None
_outbound_ip_cache_lock = asyncio.Lock()
_dns_probe_cache_lock = asyncio.Lock()
# SECURITY: Keep outbound probe URLs hardcoded. Do not source from user input.

router = APIRouter(tags=["frontend"])

# Setup templates
_templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_path))

templates.env.globals["VERSION"] = VERSION
templates.env.globals["BUILD_INFO"] = BUILD_INFO


# ---------------------------------------------------------------------------
# Auth Helpers for Frontend (redirect-based, not exception-based)
# ---------------------------------------------------------------------------

class RedirectTo(Exception):
	"""Internal redirect signal used by auth dependencies."""

	def __init__(self, url: str):
		super().__init__(url)
		self.url = url


async def redirect_to_handler(_: Request, exc: RedirectTo) -> RedirectResponse:
	"""Convert dependency redirect signal to a pure 303 redirect response."""
	return RedirectResponse(url=exc.url, status_code=303)


@lru_cache(maxsize=4096)
def _lookup_ip_cached(ip_text: str) -> dict | None:
	"""Process-wide cached GeoIP lookup to reduce repeated MMDB reads."""
	try:
		return lookup_ip(ip_text)
	except Exception:
		_log.debug("GeoIP lookup failed for %s", ip_text, exc_info=True)
		return None

def _get_csrf_token(request: Request) -> str:
	"""Get CSRF token from request state, or empty string if not set."""
	token = getattr(request.state, "csrf_token", None)
	if not token:
		_log.error("CSRF token missing from request state — middleware misconfiguration")
		raise HTTPException(status_code=500, detail="Internal server error")
	return token


def _raise_redirect(url: str) -> None:
	"""Raise an HTTP redirect exception for dependency-based auth guards."""
	raise RedirectTo(url)


def require_user_or_redirect(
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
) -> sqlite3.Row:
	"""Dependency: return authenticated user or redirect to login."""
	if not user:
		_raise_redirect("/login")
	return user


def require_admin_or_redirect(
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> sqlite3.Row:
	"""Dependency: return admin user or redirect to dashboard."""
	if not user["is_admin"]:
		_raise_redirect("/ui/dashboard")
	return user


def _format_last_seen_label(handshake_epoch: int, *, now_epoch: int | None = None) -> tuple[str, str]:
	"""Format a handshake timestamp as a compact relative label + CSS class."""
	if handshake_epoch <= 0:
		return "Never", "text-muted"

	now = int(time.time()) if now_epoch is None else int(now_epoch)
	diff = max(0, now - handshake_epoch)
	# Only "Just now" and < 3 minutes are active (green), everything else inactive (gray)
	if diff < 60:
		return "Just now", "text-success"
	if diff < 180:  # 3 minutes
		return f"{diff // 60}m ago", "text-success"
	if diff < 3600:
		return f"{diff // 60}m ago", "text-muted"
	if diff < 86400:
		return f"{diff // 3600}h ago", "text-muted"
	return f"{diff // 86400}d ago", "text-muted"


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


def _extract_geo_fields(info: dict | None) -> dict[str, str | None]:
	"""Normalize GeoIP lookup results for template display fields."""
	if not info:
		return {
			"country_code": None,
			"city": None,
			"as_org": None,
		}

	country = str(info.get("country") or "").strip().lower()
	city = str(info.get("city") or "").strip() or None
	as_org = str(info.get("as_org") or "").strip()
	if not as_org:
		asn = int(info.get("asn") or 0)
		as_org = f"AS{asn}" if asn > 0 else ""

	return {
		"country_code": country if re.fullmatch(r"[a-z]{2}", country) else None,
		"city": city,
		"as_org": as_org or None,
	}


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


def _normalize_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
	"""Parse and normalize IPv4/IPv6 string, including IPv4-mapped IPv6."""
	return parse_ip(value)


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
	query_id = int(time.time() * 1000) & 0xFFFF
	header = query_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	labels = [part for part in _STATUS_PROBE_DOMAIN.strip(".").split(".") if part]
	qname_parts: list[bytes] = []
	for label in labels:
		encoded = label.encode("idna")
		if len(encoded) == 0 or len(encoded) > 63:
			return False, f"Invalid DNS probe label length in domain {_STATUS_PROBE_DOMAIN!r}"
		qname_parts.append(bytes((len(encoded),)) + encoded)
	qname = b"".join(qname_parts) + b"\x00"
	question = qname + b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
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
	"""Return a configuration-based DNS leak heuristic (not a runtime leak test).

	Returns:
		Tuple of (status, detail) where status is:
		- True: DNS is correctly configured
		- False: DNS configuration issue detected
		- None: Not applicable (not connected via WireGuard)
	"""
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
	"""Return DNS leak status with runtime verification from Unbound-ingested queries.

	Honest semantics:
	- OK only when configuration is correct and recent DNS traffic from this client
	  is observed in WireBuddy's own DNS logs.
	- WARN for misconfiguration or when runtime verification is currently unknown.
	- INFO when not connected via WireGuard (check not applicable).
	"""
	config_ok, config_detail = _dns_config_indicator(iface)
	if config_ok is None:
		return "info", config_detail
	if not config_ok:
		return "warn", config_detail

	try:
		cfg = get_config()
		queries = await asyncio.to_thread(
			dns_ingestion.read_recent_queries,
			Path(cfg.tsdb_dir),
			_STATUS_DNS_LEAK_VERIFY_MAX_QUERIES,
		)
	except Exception:
		_log.debug("DNS leak runtime verification unavailable", exc_info=True)
		return "warn", (
			f"{config_detail}; runtime verification unavailable "
			"(could not read recent DNS logs)"
		)

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
			return "ok", f"Verified via WireBuddy DNS logs ({age_label})"
		break

	window_min = max(1, window // 60)
	return "warn", (
		f"{config_detail}; no DNS query from this client seen in WireBuddy logs "
		f"within last {window_min} minutes (status currently unknown)"
	)


# ---------------------------------------------------------------------------
# Cached About Page Data (computed once at startup/first access)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_about_data() -> dict:
	"""Compute about page data once and cache it.
	
	This includes:
	- Python version
	- Package dependencies
	- License text
	- Changelog HTML (sanitized)
	- Unbound version
	"""
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

	def _normalize_pkg_name(name: str) -> str:
		return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())
	
	# Parse requirements.txt for package versions
	requirements_versions: dict[str, str] = {}
	requirements_paths = [
		_PROJECT_ROOT / "requirements.txt",
		_APP_ROOT / "requirements.txt",
	]
	for req_path in requirements_paths:
		if req_path.exists():
			try:
				for raw_line in req_path.read_text(encoding="utf-8").splitlines():
					line = raw_line.strip()
					if not line or line.startswith("#") or line.startswith("-"):
						continue
					for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
						if sep in line:
							pkg, ver = line.split(sep, 1)
							pkg = _normalize_pkg_name(pkg.split("[")[0])  # strip extras
							ver = ver.split("#")[0].split(";")[0].strip()  # strip comments + markers
							requirements_versions[pkg] = ver
							break
				break
			except Exception as e:
				_log.warning("Failed to parse requirements.txt: %s", e)
	
	# Build dependency list
	key_packages = [
		"fastapi", "httpx", "jinja2", "markdown", "pydantic", "pydantic-settings",
		"python-multipart", "qrcode", "slowapi", "uvicorn", "nh3",
	]
	
	dependencies = []
	for pkg_name in key_packages:
		ver = requirements_versions.get(_normalize_pkg_name(pkg_name))
		if ver:
			dependencies.append((pkg_name, ver))
		else:
			try:
				from importlib.metadata import version as get_pkg_version
				ver = get_pkg_version(pkg_name)
				dependencies.append((pkg_name, ver))
			except Exception:
				dependencies.append((pkg_name, "?"))
	
	# Get unbound version synchronously at startup (blocking is ok here)
	unbound_version = "not available"
	try:
		result = subprocess.run(
			["unbound", "-V"],
			capture_output=True,
			text=True,
			timeout=5,
		)
		output = (result.stdout or result.stderr or "").strip()
		if result.returncode == 0 and output:
			m = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
			if m:
				unbound_version = m.group(1)
			else:
				first_line = output.splitlines()[0] if output.splitlines() else ""
				unbound_version = first_line.strip() or "?"
	except FileNotFoundError:
		unbound_version = "not installed"
	except Exception as e:
		_log.debug("Failed to get unbound version: %s", e)
	
	# Get WireGuard version
	wireguard_version = "not available"
	try:
		result = subprocess.run(
			["wg", "--version"],
			capture_output=True,
			text=True,
			timeout=5,
		)
		output = (result.stdout or result.stderr or "").strip()
		if result.returncode == 0 and output:
			# Output is typically: "wireguard-tools v1.0.20210914"
			# Use regex to extract version number accurately
			m = re.search(r"v([\d.]+)", output)
			wireguard_version = m.group(1) if m else output
	except FileNotFoundError:
		wireguard_version = "not installed"
	except Exception as e:
		_log.debug("Failed to get WireGuard version: %s", e)
	
	dependencies.sort(key=lambda x: x[0].lower())
	
	# Read LICENSE
	license_text = "License file not found."
	for lp in [_PROJECT_ROOT / "LICENSE", _APP_ROOT / "LICENSE"]:
		if lp.exists():
			try:
				license_text = lp.read_text(encoding="utf-8")
				break
			except Exception:
				pass
	
	# Read CHANGELOG.md and render to HTML (sanitized)
	changelog_html = "<p>Changelog not found.</p>"
	for cp in [_PROJECT_ROOT / "CHANGELOG.md", _APP_ROOT / "CHANGELOG.md"]:
		if cp.exists():
			try:
				import markdown as _markdown
				raw = cp.read_text(encoding="utf-8")
				rendered = _markdown.markdown(raw, extensions=["extra", "sane_lists", "md_in_html"])
				allowed_tags = {
					"h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr",
					"ul", "ol", "li", "a", "strong", "em", "b", "i",
					"code", "pre", "blockquote", "table", "thead", "tbody",
					"tr", "th", "td", "dl", "dt", "dd", "abbr", "sup", "sub",
					"details", "summary",
				}
				allowed_attrs = {
					"a": {"href", "title"},
					"abbr": {"title"},
					"details": {"open"},
				}
				changelog_html = nh3.clean(
					rendered,
					tags=allowed_tags,
					attributes=allowed_attrs,
					strip_comments=True,
				)
				break
			except Exception as e:
				_log.warning("Failed to render changelog: %s", e)
				changelog_html = "<p>Failed to render changelog.</p>"
	
	return {
		"version": VERSION,
		"build_info": BUILD_INFO,
		"python_version": python_version,
		"wireguard_version": wireguard_version,
		"unbound_version": unbound_version,
		"dependencies": dependencies,
		"license_text": license_text,
		"changelog_html": changelog_html,
	}


# ---------------------------------------------------------------------------
# System Status API
# ---------------------------------------------------------------------------

@router.get("/api/system/status")
def get_system_status(request: Request):
	"""Get system status including key mismatch warning.
	
	This endpoint is intentionally unauthenticated to allow the banner
	to show on the login page as well.
	"""
	key_mismatch = getattr(request.app.state, "key_mismatch", False)
	return {
		"key_mismatch": key_mismatch,
	}


# ---------------------------------------------------------------------------
# Frontend Routes
# ---------------------------------------------------------------------------

@router.get("/")
def index(
	request: Request,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Root redirect to dashboard or login."""
	if user:
		return RedirectResponse(url="/ui/dashboard", status_code=303)
	return RedirectResponse(url="/login", status_code=303)


@router.get("/login", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def login_page(
	request: Request,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Login page."""
	if user:
		return RedirectResponse(url="/ui/dashboard", status_code=303)
	
	return templates.TemplateResponse("login.html", {
		"request": request,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/otp-setup", response_class=HTMLResponse)
def otp_setup_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""OTP onboarding page for first-time setup after admin enabled OTP."""
	# Check if OTP setup is actually pending
	if not user["otp_secret"] or bool(user["otp_enabled"]):
		# No pending setup - redirect to dashboard
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse("otp_setup.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/dashboard", response_class=HTMLResponse)
def dashboard(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Dashboard page."""
	
	return templates.TemplateResponse("dashboard.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/peers", response_class=HTMLResponse)
async def peers_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Peers management page."""

	# Server-side pagination to keep peers table usable on mobile/large datasets.
	try:
		page = int(request.query_params.get("page", "1"))
	except ValueError:
		page = 1
	try:
		page_size = int(request.query_params.get("page_size", "50"))
	except ValueError:
		page_size = 50
	page = max(1, page)
	page_size = min(max(10, page_size), 200)

	total_peers = count_peers(conn)
	total_pages = max(1, math.ceil(total_peers / page_size)) if total_peers else 1
	page = min(page, total_pages)
	peer_rows = get_peers_paginated(conn, page=page, page_size=page_size)
	peers: list[dict] = []
	now_epoch = int(time.time())
	unique_client_ips = list({
		str(row["last_client_ip"] or "").strip()
		for row in peer_rows
		if str(row["last_client_ip"] or "").strip()
	})
	geoip_cache: dict[str, dict | None] = {}
	if unique_client_ips:
		results = await asyncio.gather(*[
			asyncio.to_thread(_lookup_ip_cached, client_ip)
			for client_ip in unique_client_ips
		])
		geoip_cache = dict(zip(unique_client_ips, results, strict=True))

	for row in peer_rows:
		peer = dict(row)
		handshake_epoch = int(peer.get("last_handshake_at") or 0)
		last_seen_text, last_seen_class = _format_last_seen_label(handshake_epoch, now_epoch=now_epoch)
		peer["last_seen_text"] = last_seen_text
		peer["last_seen_class"] = last_seen_class
		peer["last_client_ip_display"] = str(peer.get("last_client_ip") or "").strip()
		peer["last_client_country_code"] = None
		peer["last_client_city"] = None
		peer["last_client_as_org"] = None

		if peer["last_client_ip_display"]:
			client_ip = peer["last_client_ip_display"]
			info = geoip_cache.get(client_ip)
			geo_fields = _extract_geo_fields(info)
			peer["last_client_country_code"] = geo_fields["country_code"]
			peer["last_client_city"] = geo_fields["city"]
			peer["last_client_as_org"] = geo_fields["as_org"]
		peers.append(peer)

	start_index = ((page - 1) * page_size) + 1 if total_peers else 0
	end_index = min(page * page_size, total_peers)

	return templates.TemplateResponse("peers.html", {
		"request": request,
		"user": user,
		"peers": peers,
		"page": page,
		"page_size": page_size,
		"total_pages": total_pages,
		"total_peers": total_peers,
		"has_prev": page > 1,
		"has_next": page < total_pages,
		"start_index": start_index,
		"end_index": end_index,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/users", response_class=HTMLResponse)
def users_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin_or_redirect),
):
	"""Users management page (admin only)."""
	users = get_all_users(conn)
	
	return templates.TemplateResponse("users.html", {
		"request": request,
		"user": user,
		"users": users,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/dns", response_class=HTMLResponse)
def dns_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""DNS ad-blocking page."""
	enable_blocklist = get_dns_blocklist_enabled(conn)
	
	return templates.TemplateResponse("dns.html", {
		"request": request,
		"user": user,
		"enable_blocklist": enable_blocklist,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/traffic", response_class=HTMLResponse)
def traffic_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Traffic usage page."""

	return templates.TemplateResponse("traffic.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/about", response_class=HTMLResponse)
def about_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""About page with version, dependencies, changelog, and license (cached)."""
	
	# Get cached about data (computed once at startup)
	about_data = _get_about_data()
	
	return templates.TemplateResponse("about.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
		**about_data,
	})


@router.get("/ui/settings", response_class=HTMLResponse)
def settings_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Settings page."""
	
	return templates.TemplateResponse("settings.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


def _resolve_status_client_context(
	request: Request,
	conn: sqlite3.Connection,
	user: Optional[sqlite3.Row],
) -> tuple[
	ipaddress.IPv4Address | ipaddress.IPv6Address,
	sqlite3.Row | None,
	str,
	ipaddress.IPv4Address | ipaddress.IPv6Address | None,
	str | None,
]:
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

	matched_iface = _find_client_interface(conn, client_ip_obj)

	if matched_iface is None:
		forwarded_for = request.headers.get("X-Forwarded-For", "")
		x_real_ip = request.headers.get("X-Real-IP", "")
		_log.debug(
			"/status: proxy headers X-Forwarded-For=%r X-Real-IP=%r socket_ip=%s",
			forwarded_for,
			x_real_ip,
			socket_ip_obj,
		)
		# Automatic fallback for reverse proxies on local/private hops.
		# Trust X-Forwarded-For / X-Real-IP if the connecting socket is a
		# private/loopback address (e.g. Caddy, nginx on same host/network).
		if socket_ip_obj and (forwarded_for or x_real_ip):
			is_local_proxy_hop = bool(
				socket_ip_obj.is_private
				or socket_ip_obj.is_loopback
				or socket_ip_obj.is_link_local
			)
			if is_local_proxy_hop:
				fallback_trusted = {str(socket_ip_obj)}
				forwarded_ip_obj = _pick_forwarded_client_ip(forwarded_for, fallback_trusted)
				forwarded_ip_value = str(forwarded_ip_obj) if forwarded_ip_obj is not None else None
				if forwarded_ip_obj is not None:
					forwarded_iface = _find_client_interface(conn, forwarded_ip_obj)
					if forwarded_iface is not None:
						client_ip_obj = forwarded_ip_obj
						matched_iface = forwarded_iface
						auth_ip_source = "x-forwarded-for-local-hop"
						_log.debug(
							"/status: accepted forwarded client IP %s via local proxy hop %s",
							client_ip_obj,
							socket_ip_obj,
						)
				# Also try X-Real-IP if X-Forwarded-For didn't match
				if matched_iface is None and x_real_ip:
					real_ip_obj = _normalize_ip(x_real_ip.split(",")[0].strip())
					if real_ip_obj is not None:
						real_ip_iface = _find_client_interface(conn, real_ip_obj)
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

	return client_ip_obj, matched_iface, auth_ip_source, socket_ip_obj, forwarded_ip_value


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
	# If not connected via WireGuard, skip DNS checks entirely
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
	if not _is_status_page_enabled(conn):
		return templates.TemplateResponse(
			"status_disabled.html",
			{"request": request},
			status_code=404,
		)

	client_ip_obj, matched_iface, auth_ip_source, socket_ip_obj, forwarded_ip_value = _resolve_status_client_context(
		request,
		conn,
		user,
	)

	public_client_ip = _resolve_public_client_ip(conn, client_ip_obj, matched_iface, forwarded_ip_value)
	client_geo_country_code: str | None = None
	client_geo_city: str | None = None
	client_geo_as_org: str | None = None
	if public_client_ip:
		geo_fields = _extract_geo_fields(_lookup_ip_cached(public_client_ip))
		client_geo_country_code = geo_fields["country_code"]
		client_geo_city = geo_fields["city"]
		client_geo_as_org = geo_fields["as_org"]

	checks, outbound_ip = await _run_status_health_checks(client_ip_obj, matched_iface)

	return templates.TemplateResponse("status.html", {
		"request": request,
		"client_ip": str(client_ip_obj),
		"public_client_ip": public_client_ip or "n/a",
		"public_client_country_code": client_geo_country_code,
		"public_client_city": client_geo_city,
		"public_client_as_org": client_geo_as_org,
		"client_ip_source": auth_ip_source,
		"socket_ip": str(socket_ip_obj) if socket_ip_obj is not None else "n/a",
		"forwarded_ip": forwarded_ip_value or "n/a",
		"outbound_ip": outbound_ip or "n/a",
		"interface_name": matched_iface["name"] if matched_iface is not None else "n/a",
		"checks": checks,
	})


# ---------------------------------------------------------------------------
# ACME HTTP-01 Challenge Endpoint (public, no auth)
# ---------------------------------------------------------------------------

# ACME token validation pattern (base64url characters only)
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def acme_challenge(request: Request, token: str):
	"""Serve ACME HTTP-01 challenge response for Let's Encrypt."""
	# Validate token format to prevent path traversal
	if not _ACME_TOKEN_RE.match(token):
		return PlainTextResponse("Invalid token", status_code=400)
	
	config = get_config()
	certs_dir = get_certs_dir(config)
	
	key_auth = get_challenge_response(token, certs_dir)
	if not key_auth:
		return PlainTextResponse("Challenge not found", status_code=404)
	
	return PlainTextResponse(key_auth)
