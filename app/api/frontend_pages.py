#!/usr/bin/env python3
#
# app/api/frontend_pages.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Frontend page routes and non-status endpoints."""

from __future__ import annotations

import asyncio
import json
import socket
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path
import ipaddress
import markdown as _markdown

import nh3
from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel

from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_runtime import connect, close_connection
from ..db.sqlite_settings import get_dns_blocklist_enabled, get_setting, get_speedtest_enabled
from ..db.sqlite_users import get_all_users
from ..dns import unbound
from ..utils.config import get_config
from ..utils.deps import get_conn
from ..utils.rate_limit import RATE_LIMIT_DEFAULT, RATE_LIMIT_HEAVY, limiter
from ..utils.version import BUILD_INFO, VERSION
from .acme import get_certs_dir, get_challenge_response
from .auth import get_current_user_optional
from .frontend_shared import (
    extract_geo_fields,
    format_last_seen_label,
    get_csrf_token,
    lookup_ip_cached,
    require_admin_or_redirect,
    require_user_or_redirect,
    router,
    templates,
)
from .wireguard_isolation import extract_peer_ips

_log = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_APP_ROOT = Path("/app")
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")

# Semaphore to limit concurrent geo-IP lookups (prevents thread pool exhaustion)
_GEO_LOOKUP_SEMAPHORE = asyncio.Semaphore(20)


class SystemStatusResponse(BaseModel):
	"""System status response model."""
	key_mismatch: bool


# Absolute paths for system tools (avoids PATH manipulation attacks)
_UNBOUND_PATH = "/usr/sbin/unbound"
_WG_PATH = "/usr/bin/wg"

# Hostname/IP validation pattern for FQDN (RFC 1123 hostname or IPv4/IPv6)
_HOSTNAME_RE = re.compile(
	r"^(?:"
	r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,63}"  # FQDN
	r"|localhost"  # localhost
	r"|(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
	r"|[a-fA-F0-9:]+(?:%[a-zA-Z0-9]+)?"  # IPv6 (simplified)
	r")$"
)


@lru_cache(maxsize=1024)
def _resolve_node_geo_ip(host_or_ip: str) -> str | None:
	"""Resolve a node FQDN/IP to a concrete IP for GeoIP/ASN lookups."""
	clean = str(host_or_ip or "").strip().strip("[]")
	if not clean:
		return None

	try:
		return str(ipaddress.ip_address(clean))
	except ValueError:
		pass

	if _HOSTNAME_RE.fullmatch(clean) is None:
		return None

	try:
		addrinfo = socket.getaddrinfo(clean, None, type=socket.SOCK_STREAM)
	except OSError:
		return None

	for _family, _socktype, _proto, _canonname, sockaddr in addrinfo:
		ip_text = str(sockaddr[0]).split("%", 1)[0]
		try:
			return str(ipaddress.ip_address(ip_text))
		except ValueError:
			continue

	return None

# Key packages to display in about page
_KEY_PACKAGES = [
	"fastapi", "httpx", "jinja2", "markdown", "Pillow", "pydantic", "pydantic-settings",
	"python-multipart", "qrcode", "slowapi", "uvicorn", "nh3",
]

# Allowed HTML tags/attrs for changelog rendering
_CHANGELOG_ALLOWED_TAGS = {
	"h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr",
	"ul", "ol", "li", "a", "strong", "em", "b", "i",
	"code", "pre", "blockquote", "table", "thead", "tbody",
	"tr", "th", "td", "dl", "dt", "dd", "abbr", "sup", "sub",
	"details", "summary",
}
_CHANGELOG_ALLOWED_ATTRS = {
	"a": {"href", "title"},
	"abbr": {"title"},
	"details": {"open"},
}


def _normalize_pkg_name(name: str) -> str:
	"""Normalize package name for comparison (PEP 503)."""
	return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())


def _parse_requirements() -> dict[str, str]:
	"""Parse requirements.txt and return package->version mapping."""
	requirements_paths = [
		_PROJECT_ROOT / "requirements.txt",
		_APP_ROOT / "requirements.txt",
	]
	for req_path in requirements_paths:
		if req_path.exists():
			try:
				versions: dict[str, str] = {}
				for raw_line in req_path.read_text(encoding="utf-8").splitlines():
					line = raw_line.strip()
					if not line or line.startswith("#") or line.startswith("-"):
						continue
					for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
						if sep in line:
							pkg, ver = line.split(sep, 1)
							pkg = _normalize_pkg_name(pkg.split("[")[0])
							ver = ver.split("#")[0].split(";")[0].strip()
							versions[pkg] = ver
							break
				return versions
			except (OSError, ValueError, UnicodeDecodeError) as exc:
				_log.warning("Failed to parse requirements.txt: %s", exc)
	return {}


def _resolve_dependencies(requirements_versions: dict[str, str]) -> list[tuple[str, str]]:
	"""Resolve dependency versions from requirements or importlib.metadata."""
	from importlib.metadata import PackageNotFoundError, version as get_pkg_version

	dependencies = []
	for pkg_name in _KEY_PACKAGES:
		ver = requirements_versions.get(_normalize_pkg_name(pkg_name))
		if ver:
			dependencies.append((pkg_name, ver))
		else:
			try:
				ver = get_pkg_version(pkg_name)
				dependencies.append((pkg_name, ver))
			except PackageNotFoundError:
				_log.debug("Package not found: %s", pkg_name)
				dependencies.append((pkg_name, "?"))
	dependencies.sort(key=lambda x: x[0].lower())
	return dependencies


def _get_system_tool_version(cmd_path: str, version_pattern: str) -> str:
	"""Get version string from a system tool.
	
	Args:
		cmd_path: Absolute path to the command
		version_pattern: Regex pattern to extract version (first group is used)
	
	Returns:
		Version string, "not installed", or "not available"
	"""
	try:
		result = subprocess.run(
			[cmd_path, "-V" if "unbound" in cmd_path else "--version"],
			capture_output=True,
			text=True,
			timeout=5,
		)
		output = (result.stdout or result.stderr or "").strip()
		if result.returncode == 0 and output:
			m = re.search(version_pattern, output)
			if m:
				return m.group(1)
			# Fallback: return first line
			first_line = output.splitlines()[0] if output.splitlines() else ""
			return first_line.strip() or "?"
		return "not available"
	except FileNotFoundError:
		return "not installed"
	except (subprocess.TimeoutExpired, OSError) as exc:
		_log.warning("Failed to get version from %s: %s", cmd_path, exc)
		return "not available"


def _read_license() -> str:
	"""Read LICENSE file content."""
	for lp in [_PROJECT_ROOT / "LICENSE", _APP_ROOT / "LICENSE"]:
		if lp.exists():
			try:
				return lp.read_text(encoding="utf-8")
			except (OSError, UnicodeDecodeError) as exc:
				_log.warning("Failed to read LICENSE: %s", exc)
	return "License file not found."


def _render_changelog() -> str:
	"""Render CHANGELOG.md to sanitized HTML."""
	for cp in [_PROJECT_ROOT / "CHANGELOG.md", _APP_ROOT / "CHANGELOG.md"]:
		if cp.exists():
			try:
				raw = cp.read_text(encoding="utf-8")
				rendered = _markdown.markdown(raw, extensions=["extra", "sane_lists", "md_in_html"])
				return nh3.clean(
					rendered,
					tags=_CHANGELOG_ALLOWED_TAGS,
					attributes=_CHANGELOG_ALLOWED_ATTRS,
					strip_comments=True,
				)
			except (OSError, UnicodeDecodeError) as exc:
				_log.warning("Failed to read changelog: %s", exc)
				return "<p>Failed to read changelog.</p>"
			except (ValueError, TypeError) as exc:
				_log.warning("Failed to render changelog: %s", exc)
				return "<p>Failed to render changelog.</p>"
	return "<p>Changelog not found.</p>"


def _get_configured_timezone() -> str:
	"""Return the configured local timezone label for display."""
	get_config()  # Ensure settings.env is loaded before reading env vars.

	tz_name = os.getenv("TZ", "").strip()
	if tz_name:
		return tz_name

	tz_file = Path("/etc/timezone")
	try:
		tz_text = tz_file.read_text(encoding="utf-8").strip()
		if tz_text:
			return tz_text
	except OSError:
		pass

	try:
		localtime_path = Path("/etc/localtime").resolve()
		zoneinfo_root = Path("/usr/share/zoneinfo")
		if zoneinfo_root in localtime_path.parents:
			return str(localtime_path.relative_to(zoneinfo_root))
	except OSError:
		pass

	return "System local time"


@lru_cache(maxsize=1)
def _get_about_data() -> dict:
	"""Compute about page data once and cache it."""
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
	requirements_versions = _parse_requirements()

	return {
		"version": VERSION,
		"build_info": BUILD_INFO,
		"python_version": python_version,
		"timezone": _get_configured_timezone(),
		"wireguard_version": _get_system_tool_version(_WG_PATH, r"v([\d.]+)"),
		"unbound_version": _get_system_tool_version(_UNBOUND_PATH, r"(\d+\.\d+(?:\.\d+)?)"),
		"dependencies": _resolve_dependencies(requirements_versions),
		"license_text": _read_license(),
		"changelog_html": _render_changelog(),
	}


def _is_loopback_request(request: Request) -> bool:
	"""Check if request originates from loopback address."""
	client_host = request.client.host if request.client else None
	if not client_host:
		return False
	try:
		addr = ipaddress.ip_address(client_host)
		return addr.is_loopback
	except ValueError:
		return False


@router.get("/api/system/status", response_model=SystemStatusResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def get_system_status(request: Request) -> SystemStatusResponse:
	"""Get system status including key mismatch warning.
	
	Restricted to loopback addresses only (localhost health checks).
	Returns key_mismatch=False for non-loopback clients to avoid leaking
	internal configuration state.
	"""
	if not _is_loopback_request(request):
		# Don't leak internal state to external clients
		return SystemStatusResponse(key_mismatch=False)
	key_mismatch = getattr(request.app.state, "key_mismatch", False)
	return SystemStatusResponse(key_mismatch=key_mismatch)


@router.get("/", response_class=RedirectResponse)
def index(
	request: Request,
	user: sqlite3.Row | None = Depends(get_current_user_optional),
) -> RedirectResponse:
	"""Root redirect to dashboard or login."""
	if user:
		return RedirectResponse(url="/ui/dashboard", status_code=303)
	return RedirectResponse(url="/login", status_code=303)


@router.get("/login", response_class=Response)
@limiter.limit(RATE_LIMIT_DEFAULT)
def login_page(
	request: Request,
	user: sqlite3.Row | None = Depends(get_current_user_optional),
) -> Response:
	"""Login page."""
	if user:
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse(
		request,
		name="login.html",
		context={
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/otp-setup", response_class=Response)
@limiter.limit(RATE_LIMIT_DEFAULT)
def otp_setup_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""OTP onboarding page for first-time setup after admin enabled OTP.
	
	Redirects to dashboard if:
	- User has no OTP secret (setup not initiated by admin), OR
	- User has already confirmed OTP (otp_enabled=True)
	"""
	has_secret = bool(user["otp_secret"])
	already_enabled = bool(user["otp_enabled"])
	if not has_secret or already_enabled:
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse(
		request,
		name="otp_setup.html",
		context={
			"user": user,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/passkey-setup", response_class=Response)
@limiter.limit(RATE_LIMIT_DEFAULT)
def passkey_setup_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Passkey onboarding page for first-time setup after admin enabled passkeys.
	
	Redirects to dashboard if:
	- User has no passkey_pending flag (setup not initiated by admin), OR
	- User has already registered a passkey (passkey_enabled=True)
	"""
	passkey_pending = bool(user["passkey_pending"])
	already_enabled = bool(user["passkey_enabled"])
	if not passkey_pending or already_enabled:
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse(
		request,
		name="passkey_setup.html",
		context={
			"user": user,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/dashboard", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def dashboard(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Dashboard page."""
	return templates.TemplateResponse(
		request,
		name="dashboard.html",
		context={
			"user": user,
			"csrf_token": get_csrf_token(request),
		},
	)


# Batch size for geo-IP lookups to limit memory pressure from coroutine objects
_GEO_LOOKUP_BATCH_SIZE = 100


@router.get("/ui/peers", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_HEAVY)  # Expensive: DB query + geo-IP lookups
async def peers_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Peers management page with all peers and geo-IP lookups.
	
	Note: Database connection is created inside the thread pool to avoid
	SQLite threading issues (connections are not thread-safe).
	"""
	db_path = request.app.state.db_path

	def _load_all_peers() -> list[sqlite3.Row]:
		"""Load all peer data in thread pool with dedicated connection."""
		thread_conn = connect(db_path)
		try:
			return get_all_peers(thread_conn)
		finally:
			close_connection(thread_conn)

	def _load_tunnel_peer_ids() -> set[int]:
		"""Load all tunnel peer IDs (node system peers, not user-editable)."""
		from ..db.sqlite_nodes import get_all_tunnel_peer_ids
		thread_conn = connect(db_path)
		try:
			return get_all_tunnel_peer_ids(thread_conn)
		finally:
			close_connection(thread_conn)

	peer_rows = await asyncio.to_thread(_load_all_peers)
	tunnel_peer_ids = await asyncio.to_thread(_load_tunnel_peer_ids)
	total_peers = len(peer_rows)
	peers: list[dict] = []
	now_epoch = int(time.time())
	unique_client_ips = list({
		str(row["last_client_ip"] or "").strip()
		for row in peer_rows
		if str(row["last_client_ip"] or "").strip()
	})
	geoip_cache: dict[str, dict | None] = {}
	if unique_client_ips:
		# Use semaphore to limit concurrent geo-IP lookups (prevents thread pool exhaustion)
		async def _bounded_lookup(ip: str) -> dict | None:
			async with _GEO_LOOKUP_SEMAPHORE:
				return await asyncio.to_thread(lookup_ip_cached, ip)
		
		# Process in batches to limit memory pressure from coroutine objects
		for batch_start in range(0, len(unique_client_ips), _GEO_LOOKUP_BATCH_SIZE):
			batch = unique_client_ips[batch_start:batch_start + _GEO_LOOKUP_BATCH_SIZE]
			results = await asyncio.gather(*[
				_bounded_lookup(client_ip)
				for client_ip in batch
			], return_exceptions=True)
			
			# Filter out exceptions from failed lookups
			for ip, result in zip(batch, results):
				if isinstance(result, BaseException):
					_log.debug("Geo-IP lookup failed for %s: %s", ip, result)
					geoip_cache[ip] = None
				else:
					geoip_cache[ip] = result

	for row in peer_rows:
		peer = dict(row)
		handshake_epoch = int(peer.get("last_handshake_at") or 0)
		last_seen = format_last_seen_label(handshake_epoch, now_epoch=now_epoch)
		peer["last_seen_text"] = last_seen.text
		peer["last_seen_class"] = last_seen.css_class
		peer["last_seen_active"] = last_seen.is_active
		peer["last_client_ip_display"] = str(peer.get("last_client_ip") or "").strip()
		peer["last_client_country_code"] = None
		peer["last_client_city"] = None
		peer["last_client_as_org"] = None
		
		# Extract IPv4 and IPv6 from peer_address for separate display
		ipv4, ipv6 = extract_peer_ips(peer.get("peer_address"))
		peer["peer_ipv4"] = ipv4
		peer["peer_ipv6"] = ipv6

		if peer["last_client_ip_display"]:
			client_ip = peer["last_client_ip_display"]
			info = geoip_cache.get(client_ip)
			geo_fields = extract_geo_fields(info)
			peer["last_client_country_code"] = geo_fields["country_code"]
			peer["last_client_city"] = geo_fields["city"]
			peer["last_client_as_org"] = geo_fields["as_org"]

		# Mark node tunnel peers (system peers not editable by users)
		peer["is_node_tunnel"] = peer["id"] in tunnel_peer_ids
		peers.append(peer)

	# Sort peers: regular peers first (alphabetically), then node tunnel peers
	peers.sort(key=lambda p: (
		p["is_node_tunnel"],  # False (regular) before True (tunnel)
		p.get("interface", ""),
		p.get("name", "").lower(),
	))

	# Load nodes for the node selector in the Add Peer modal (admin only)
	nodes_data = []
	if user["is_admin"]:
		def _load_nodes() -> list:
			from ..db.sqlite_nodes import get_all_nodes as db_get_all_nodes
			thread_conn = connect(db_path)
			try:
				nodes = []
				for n in db_get_all_nodes(thread_conn):
					resolved_geo_ip = _resolve_node_geo_ip(n["fqdn"])
					geo_fields = extract_geo_fields(lookup_ip_cached(resolved_geo_ip)) if resolved_geo_ip else {
						"country_code": None,
						"city": None,
						"as_org": None,
					}
					nodes.append({
						"id": n["id"],
						"name": n["name"],
						"fqdn": n["fqdn"],
						"geo_country_code": geo_fields["country_code"],
					})
				return nodes
			finally:
				close_connection(thread_conn)
		nodes_data = await asyncio.to_thread(_load_nodes)

	return templates.TemplateResponse(
		request,
		name="peers.html",
		context={
			"user": user,
			"peers": peers,
			"total_peers": total_peers,
			"nodes": nodes_data,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/users", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def users_page(
	request: Request,
	user: sqlite3.Row = Depends(require_admin_or_redirect),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
	"""Users management page (admin only).
	
	Note: This is a sync handler, so FastAPI runs it in a threadpool worker.
	The conn dependency is created and used in the same thread — safe.
	Auth check happens before DB connection to avoid wasting resources.
	"""
	users = get_all_users(conn)
	return templates.TemplateResponse(
		request,
		name="users.html",
		context={
			"user": user,
			"users": users,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/nodes", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def nodes_page(
	request: Request,
	user: sqlite3.Row = Depends(require_admin_or_redirect),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
	"""Remote nodes management page (admin only)."""
	from ..db.sqlite_nodes import get_all_nodes, get_peers_count_by_node
	nodes = get_all_nodes(conn)
	peer_counts = get_peers_count_by_node(conn)
	nodes_data = []
	for n in nodes:
		resolved_geo_ip = _resolve_node_geo_ip(n["fqdn"])
		geo_fields = extract_geo_fields(lookup_ip_cached(resolved_geo_ip)) if resolved_geo_ip else {
			"country_code": None,
			"city": None,
			"as_org": None,
		}
		# Parse metadata JSON for version
		node_version = None
		if n["metadata"]:
			try:
				meta = json.loads(n["metadata"]) if isinstance(n["metadata"], str) else n["metadata"]
				node_version = meta.get("version")
			except (json.JSONDecodeError, TypeError):
				pass
		nodes_data.append({
			"id": n["id"],
			"name": n["name"],
			"fqdn": n["fqdn"],
			"wg_port": n["wg_port"],
			"status": n["status"],
			"last_seen": n["last_seen"],
			"enrolled_at": n["enrolled_at"],
			"created_at": n["created_at"],
			"peer_count": peer_counts.get(n["id"], 0),
			"geo_country_code": geo_fields["country_code"],
			"geo_city": geo_fields["city"],
			"geo_as_org": geo_fields["as_org"],
			"node_version": node_version,
		})
	# Get default WireGuard port from first interface for pre-filling the Add Node modal
	first_iface = conn.execute("SELECT listen_port FROM interfaces LIMIT 1").fetchone()
	default_wg_port = first_iface["listen_port"] if first_iface else 51820
	return templates.TemplateResponse(
		request,
		name="nodes.html",
		context={
			"user": user,
			"nodes": nodes_data,
			"default_wg_port": default_wg_port,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/dns", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def dns_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
	"""DNS ad-blocking page.
	
	Note: This is a sync handler, so FastAPI runs it in a threadpool worker.
	The conn dependency is created and used in the same thread — safe.
	Auth check happens before DB connection to avoid wasting resources.
	"""
	enable_blocklist = get_dns_blocklist_enabled(conn)
	dns_unavailable = not unbound.is_unbound_installed()
	return templates.TemplateResponse(
		request,
		name="dns.html",
		context={
			"user": user,
			"enable_blocklist": enable_blocklist,
			"dns_unavailable": dns_unavailable,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/traffic", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def traffic_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
	"""Traffic usage page.
	
	Auth check happens before DB connection to avoid wasting resources.
	"""
	traffic_analysis_enabled = get_setting(conn, "traffic_analysis_enabled") == "1"
	return templates.TemplateResponse(
		request,
		name="traffic.html",
		context={
			"user": user,
			"traffic_analysis_enabled": traffic_analysis_enabled,
			"csrf_token": get_csrf_token(request),
		},
	)


@router.get("/ui/about", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def about_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""About page with version, dependencies, changelog, and license.
	
	Note: Data is cached via @lru_cache for performance. Cache persists until
	server restart — runtime changes to requirements.txt, LICENSE, or CHANGELOG.md
	won't be reflected without restart.
	"""
	about_data = _get_about_data()
	return templates.TemplateResponse(
		request,
		name="about.html",
		context={
			"user": user,
			"csrf_token": get_csrf_token(request),
			**about_data,
		},
	)


@router.get("/ui/settings", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def settings_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
	"""Settings page."""
	# Load toggle states server-side to avoid visual jump on page load
	# Calculate URLs server-side to prevent flickering
	wg_fqdn = get_setting(conn, "wg_fqdn") or ""
	raw_host = wg_fqdn.strip().strip("[]") if wg_fqdn else str(request.url.hostname or "localhost")
	
	# Validate hostname/IP to prevent URL injection attacks
	if not _HOSTNAME_RE.match(raw_host):
		_log.warning("Invalid FQDN in settings: %r", raw_host[:50])
		raw_host = "localhost"  # Fallback to safe default
	
	url_host = f"[{raw_host}]" if ":" in raw_host else raw_host
	
	settings = {
		"enable_status_page": get_setting(conn, "enable_status_page") == "1",
		"enable_swagger": get_setting(conn, "enable_swagger") == "1",
		"gui_localhost_only": get_setting(conn, "gui_localhost_only") == "1",
		"wg_use_psk": get_setting(conn, "wg_use_psk") == "1",
		"traffic_analysis_enabled": get_setting(conn, "traffic_analysis_enabled") == "1",
		"speedtest_enabled": get_speedtest_enabled(conn),
		"status_page_url": f"https://{url_host}/status",
		"swagger_url": f"https://{url_host}/swagger",
	}
	return templates.TemplateResponse(
		request,
		name="settings.html",
		context={
			"user": user,
			"csrf_token": get_csrf_token(request),
			"settings": settings,
		},
	)


@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def acme_challenge(request: Request, token: str) -> PlainTextResponse:
	"""Serve ACME HTTP-01 challenge response for Let's Encrypt.
	
	Note: Sync handler so FastAPI runs it in threadpool (get_challenge_response
	performs file I/O and should not block the event loop).
	"""
	if not _ACME_TOKEN_RE.match(token):
		_log.warning("ACME challenge: invalid token format (length=%d)", len(token))
		return PlainTextResponse("Invalid token", status_code=400)

	config = get_config()
	certs_dir = get_certs_dir(config)

	key_auth = get_challenge_response(token, certs_dir)
	if not key_auth:
		_log.info("ACME challenge: token not found: %s", token[:20])
		return PlainTextResponse("Challenge not found", status_code=404)

	return PlainTextResponse(key_auth)
