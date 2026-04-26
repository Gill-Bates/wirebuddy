#!/usr/bin/env python3
#
# app/api/frontend_pages.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Frontend page routes and non-status endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
import ipaddress
import markdown as _markdown

import nh3
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel

from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
from ..db import tsdb
from ..db.sqlite_interfaces import get_first_listen_port
from ..db.sqlite_nodes import get_all_nodes, get_all_tunnel_peer_ids, get_peers_count_by_node, is_node_sse_connected
from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_runtime import connect, close_connection, thread_connection
from ..db.sqlite_settings import get_dns_blocklist_enabled, get_node_speedtest_last_results, get_setting, get_speedtest_enabled, get_speedtest_ignore_peers
from ..db.sqlite_users import get_all_users
from ..dns import unbound
from ..utils.config import get_config
from ..utils.onboarding import ONBOARDING_STEPS
from ..utils.rate_limit import RATE_LIMIT_DEFAULT, RATE_LIMIT_HEAVY, limiter
from ..utils.tsdb_helpers import build_latest_by_node
from ..utils.version import BUILD_INFO, VERSION
from .acme import get_certs_dir, get_challenge_response
from .auth import coerce_db_bool, get_current_user_optional
from .frontend_shared import (
    extract_geo_fields,
    format_last_seen_label,
    get_csrf_token,
    lookup_ip_cached,
    parse_last_seen_epoch,
    parse_node_metadata,
    resolve_node_geo_ip,
    require_admin_or_redirect,
    require_user_or_redirect,
    router,
    templates,
)
from .wireguard_isolation import extract_peer_ips

_log = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_APP_ROOT = Path("/app")
# _APP_ROOT handles Docker deployments where the project is mounted at /app.
# _PROJECT_ROOT handles local development checkouts.
_SEARCH_ROOTS = (_PROJECT_ROOT, _APP_ROOT)
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")

# Configuration constants
_GEO_SEMAPHORE_LIMIT = 20  # Max concurrent GeoIP lookups
_SUBPROCESS_TIMEOUT = 5  # Timeout for system tool version checks (seconds)
_geo_lookup_semaphore: asyncio.Semaphore | None = None


def _get_geo_semaphore() -> asyncio.Semaphore:
	"""Return a lazily initialized process-local geo-IP semaphore."""
	global _geo_lookup_semaphore
	if _geo_lookup_semaphore is None:
		_geo_lookup_semaphore = asyncio.Semaphore(_GEO_SEMAPHORE_LIMIT)
	return _geo_lookup_semaphore


async def _batch_geoip_lookup(ips: list[str]) -> dict[str, dict | None]:
	"""Lookup GeoIP for multiple IPs with semaphore-bounded concurrency."""
	if not ips:
		return {}
	sem = _get_geo_semaphore()

	async def _bounded(ip: str) -> dict | None:
		async with sem:
			return await asyncio.to_thread(lookup_ip_cached, ip)

	results = await asyncio.gather(*[_bounded(ip) for ip in ips], return_exceptions=True)
	return {
		ip: (None if isinstance(r, Exception) else r)
		for ip, r in zip(ips, results)
	}


def _resolve_geo(fqdn: str | None) -> dict:
	"""Resolve FQDN to GeoIP fields, returning empty fields on failure."""
	if not fqdn:
		return extract_geo_fields(None)
	ip = resolve_node_geo_ip(fqdn)
	return extract_geo_fields(lookup_ip_cached(ip)) if ip else extract_geo_fields(None)


def _base_context(request: Request, user: sqlite3.Row, **extra) -> dict:
	"""Build a template context dict with guaranteed base keys."""
	return {
		"user": user,
		"csrf_token": get_csrf_token(request),
		**extra,
	}


def _redirect_if_setup_not_needed(condition_pending: bool, condition_done: bool) -> Response | None:
	"""Return a dashboard redirect when setup is not needed, else None."""
	if not condition_pending or condition_done:
		return RedirectResponse(url="/ui/dashboard", status_code=303)
	return None


def _find_existing_file(filename: str) -> Path | None:
	"""Resolve a project file from known search roots."""
	for root in _SEARCH_ROOTS:
		candidate = root / filename
		if candidate.exists():
			return candidate
	return None


class SystemStatusResponse(BaseModel):
	"""System status response model."""
	key_mismatch: bool


# Absolute paths for system tools (avoids PATH manipulation attacks)
_UNBOUND_PATH = "/usr/sbin/unbound"
_WG_PATH = "/usr/bin/wg"

# FQDN validation pattern (RFC 1123 hostname)
_FQDN_RE = re.compile(
	r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,63}$"
)


def _is_valid_hostname_or_ip(value: str) -> bool:
	"""Validate hostname or IP address with proper parsing.
	
	More robust than regex-only validation, especially for IPv6.
	"""
	clean = str(value or "").strip()
	if not clean:
		return False
	
	# Check for localhost
	if clean.lower() == "localhost":
		return True
	
	# Try parsing as IP address (IPv4 or IPv6)
	try:
		ipaddress.ip_address(clean)
		return True
	except ValueError:
		pass
	
	# Validate as FQDN using regex
	return _FQDN_RE.match(clean) is not None


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
	req_path = _find_existing_file("requirements.txt")
	if req_path is None:
		return {}
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


def _get_system_tool_version(cmd_path: str, version_pattern: str, version_flag: str = "--version") -> str:
	"""Get version string from a system tool.
	
	Args:
		cmd_path: Absolute path to the command
		version_pattern: Regex pattern to extract version (first group is used)
		version_flag: Flag to request version output
	
	Returns:
		Version string, "not installed", or "not available"
	"""
	try:
		result = subprocess.run(
			[cmd_path, version_flag],
			capture_output=True,
			text=True,
			timeout=_SUBPROCESS_TIMEOUT,
			check=False,  # Don't raise on non-zero exit (explicit)
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
	license_path = _find_existing_file("LICENSE")
	if license_path is not None:
		try:
			return license_path.read_text(encoding="utf-8")
		except (OSError, UnicodeDecodeError) as exc:
			_log.warning("Failed to read LICENSE: %s", exc)
	return "License file not found."


def _render_changelog() -> str:
	"""Render CHANGELOG.md to sanitized HTML."""
	changelog_path = _find_existing_file("CHANGELOG.md")
	if changelog_path is not None:
		try:
			raw = changelog_path.read_text(encoding="utf-8")
			rendered = _markdown.markdown(raw, extensions=["extra", "sane_lists"])
			return nh3.clean(
				rendered,
				tags=_CHANGELOG_ALLOWED_TAGS,
				attributes=_CHANGELOG_ALLOWED_ATTRS,
				url_schemes={"http", "https", "mailto"},
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
	"""Compute about page data once and cache it.

	Callers must treat the returned mapping as read-only.

	NOTE: ``lru_cache`` is safe here for the cache-hit path (read-only dict
	return is a pure Python operation protected by the GIL).  The only
	risk is a duplicate computation on the very first call from two concurrent
	coroutines.  ``_about_data_lock`` prevents that race.
	"""
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
	requirements_versions = _parse_requirements()

	return {
		"version": VERSION,
		"build_info": BUILD_INFO,
		"python_version": python_version,
		"timezone": _get_configured_timezone(),
		"wireguard_version": _get_system_tool_version(_WG_PATH, r"v([\d.]+)", "--version"),
		"unbound_version": _get_system_tool_version(_UNBOUND_PATH, r"(\d+\.\d+(?:\.\d+)?)", "-V"),
		"dependencies": _resolve_dependencies(requirements_versions),
		"license_text": _read_license(),
		"changelog_html": _render_changelog(),
	}


# Lock ensures only one coroutine populates _get_about_data's lru_cache on
# the first call, preventing duplicate heavy work on concurrent cache misses.
_about_data_lock = asyncio.Lock()


async def _get_about_data_cached() -> dict:
	"""Thread-safe async wrapper for _get_about_data."""
	import copy
	async with _about_data_lock:
		return copy.deepcopy(await asyncio.to_thread(_get_about_data))


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
async def get_system_status(request: Request) -> SystemStatusResponse:
	"""Get system status including key mismatch warning.
	
	Restricted to loopback addresses only (localhost health checks).
	Returns 403 for non-loopback clients to avoid leaking internal state.
	"""
	if not _is_loopback_request(request):
		# Security: Only allow localhost access to prevent info disclosure
		raise HTTPException(status_code=403, detail="Access denied: localhost only")
	
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
	if redirect := _redirect_if_setup_not_needed(has_secret, bool(user["otp_enabled"])):
		return redirect

	return templates.TemplateResponse(
		request,
		name="otp_setup.html",
		context=_base_context(request, user),
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
	if redirect := _redirect_if_setup_not_needed(passkey_pending, bool(user["passkey_enabled"])):
		return redirect

	return templates.TemplateResponse(
		request,
		name="passkey_setup.html",
		context=_base_context(request, user),
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
		context=_base_context(request, user),
	)


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

	def _load_peers_data() -> tuple[list[sqlite3.Row], set[int], dict[str, str]]:
		"""Load all peer data, tunnel peer IDs, and node names with a single connection."""
		with thread_connection(db_path) as conn:
			peers = get_all_peers(conn)
			tunnel_ids = get_all_tunnel_peer_ids(conn)
			nodes = get_all_nodes(conn)
			node_map = {n["id"]: n["name"] for n in nodes}
			return peers, tunnel_ids, node_map
	peer_rows, tunnel_peer_ids, node_id_to_name = await asyncio.to_thread(_load_peers_data)
	total_peers = len(peer_rows)
	peers: list[dict] = []
	now_epoch = int(time.time())
	unique_client_ips = list({
		ip
		for row in peer_rows
		if (ip := str(row["last_client_ip"] or "").strip())
	})
	geoip_cache = await _batch_geoip_lookup(unique_client_ips)

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
		
		# Add node name for display (None = Master)
		peer["node_name"] = node_id_to_name.get(peer.get("node_id")) if peer.get("node_id") else None
		peers.append(peer)

	# Sort peers: regular peers first (alphabetically), then node tunnel peers
	peers.sort(key=lambda p: (
		p["is_node_tunnel"],  # False (regular) before True (tunnel)
		p.get("interface", ""),
		p.get("name", "").lower(),
	))

	# Load nodes for the node selector in the Add Peer modal (admin only).
	# Run peers load and nodes load in parallel for admin requests.
	nodes_data: list = []
	local_fqdn = None
	local_country_code = None
	if coerce_db_bool(user["is_admin"]):
		def _load_nodes() -> tuple[list, str | None, str | None]:
			with thread_connection(db_path) as conn:
				nodes = []
				for n in get_all_nodes(conn):
					geo_fields = _resolve_geo(n["fqdn"])
					nodes.append({
						"id": n["id"],
						"name": n["name"],
						"fqdn": n["fqdn"],
						"geo_country_code": geo_fields["country_code"],
					})
				fqdn = (get_setting(conn, "wg_fqdn") or "").strip()
				local_geo = _resolve_geo(fqdn or None)
				return nodes, fqdn or None, local_geo.get("country_code")
		nodes_data, local_fqdn, local_country_code = await asyncio.to_thread(_load_nodes)

	return templates.TemplateResponse(
		request,
		name="peers.html",
		context=_base_context(
			request, user,
			peers=peers,
			total_peers=total_peers,
			nodes=nodes_data,
			local_fqdn=local_fqdn,
			local_country_code=local_country_code,
		),
	)


@router.get("/ui/users", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def users_page(
	request: Request,
	user: sqlite3.Row = Depends(require_admin_or_redirect),
) -> Response:
	"""Users management page (admin only).

	Runs blocking DB operations in a worker thread and uses a thread-local
	SQLite connection to avoid cross-thread connection usage.
	"""
	db_path = request.app.state.db_path

	def _load_users() -> list[sqlite3.Row]:
		with thread_connection(db_path) as conn:
			return get_all_users(conn)

	users = await asyncio.to_thread(_load_users)
	return templates.TemplateResponse(
		request,
		name="users.html",
		context=_base_context(request, user, users=users),
	)


@router.get("/ui/nodes", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def nodes_page(
	request: Request,
	user: sqlite3.Row = Depends(require_admin_or_redirect),
) -> Response:
	"""Remote nodes management page (admin only).

	Runs blocking DB/TSDB operations in a worker thread to avoid blocking
	the event loop and to keep SQLite connection usage thread-safe.
	"""
	cfg = get_config()
	db_path = request.app.state.db_path

	def _load_nodes_page_data() -> tuple[list[dict], int]:
		with thread_connection(db_path) as conn:
			nodes = get_all_nodes(conn)
			peer_counts = get_peers_count_by_node(conn)

			# Load TSDB history first, then let persisted SQLite results override it.
			speedtest_by_node: dict[str, dict] = {}
			try:
				since = datetime.now(UTC) - timedelta(days=90)
				points = tsdb.query(
					cfg.tsdb_dir,
					peer_key=SPEEDTEST_TSDB_KEY,
					metric=SPEEDTEST_TSDB_METRIC,
					since=since,
					limit=2000,
					latest=True,
				)
				speedtest_by_node = {
					str(node_id): point
					for node_id, point in build_latest_by_node(points).items()
					if node_id is not None
				}
			except Exception as exc:
				_log.debug("Failed to load speedtest data for nodes: %s", exc)

			# Persisted last results must win over TSDB history.
			speedtest_by_node.update(get_node_speedtest_last_results(conn, {str(n["id"]) for n in nodes}))

			# Batch resolve GeoIP for all nodes (performance optimization)
			unique_node_ips = []
			node_ip_map = {}  # node_id -> resolved_ip
			for n in nodes:
				resolved_ip = resolve_node_geo_ip(n["fqdn"])
				if resolved_ip:
					node_ip_map[n["id"]] = resolved_ip
					if resolved_ip not in unique_node_ips:
						unique_node_ips.append(resolved_ip)

			# Batch lookup GeoIP data
			geo_cache = {}
			for ip in unique_node_ips:
				geo_cache[ip] = extract_geo_fields(lookup_ip_cached(ip))

			nodes_data = []
			for n in nodes:
				resolved_ip = node_ip_map.get(n["id"])
				geo_fields = geo_cache.get(resolved_ip) if resolved_ip else extract_geo_fields(None)
				# Parse metadata JSON for version
				meta = parse_node_metadata(n["metadata"], node_id=n["id"])
				node_version = (meta or {}).get("version")

				# Shared parser keeps datetime/string/None handling consistent across pages.
				last_seen_epoch = parse_last_seen_epoch(n["last_seen"])
				last_seen_label = format_last_seen_label(last_seen_epoch)

				# Get last speedtest for this node
				last_speedtest = speedtest_by_node.get(n["id"])

				try:
					show_on_dashboard = bool(n["show_on_dashboard"])
				except (KeyError, IndexError):
					show_on_dashboard = True

				nodes_data.append({
					"id": n["id"],
					"name": n["name"],
					"fqdn": n["fqdn"],
					"wg_port": n["wg_port"],
					"status": n["status"],
					"last_seen": n["last_seen"],
					"last_seen_text": last_seen_label.text,
					"last_seen_class": last_seen_label.css_class,
					"enrolled_at": n["enrolled_at"],
					"created_at": n["created_at"],
					"peer_count": peer_counts.get(n["id"], 0),
					"geo_country_code": geo_fields["country_code"],
					"geo_city": geo_fields["city"],
					"geo_as_org": geo_fields["as_org"],
					"node_version": node_version,
					"last_speedtest": last_speedtest,
					"sse_connected": is_node_sse_connected(conn, n["id"]) if n["status"] == "online" else False,
					"show_on_dashboard": show_on_dashboard,
				})

			# Get default WireGuard port from first interface for pre-filling the Add Node modal
			default_wg_port = get_first_listen_port(conn, default=51820)
			return nodes_data, default_wg_port

	nodes_data, default_wg_port = await asyncio.to_thread(_load_nodes_page_data)
	return templates.TemplateResponse(
		request,
		name="nodes.html",
		context=_base_context(
			request, user,
			nodes=nodes_data,
			default_wg_port=default_wg_port,
		),
	)


@router.get("/ui/dns", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def dns_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""DNS ad-blocking page.

	Runs blocking DB/system checks in a worker thread.
	"""
	db_path = request.app.state.db_path

	def _load_dns_page_data() -> tuple[bool, bool]:
		with thread_connection(db_path) as conn:
			enable_blocklist = get_dns_blocklist_enabled(conn)
			dns_unavailable = not unbound.is_unbound_installed()
			return enable_blocklist, dns_unavailable

	enable_blocklist, dns_unavailable = await asyncio.to_thread(_load_dns_page_data)
	is_admin = coerce_db_bool(user["is_admin"])
	return templates.TemplateResponse(
		request,
		name="dns.html",
		context=_base_context(
			request, user,
			is_admin=is_admin,
			enable_blocklist=enable_blocklist,
			dns_unavailable=dns_unavailable,
		),
	)


@router.get("/ui/traffic", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def traffic_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Traffic usage page.

	Runs blocking DB reads in a worker thread.
	"""
	db_path = request.app.state.db_path

	def _load_traffic_page_data() -> bool:
		with thread_connection(db_path) as conn:
			return get_setting(conn, "traffic_analysis_enabled") == "1"

	traffic_analysis_enabled = await asyncio.to_thread(_load_traffic_page_data)
	is_admin = coerce_db_bool(user["is_admin"])
	return templates.TemplateResponse(
		request,
		name="traffic.html",
		context=_base_context(
			request, user,
			is_admin=is_admin,
			traffic_analysis_enabled=traffic_analysis_enabled,
		),
	)


@router.get("/ui/about", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def about_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""About page with version, dependencies, changelog, and license.
	
	Note: Data is cached via @lru_cache for performance. Cache persists until
	server restart — runtime changes to requirements.txt, LICENSE, or CHANGELOG.md
	won't be reflected without restart.
	
	First call (cache miss) runs blocking operations in thread pool to avoid
	blocking the event loop.
	"""
	about_data = dict(await _get_about_data_cached())
	return templates.TemplateResponse(
		request,
		name="about.html",
		context=_base_context(request, user, **about_data),
	)


@router.get("/ui/settings", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def settings_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Settings page."""
	# Load toggle states server-side to avoid visual jump on page load.
	# Security: use configured FQDN only, never trust request.url.hostname.
	db_path = request.app.state.db_path

	def _load_settings_page_data() -> dict[str, object]:
		with thread_connection(db_path) as conn:
			wg_fqdn = get_setting(conn, "wg_fqdn") or ""
			raw_host = wg_fqdn.strip().strip("[]") if wg_fqdn else "localhost"

			# Validate hostname/IP to prevent URL injection attacks.
			if not _is_valid_hostname_or_ip(raw_host):
				_log.warning("Invalid FQDN in settings: %r", raw_host[:50])
				raw_host = "localhost"

			url_host = f"[{raw_host}]" if ":" in raw_host else raw_host

			return {
				"enable_status_page": get_setting(conn, "enable_status_page") == "1",
				"enable_swagger": get_setting(conn, "enable_swagger") == "1",
				"gui_localhost_only": get_setting(conn, "gui_localhost_only") == "1",
				"wg_use_psk": get_setting(conn, "wg_use_psk", "1") == "1",  # Default: enabled
				"traffic_analysis_enabled": get_setting(conn, "traffic_analysis_enabled") == "1",
				"speedtest_enabled": get_speedtest_enabled(conn),
				"speedtest_ignore_peers": get_speedtest_ignore_peers(conn),
				"status_page_url": f"https://{url_host}/status",
				"swagger_url": f"https://{url_host}/swagger",
			}

	settings = await asyncio.to_thread(_load_settings_page_data)
	return templates.TemplateResponse(
		request,
		name="settings.html",
		context=_base_context(request, user, settings=settings),
	)


@router.get("/ui/fragments/onboarding", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def onboarding_modal_fragment(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
) -> Response:
	"""Serve the onboarding modal fragment on-demand.
	
	Returns only the modal HTML (no page wrapper), used for lazy-loading
	by onboarding.js to reduce initial page load size.
	
	The onboarding steps are defined in app.utils.onboarding.ONBOARDING_STEPS
	to enable testing, internationalization, and dynamic modifications
	without template changes.
	"""
	return templates.TemplateResponse(
		request,
		name="fragments/onboarding_modal.html",
		context={
			"user": user,
			"onboarding_steps": ONBOARDING_STEPS,
		},
	)


@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def acme_challenge(request: Request, token: str) -> PlainTextResponse:
	"""Serve ACME HTTP-01 challenge response for Let's Encrypt.
	
	Note: Sync handler so FastAPI runs it in threadpool (get_challenge_response
	performs file I/O and should not block the event loop).
	"""
	# Always return 404 for invalid or missing tokens to prevent timing attacks
	if not _ACME_TOKEN_RE.match(token):
		_log.warning("ACME challenge: invalid token format (length=%d)", len(token))
		return PlainTextResponse("Challenge not found", status_code=404)

	config = get_config()
	certs_dir = get_certs_dir(config)

	key_auth = get_challenge_response(token, certs_dir)
	if not key_auth:
		_log.info("ACME challenge: token not found: %s", token[:20])
		return PlainTextResponse("Challenge not found", status_code=404)

	return PlainTextResponse(key_auth)
