#!/usr/bin/env python3
#
# app/api/frontend_pages.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Frontend page routes and non-status endpoints."""

from __future__ import annotations

import asyncio
import logging
import math
import re
import sqlite3
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Optional

import nh3
from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from ..db.sqlite_peers import count_peers, get_peers_paginated
from ..db.sqlite_runtime import connect, close_connection
from ..db.sqlite_settings import get_dns_blocklist_enabled
from ..db.sqlite_users import get_all_users
from ..utils.config import get_config
from ..utils.deps import get_conn
from ..utils.rate_limit import RATE_LIMIT_DEFAULT, RATE_LIMIT_HEAVY, limiter
from ..utils.version import BUILD_INFO, VERSION
from .acme import get_certs_dir, get_challenge_response
from .auth import get_current_user_optional
from .frontend_shared import (
	_extract_geo_fields,
	_format_last_seen_label,
	_get_csrf_token,
	_lookup_ip_cached,
	require_admin_or_redirect,
	require_user_or_redirect,
	router,
	templates,
)
from .wireguard_isolation import extract_peer_ips

_log = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_APP_ROOT = Path("/app")
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Semaphore to limit concurrent geo-IP lookups (prevents thread pool exhaustion)
_GEO_LOOKUP_SEMAPHORE = asyncio.Semaphore(20)


@lru_cache(maxsize=1)
def _get_about_data() -> dict:
	"""Compute about page data once and cache it."""
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

	def _normalize_pkg_name(name: str) -> str:
		return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())

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
							pkg = _normalize_pkg_name(pkg.split("[")[0])
							ver = ver.split("#")[0].split(";")[0].strip()
							requirements_versions[pkg] = ver
							break
				break
			except Exception as exc:
				_log.warning("Failed to parse requirements.txt: %s", exc)

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
			except Exception as exc:
				_log.debug("Dependency version lookup failed for %s: %s", pkg_name, exc)
				dependencies.append((pkg_name, "?"))

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
	except Exception as exc:
		_log.debug("Failed to get unbound version: %s", exc)

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
			m = re.search(r"v([\d.]+)", output)
			wireguard_version = m.group(1) if m else output
	except FileNotFoundError:
		wireguard_version = "not installed"
	except Exception as exc:
		_log.debug("Failed to get WireGuard version: %s", exc)

	dependencies.sort(key=lambda x: x[0].lower())

	license_text = "License file not found."
	for lp in [_PROJECT_ROOT / "LICENSE", _APP_ROOT / "LICENSE"]:
		if lp.exists():
			try:
				license_text = lp.read_text(encoding="utf-8")
				break
			except Exception:
				pass

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
			except Exception as exc:
				_log.warning("Failed to render changelog: %s", exc)
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


@router.get("/api/system/status", response_model=dict)
@limiter.limit(RATE_LIMIT_DEFAULT)
def get_system_status(request: Request) -> dict:
	"""Get system status including key mismatch warning."""
	key_mismatch = getattr(request.app.state, "key_mismatch", False)
	return {
		"key_mismatch": key_mismatch,
	}


@router.get("/", response_class=RedirectResponse)
def index(
	request: Request,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
) -> RedirectResponse:
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
@limiter.limit(RATE_LIMIT_DEFAULT)
def otp_setup_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""OTP onboarding page for first-time setup after admin enabled OTP.
	
	Redirects to dashboard if:
	- User has no OTP secret (setup not initiated by admin), OR
	- User has already confirmed OTP (otp_enabled=True)
	"""
	has_secret = bool(user["otp_secret"])
	already_enabled = bool(user["otp_enabled"])
	if not has_secret or already_enabled:
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse("otp_setup.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/passkey-setup", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def passkey_setup_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Passkey onboarding page for first-time setup after admin enabled passkeys.
	
	Redirects to dashboard if:
	- User has no passkey_pending flag (setup not initiated by admin), OR
	- User has already registered a passkey (passkey_enabled=True)
	"""
	passkey_pending = bool(user["passkey_pending"])
	already_enabled = bool(user["passkey_enabled"])
	if not passkey_pending or already_enabled:
		return RedirectResponse(url="/ui/dashboard", status_code=303)

	return templates.TemplateResponse("passkey_setup.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/dashboard", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
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
@limiter.limit(RATE_LIMIT_HEAVY)  # Expensive: paginated DB + geo-IP lookups
async def peers_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""Peers management page with paginated data and geo-IP lookups.
	
	Note: Database connection is created inside the thread pool to avoid
	SQLite threading issues (connections are not thread-safe).
	"""
	try:
		page = int(request.query_params.get("page", "1"))
	except ValueError:
		page = 1
	try:
		page_size = int(request.query_params.get("page_size", "50"))
	except ValueError:
		page_size = 50
	page = max(1, page)
	# Clamp page_size to valid range (10-200)
	page_size = min(max(10, page_size), 200)

	db_path = request.app.state.db_path

	def _load_page_data() -> tuple[int, int, int, list[sqlite3.Row]]:
		"""Load peer data in thread pool with dedicated connection."""
		thread_conn = connect(db_path)
		try:
			total = count_peers(thread_conn)
			pages = max(1, math.ceil(total / page_size)) if total else 1
			current_page = min(page, pages)
			rows = get_peers_paginated(thread_conn, page=current_page, page_size=page_size)
			return total, pages, current_page, rows
		finally:
			close_connection(thread_conn)

	total_peers, total_pages, page, peer_rows = await asyncio.to_thread(_load_page_data)
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
				return await asyncio.to_thread(_lookup_ip_cached, ip)
		
		results = await asyncio.gather(*[
			_bounded_lookup(client_ip)
			for client_ip in unique_client_ips
		])
		geoip_cache = dict(zip(unique_client_ips, results, strict=True))

	for row in peer_rows:
		peer = dict(row)
		handshake_epoch = int(peer.get("last_handshake_at") or 0)
		last_seen = _format_last_seen_label(handshake_epoch, now_epoch=now_epoch)
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
@limiter.limit(RATE_LIMIT_DEFAULT)
def users_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin_or_redirect),
):
	"""Users management page (admin only).
	
	Note: This is a sync handler, so FastAPI runs it in a threadpool worker.
	The conn dependency is created and used in the same thread — safe.
	"""
	users = get_all_users(conn)
	return templates.TemplateResponse("users.html", {
		"request": request,
		"user": user,
		"users": users,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/dns", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def dns_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""DNS ad-blocking page.
	
	Note: This is a sync handler, so FastAPI runs it in a threadpool worker.
	The conn dependency is created and used in the same thread — safe.
	"""
	enable_blocklist = get_dns_blocklist_enabled(conn)
	return templates.TemplateResponse("dns.html", {
		"request": request,
		"user": user,
		"enable_blocklist": enable_blocklist,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/traffic", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
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
@limiter.limit(RATE_LIMIT_DEFAULT)
def about_page(
	request: Request,
	user: sqlite3.Row = Depends(require_user_or_redirect),
):
	"""About page with version, dependencies, changelog, and license.
	
	Note: Data is cached via @lru_cache for performance. Cache persists until
	server restart — runtime changes to requirements.txt, LICENSE, or CHANGELOG.md
	won't be reflected without restart.
	"""
	about_data = _get_about_data()
	return templates.TemplateResponse("about.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
		**about_data,
	})


@router.get("/ui/settings", response_class=HTMLResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
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


@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def acme_challenge(request: Request, token: str):
	"""Serve ACME HTTP-01 challenge response for Let's Encrypt."""
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
