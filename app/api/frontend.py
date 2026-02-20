#!/usr/bin/env python3
#
# app/api/frontend.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Frontend HTML routes."""

from __future__ import annotations

from ..db.sqlite_peers import (
	count_peers,
	get_peers_paginated,
)
from ..db.sqlite_users import (
	get_all_users,
)

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

import bleach
import markdown
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..utils.geoip import lookup_ip
from ..utils.deps import get_conn
from .auth import get_current_user_optional

_log = logging.getLogger(__name__)

router = APIRouter(tags=["frontend"])

# Setup templates
_templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_path))

# Make VERSION and BUILD_INFO available in all templates
from ..utils.version import VERSION, BUILD_INFO
templates.env.globals["VERSION"] = VERSION
templates.env.globals["BUILD_INFO"] = BUILD_INFO


# ---------------------------------------------------------------------------
# Auth Helpers for Frontend (redirect-based, not exception-based)
# ---------------------------------------------------------------------------

def _get_csrf_token(request: Request) -> str:
	"""Get CSRF token from request state, or empty string if not set."""
	token = getattr(request.state, "csrf_token", None)
	if not token:
		_log.warning("CSRF token missing from request state — check middleware ordering")
		return ""
	return token


def _require_admin_or_redirect(user: Optional[sqlite3.Row]) -> Optional[RedirectResponse]:
	"""Check if user is admin. Returns redirect response if not, None if ok."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	if not user["is_admin"]:
		return RedirectResponse(url="/ui/dashboard", status_code=303)
	return None


def _format_last_seen_label(handshake_epoch: int) -> tuple[str, str]:
	"""Format a handshake timestamp as a compact relative label + CSS class."""
	if handshake_epoch <= 0:
		return "Never", "text-muted"

	diff = max(0, int(time.time()) - handshake_epoch)
	if diff < 60:
		return "Just now", "text-success"
	if diff < 3600:
		return f"{diff // 60}m ago", "text-success"
	if diff < 86400:
		return f"{diff // 3600}h ago", "text-warning"
	return f"{diff // 86400}d ago", "text-muted"


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
	from ..utils.version import VERSION, BUILD_INFO
	
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
	
	# Parse requirements.txt for package versions
	requirements_versions: dict[str, str] = {}
	requirements_paths = [
		Path(__file__).resolve().parent.parent.parent / "requirements.txt",
		Path("/app/requirements.txt"),
	]
	for req_path in requirements_paths:
		if req_path.exists():
			try:
				for line in req_path.read_text(encoding="utf-8").splitlines():
					line = line.strip()
					if not line or line.startswith("#") or line.startswith("-"):
						continue
					for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
						if sep in line:
							pkg, ver = line.split(sep, 1)
							pkg = pkg.strip().lower().split("[")[0]  # strip extras
							ver = ver.split("#")[0].split(";")[0].strip()  # strip comments + markers
							requirements_versions[pkg] = ver
							break
				break
			except Exception as e:
				_log.warning("Failed to parse requirements.txt: %s", e)
	
	# Build dependency list
	key_packages = [
		"fastapi", "httpx", "jinja2", "markdown", "pydantic", "pydantic-settings",
		"python-multipart", "qrcode", "slowapi", "uvicorn", "bleach",
	]
	
	dependencies = []
	for pkg_name in key_packages:
		ver = requirements_versions.get(pkg_name.lower())
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
		if result.returncode == 0 and result.stdout.strip():
			first_line = result.stdout.strip().splitlines()[0]
			unbound_version = first_line.split()[-1] if first_line else "?"
	except FileNotFoundError:
		unbound_version = "not installed"
	except Exception as e:
		_log.debug("Failed to get unbound version: %s", e)
	
	dependencies.append(("unbound", unbound_version))
	
	# Get WireGuard version
	wireguard_version = "not available"
	try:
		result = subprocess.run(
			["wg", "--version"],
			capture_output=True,
			text=True,
			timeout=5,
		)
		if result.returncode == 0 and result.stdout.strip():
			# Output is typically: "wireguard-tools v1.0.20210914"
			output = result.stdout.strip()
			# Use regex to extract version number accurately
			m = re.search(r"v([\d.]+)", output)
			wireguard_version = m.group(1) if m else output
	except FileNotFoundError:
		wireguard_version = "not installed"
	except Exception as e:
		_log.debug("Failed to get WireGuard version: %s", e)
	
	dependencies.append(("wireguard", wireguard_version))
	dependencies.sort(key=lambda x: x[0].lower())
	
	# Read LICENSE
	license_text = "License file not found."
	for lp in [Path(__file__).resolve().parent.parent.parent / "LICENSE", Path("/app/LICENSE")]:
		if lp.exists():
			try:
				license_text = lp.read_text(encoding="utf-8")
				break
			except Exception:
				pass
	
	# Read CHANGELOG.md and render to HTML (sanitized)
	changelog_html = "<p>Changelog not found.</p>"
	for cp in [
		Path(__file__).resolve().parent.parent.parent / "CHANGELOG.md",
		Path("/app/CHANGELOG.md"),
	]:
		if cp.exists():
			try:
				raw = cp.read_text(encoding="utf-8")
				rendered = markdown.markdown(raw, extensions=["extra", "sane_lists", "md_in_html"])
				allowed_tags = [
					"h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr",
					"ul", "ol", "li", "a", "strong", "em", "b", "i",
					"code", "pre", "blockquote", "table", "thead", "tbody",
					"tr", "th", "td", "dl", "dt", "dd", "abbr", "sup", "sub",
					"details", "summary",
				]
				allowed_attrs = {
					"a": ["href", "title"],
					"abbr": ["title"],
					"details": ["open"],
				}
				changelog_html = bleach.clean(
					rendered,
					tags=allowed_tags,
					attributes=allowed_attrs,
					strip=True,
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
		"dependencies": dependencies,
		"license_text": license_text,
		"changelog_html": changelog_html,
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


@router.get("/ui/dashboard", response_class=HTMLResponse)
def dashboard(
	request: Request,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Dashboard page."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	return templates.TemplateResponse("dashboard.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/peers", response_class=HTMLResponse)
def peers_page(
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Peers management page."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)

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
	for row in peer_rows:
		peer = dict(row)
		handshake_epoch = int(peer.get("last_handshake_at") or 0)
		last_seen_text, last_seen_class = _format_last_seen_label(handshake_epoch)
		peer["last_seen_text"] = last_seen_text
		peer["last_seen_class"] = last_seen_class
		peer["last_client_ip_display"] = str(peer.get("last_client_ip") or "").strip()
		peer["last_client_country_code"] = None
		peer["last_client_city"] = None
		peer["last_client_as_org"] = None

		if peer["last_client_ip_display"]:
			try:
				info = lookup_ip(peer["last_client_ip_display"])
			except Exception:
				info = None
			if info:
				country = str(info.get("country") or "").strip().lower()
				peer["last_client_country_code"] = country if re.fullmatch(r"[a-z]{2}", country) else None
				city = str(info.get("city") or "").strip()
				peer["last_client_city"] = city or None
				as_org = str(info.get("as_org") or "").strip()
				if as_org:
					peer["last_client_as_org"] = as_org
				else:
					asn = int(info.get("asn") or 0)
					peer["last_client_as_org"] = f"AS{asn}" if asn > 0 else None
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
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Users management page (admin only)."""
	redirect = _require_admin_or_redirect(user)
	if redirect:
		return redirect
	
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
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""DNS ad-blocking page."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	return templates.TemplateResponse("dns.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


@router.get("/ui/about", response_class=HTMLResponse)
def about_page(
	request: Request,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""About page with version, dependencies, changelog, and license (cached)."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
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
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
):
	"""Settings page."""
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	return templates.TemplateResponse("settings.html", {
		"request": request,
		"user": user,
		"csrf_token": _get_csrf_token(request),
	})


# ---------------------------------------------------------------------------
# ACME HTTP-01 Challenge Endpoint (public, no auth)
# ---------------------------------------------------------------------------

# ACME token validation pattern (base64url characters only)
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
async def acme_challenge(token: str):
	"""Serve ACME HTTP-01 challenge response for Let's Encrypt."""
	# Validate token format to prevent path traversal
	if not _ACME_TOKEN_RE.match(token):
		return PlainTextResponse("Invalid token", status_code=400)
	
	from .acme import get_challenge_response, _get_certs_dir
	from ..utils.config import get_config
	
	config = get_config()
	certs_dir = _get_certs_dir(config)
	
	key_auth = get_challenge_response(token, certs_dir)
	if not key_auth:
		return PlainTextResponse("Challenge not found", status_code=404)
	
	return PlainTextResponse(key_auth)
