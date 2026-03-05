#!/usr/bin/env python3
#
# app/api/frontend_shared.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared frontend router primitives and helpers."""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..utils.geoip import lookup_ip
from ..utils.version import BUILD_INFO, VERSION
from .auth import get_current_user_optional

_log = logging.getLogger(__name__)

router = APIRouter(tags=["frontend"])

_templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_path))

templates.env.globals["VERSION"] = VERSION
templates.env.globals["BUILD_INFO"] = BUILD_INFO

__all__ = [
	"router",
	"templates",
	"RedirectTo",
	"LastSeenLabel",
	"redirect_to_handler",
	"require_user_or_redirect",
	"require_admin_or_redirect",
	"_get_csrf_token",
	"_lookup_ip_cached",
	"_format_last_seen_label",
	"_extract_geo_fields",
]


class RedirectTo(Exception):
	"""Internal redirect signal used by auth dependencies."""

	def __init__(self, url: str):
		super().__init__(url)
		self.url = url


@dataclass(frozen=True)
class LastSeenLabel:
	"""Display model for peer last-seen information."""
	text: str
	css_class: str
	is_active: bool


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


def _format_last_seen_label(handshake_epoch: int, *, now_epoch: int | None = None) -> LastSeenLabel:
	"""Format a handshake timestamp as a compact relative label + CSS class + active flag."""
	if handshake_epoch <= 0:
		return LastSeenLabel(text="Never", css_class="text-muted", is_active=False)

	now = int(time.time()) if now_epoch is None else int(now_epoch)
	diff = max(0, now - handshake_epoch)
	if diff < 60:
		return LastSeenLabel(text="", css_class="", is_active=True)
	if diff < 3600:
		return LastSeenLabel(text=f"{diff // 60}m ago", css_class="text-muted", is_active=False)
	if diff < 86400:
		return LastSeenLabel(text=f"{diff // 3600}h ago", css_class="text-muted", is_active=False)
	return LastSeenLabel(text=f"{diff // 86400}d ago", css_class="text-muted", is_active=False)


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
		"country_code": country if len(country) == 2 and country.isalpha() else None,
		"city": city,
		"as_org": as_org or None,
	}


# Register route modules on shared router.
from . import frontend_pages as _frontend_pages  # noqa: F401, E402
from . import frontend_status as _frontend_status  # noqa: F401, E402
