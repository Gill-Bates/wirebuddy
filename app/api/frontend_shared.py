#!/usr/bin/env python3
#
# app/api/frontend_shared.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared frontend router primitives and helpers."""

from __future__ import annotations

import copy
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from functools import lru_cache, wraps
from pathlib import Path
from typing import Never

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..utils.formatting import format_bandwidth_mbit
from ..utils.geoip import lookup_ip
from ..utils.version import BUILD_INFO, VERSION
from .auth import get_current_user_optional

_log = logging.getLogger(__name__)

# Canonical threshold: peers with a handshake within this many seconds
# are considered "connected / online".  Every backend module and every
# frontend JS constant MUST reference or mirror this single value.
CONNECTED_THRESHOLD_S: int = 180

router = APIRouter(tags=["frontend"])

_templates_path = Path(__file__).parent.parent / "templates"
_jinja_templates = Jinja2Templates(directory=str(_templates_path))

_jinja_templates.env.globals["VERSION"] = VERSION
_jinja_templates.env.globals["BUILD_INFO"] = BUILD_INFO


class _ContextAwareTemplates:
	"""Wrapper around Jinja2Templates that automatically adds request.app.state to context."""
	
	def __init__(self, jinja: Jinja2Templates):
		self._jinja = jinja
		self.env = jinja.env  # Expose env for filters/globals
	
	def TemplateResponse(
		self,
		request: Request,
		name: str,
		context: dict[str, Any] | None = None,
		**kwargs: Any,
	) -> Any:
		"""Render template with automatic key_mismatch injection from app state."""
		ctx = context or {}
		# Add key_mismatch from app state (for Critical banner in base.html)
		if not ctx.get("key_mismatch"):
			ctx["key_mismatch"] = getattr(request.app.state, "key_mismatch", False)
		return self._jinja.TemplateResponse(request, name, ctx, **kwargs)


templates = _ContextAwareTemplates(_jinja_templates)


def _wbr_ip(value: str | None) -> str:
    """Jinja2 filter: Insert U+200B (zero-width space) after ':' and '/' for soft line-wrapping."""
    if not value:
        return ""
    return value.replace(":", ":\u200b").replace("/", "/\u200b")


def _truncate_ip(value: str | None, length: int = 24) -> str:
    """Jinja2 filter: Truncate IP address to specified length."""
    if not value:
        return "n/a"
    return value[:length]


# Register Jinja2 filters
_jinja_templates.env.filters["wbr_ip"] = _wbr_ip
_jinja_templates.env.filters["truncate_ip"] = _truncate_ip
_jinja_templates.env.filters["format_bandwidth_mbit"] = format_bandwidth_mbit

__all__ = [
    "router",
    "templates",
    "RedirectTo",
    "LastSeenLabel",
    "redirect_to_handler",
    "require_user_or_redirect",
    "require_admin_or_redirect",
    "get_csrf_token",
    "lookup_ip_cached",
    "CONNECTED_THRESHOLD_S",
    "format_last_seen_label",
    "extract_geo_fields",
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


def _lookup_ip_cached_decorator(maxsize: int = 4096):
    """LRU cache that does not store None results and returns immutable copies.
    
    Prevents cache poisoning from transient failures and protects against
    mutation of cached dictionaries.
    """
    def decorator(fn):
        @lru_cache(maxsize=maxsize)
        def _cached(ip_text: str) -> dict:
            return fn(ip_text)  # Let exception propagate → not cached

        @wraps(fn)
        def wrapper(ip_text: str) -> dict | None:
            try:
                result = _cached(ip_text)
                # Return shallow copy to prevent cache corruption
                return copy.copy(result)
            except Exception:
                _log.debug("GeoIP lookup failed for %s", ip_text, exc_info=True)
                return None

        wrapper.cache_clear = _cached.cache_clear
        wrapper.cache_info = _cached.cache_info
        return wrapper
    return decorator


@_lookup_ip_cached_decorator(maxsize=4096)
def _lookup_ip_cached_inner(ip_text: str) -> dict:
    """Process-wide cached GeoIP lookup to reduce repeated MMDB reads."""
    return lookup_ip(ip_text)


def lookup_ip_cached(ip_text: str) -> dict | None:
    """Public API: cached GeoIP lookup."""
    return _lookup_ip_cached_inner(ip_text)


def get_csrf_token(request: Request) -> str:
    """Get CSRF token from request state."""
    token = getattr(request.state, "csrf_token", None)
    if not token:
        _log.error(
            "CSRF token missing from request state on %s %s — middleware misconfiguration",
            request.method,
            request.url.path,
        )
        raise HTTPException(status_code=500, detail="Internal server error")
    return token


# Allowed URL prefixes for internal redirects (prevents open redirect)
_ALLOWED_REDIRECT_PREFIXES = ("/login", "/ui/")


def _raise_redirect(url: str) -> Never:
    """Raise an HTTP redirect exception for dependency-based auth guards.
    
    Only allows redirects to known internal paths to prevent open redirect attacks.
    """
    if not any(url.startswith(prefix) for prefix in _ALLOWED_REDIRECT_PREFIXES):
        _log.error("Attempted redirect to disallowed URL: %s", url)
        raise ValueError(f"Redirect to disallowed URL: {url}")
    raise RedirectTo(url)


def require_user_or_redirect(
    user: sqlite3.Row | None = Depends(get_current_user_optional),
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


def format_last_seen_label(handshake_epoch: int, *, now_epoch: int | None = None) -> LastSeenLabel:
    """Format a handshake timestamp as a compact relative label + CSS class + active flag.

    ``is_active`` uses :data:`CONNECTED_THRESHOLD_S` (180 s) so that the
    server-rendered badge matches the API ``connected`` field and the JS
    threshold on both the Dashboard and Peers pages.
    """
    if handshake_epoch <= 0:
        return LastSeenLabel(text="Never", css_class="text-muted", is_active=False)

    now = int(time.time()) if now_epoch is None else int(now_epoch)
    diff = max(0, now - handshake_epoch)
    active = diff < CONNECTED_THRESHOLD_S
    if diff < 60:
        return LastSeenLabel(text="Now", css_class="text-success fw-semibold", is_active=active)
    if diff < 3600:
        return LastSeenLabel(text=f"{diff // 60}m ago", css_class="text-muted", is_active=active)
    if diff < 86400:
        return LastSeenLabel(text=f"{diff // 3600}h ago", css_class="text-muted", is_active=active)
    return LastSeenLabel(text=f"{diff // 86400}d ago", css_class="text-muted", is_active=active)


def extract_geo_fields(info: dict | None) -> dict[str, str | None]:
    """Normalize GeoIP lookup results for template display fields.
    
    Country codes are strictly validated to prevent path traversal attacks
    when used in flag image paths.
    """
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
        try:
            asn = int(info.get("asn") or 0)
        except (ValueError, TypeError):
            asn = 0
        as_org = f"AS{asn}" if asn > 0 else ""

    # Strict validation: exactly 2 lowercase letters, prevents path traversal
    validated_country = country if re.fullmatch(r"[a-z]{2}", country) else None

    return {
        "country_code": validated_country,
        "city": city,
        "as_org": as_org or None,
    }


# Register route modules on shared router.
from . import frontend_pages as _frontend_pages  # noqa: F401, E402
from . import frontend_status as _frontend_status  # noqa: F401, E402
