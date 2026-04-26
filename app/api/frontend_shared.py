#!/usr/bin/env python3
#
# app/api/frontend_shared.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared frontend router primitives and helpers."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sqlite3
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Never, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..utils.formatting import format_bandwidth_mbit
from ..utils.geoip import lookup_ip
from ..utils.time import parse_utc
from ..utils.version import BUILD_INFO, VERSION
from .auth import coerce_db_bool, get_current_user_optional

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
# now() is evaluated at render time (not import time), so each template
# render reflects the current timestamp.
_jinja_templates.env.globals["now"] = lambda: datetime.now(timezone.utc)


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
		ctx = dict(context) if context else {}
		# Use app.state.key_mismatch as authoritative source only when the caller
		# has not explicitly provided the key (preserves caller-set False for tests).
		if "key_mismatch" not in ctx:
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
    "resolve_node_geo_ip",
    "parse_last_seen_epoch",
    "parse_node_metadata",
]


def parse_node_metadata(value: Any, *, node_id: str) -> dict[str, Any]:
    """Parse node metadata stored as a JSON string or plain dict.

    Returns an empty dict on any parse failure so callers can safely call
    `.get()` without further error handling.
    """
    if value is None or value == "":
        return {}
    if not isinstance(value, str):
        return value if isinstance(value, dict) else {}
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):  # JSONDecodeError is a subclass of ValueError
        _log.warning("Node %s has invalid metadata JSON; returning empty dict", node_id)
        return {}


class RedirectTo(Exception):
    """Internal redirect signal used by auth dependencies."""

    def __init__(self, url: str):
        super().__init__(url)
        self.url = url


@dataclass(frozen=True)
class LastSeenLabel:
    """Display model for peer last-seen information."""
    text: str        # Human-readable label, e.g. "2h ago"
    css_class: str   # Bootstrap/CSS class for badge styling
    is_active: bool  # True if last_seen < CONNECTED_THRESHOLD_S seconds ago


async def redirect_to_handler(_: Request, exc: RedirectTo) -> RedirectResponse:
    """Convert dependency redirect signal to a pure 303 redirect response."""
    return RedirectResponse(url=exc.url, status_code=303)


@lru_cache(maxsize=4096)
def _geoip_lookup_cached(ip_text: str) -> dict:
    """Internal: cached raw GeoIP lookup. Raises on failure (result not cached)."""
    return lookup_ip(ip_text)


def lookup_ip_cached(ip_text: str) -> dict | None:
    """Public API: cached GeoIP lookup.
    
    Returns:
        dict: GeoIP data (may be empty {} for IPs without geo data).
        None: On lookup failure (not cached, next call retries).
    """
    try:
        return dict(_geoip_lookup_cached(ip_text))
    except Exception:
        _log.debug("GeoIP lookup failed for %s", ip_text, exc_info=True)
        return None

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
    NOTE: Must only be called with hardcoded relative paths, never user-controlled input.
    The prefix check is a defence-in-depth safeguard, not the primary access guard.
    """
    if not any(url.startswith(prefix) for prefix in _ALLOWED_REDIRECT_PREFIXES):
        _log.error("Attempted redirect to disallowed URL: %s", url)
        raise HTTPException(status_code=500, detail="Internal redirect configuration error")
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
    if not coerce_db_bool(user["is_admin"]):
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


class GeoFields(TypedDict):
    """Type-safe structure for extracted GeoIP fields."""
    country_code: str | None
    city: str | None
    as_org: str | None


def extract_geo_fields(info: dict | None) -> GeoFields:
    """Normalize GeoIP lookup results for template display fields.
    
    Country codes are strictly validated to prevent path traversal attacks
    when used in flag image paths.
    """
    if not info:
        return {"country_code": None, "city": None, "as_org": None}

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


def _strip_ipv6_zone(ip_text: str) -> str:
    """Remove an IPv6 zone identifier such as %eth0."""
    return ip_text.split("%", 1)[0]

# ULA prefix for IPv6 private addresses (fc00::/7 = fc00:: – fdff::)
_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


def _is_globally_routable(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is publicly routable (not private/loopback/link-local/ULA)."""
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return False
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _ULA_NETWORK:
        return False
    return True


@lru_cache(maxsize=256)
def resolve_node_geo_ip(host_or_ip: str) -> str:
    """Resolve a node FQDN/IP to a concrete public IP for GeoIP lookups.

    Returns the resolved IP string, or empty string if not resolvable/private
    (empty string is cached to avoid repeated DNS timeouts on bad hosts).

    WARNING: Makes a blocking DNS call on cache miss. Call via
    ``asyncio.to_thread()`` when used from an async context.
    """
    clean = str(host_or_ip or "").strip()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    if not clean:
        return ""

    try:
        ip_obj = ipaddress.ip_address(_strip_ipv6_zone(clean))
        return str(ip_obj) if _is_globally_routable(ip_obj) else ""
    except ValueError:
        pass

    try:
        addrinfo = socket.getaddrinfo(clean, None, type=socket.SOCK_STREAM)
    except OSError:
        return ""  # Cached as empty string — prevents repeated DNS timeout retries

    for _family, _socktype, _proto, _canonname, sockaddr in addrinfo:
        ip_text = _strip_ipv6_zone(str(sockaddr[0]))
        try:
            ip_obj = ipaddress.ip_address(ip_text)
            if _is_globally_routable(ip_obj):
                return str(ip_obj)
        except ValueError:
            continue

    return ""  # All addresses were private/unresolvable


def parse_last_seen_epoch(value: object) -> int:
    """Parse a datetime-like value into epoch seconds (UTC fallback for naive values)."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    if isinstance(value, str):
        try:
            dt = parse_utc(value)
            return int(dt.timestamp()) if dt else 0
        except (ValueError, TypeError):
            return 0
    return 0


# Circular import resolution: frontend_pages and frontend_status import symbols
# from this module. Importing them here at module-end registers their routes on
# `router` without creating a circular dependency at class-definition level.
# The `_` prefix prevents accidental re-export via `from frontend_shared import *`.
from . import frontend_pages as _frontend_pages  # noqa: F401, E402
from . import frontend_status as _frontend_status  # noqa: F401, E402
