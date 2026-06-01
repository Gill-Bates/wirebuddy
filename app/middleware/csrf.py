#!/usr/bin/env python3
#
# app/middleware/csrf.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""CSRF protection middleware for UI routes."""

from __future__ import annotations

import os
import posixpath
import secrets
from typing import Callable
from urllib.parse import parse_qs
from urllib.parse import urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# UI/API path prefixes that require CSRF protection.
# API enforcement is only applied for cookie-authenticated browser requests.
CSRF_PREFIXES = ("/ui/", "/login", "/api/")
_AUTH_COOKIE_NAMES = ("auth_token",)
_CSRF_EXEMPT_API_PATHS = frozenset({
	"/api/login",
	"/api/mfa/verify",
	"/api/passkeys/login/start",
	"/api/passkeys/login/finish",
})
_CSRF_FORM_MAX_BYTES = 16_384


def _default_port_for_scheme(scheme: str) -> int | None:
	if scheme == "https":
		return 443
	if scheme == "http":
		return 80
	return None


def _origin_tuple(parsed) -> tuple[str, str, int | None] | None:
	scheme = (parsed.scheme or "").lower()
	host = (parsed.hostname or "").lower()
	if not scheme or not host:
		return None
	return scheme, host, parsed.port if parsed.port is not None else _default_port_for_scheme(scheme)


def _has_auth_cookie(request: Request) -> bool:
	"""Return True when any configured auth cookie is present."""
	return any(request.cookies.get(cookie_name) for cookie_name in _AUTH_COOKIE_NAMES)


def _is_header_only_bearer_request(request: Request) -> bool:
	"""Return True for API Bearer requests that do not carry auth cookies."""
	if not request.url.path.startswith("/api/"):
		return False
	auth = request.headers.get("Authorization", "").strip()
	return auth.startswith("Bearer ") and not _has_auth_cookie(request)


def _is_secure_cookie_request(request: Request) -> bool:
	"""Reuse auth-layer HTTPS detection for secure cookie handling."""
	from ..api.auth import _is_https

	try:
		return _is_https(request)
	except Exception:
		return True


class CSRFMiddleware(BaseHTTPMiddleware):
	"""Double-Submit-Cookie CSRF Protection.
	
	1. Generates a random token and sets it as a cookie (HttpOnly=False).
	2. On state-changing methods (POST, etc.), validates that the
	   header 'X-CSRF-Token' matches the cookie.
	3. Optional: Origin header check for additional hardening.
	"""

	def __init__(self, app: ASGIApp):
		super().__init__(app)
		origins_raw = os.environ.get("WIREBUDDY_CSRF_ALLOWED_ORIGINS", "").strip()
		public_origin = os.environ.get("WIREBUDDY_PUBLIC_ORIGIN", "").strip()
		configured = [item.strip() for item in origins_raw.split(",") if item.strip()]
		if public_origin:
			configured.append(public_origin)
		self._allowed_origins = {
			origin_tuple
			for item in configured
			if (origin_tuple := _origin_tuple(urlparse(item))) is not None
		}

	def _requires_csrf(self, path: str) -> bool:
		"""Check if path requires CSRF protection."""
		normalized = posixpath.normpath(path).lower()
		
		for prefix in CSRF_PREFIXES:
			norm_prefix = posixpath.normpath(prefix).lower()
			if normalized.startswith(norm_prefix + "/") or normalized == norm_prefix:
				return True
		return False

	def _is_cookie_authenticated_api_request(self, request: Request) -> bool:
		"""Return True when API request carries session-auth cookie(s)."""
		if not request.url.path.startswith("/api/"):
			return True
		if request.url.path in _CSRF_EXEMPT_API_PATHS:
			return False
		for cookie_name in _AUTH_COOKIE_NAMES:
			if request.cookies.get(cookie_name):
				return True
		return False

	def _is_allowed_origin(self, origin_value: str, request: Request) -> bool:
		"""Validate origin against configured public origins or the current request origin."""
		origin_tuple = _origin_tuple(urlparse(origin_value))
		if origin_tuple is None:
			return False
		if self._allowed_origins:
			return origin_tuple in self._allowed_origins
		request_origin = _origin_tuple(request.url)
		return request_origin is not None and origin_tuple == request_origin

	def _check_origin_or_referer(self, request: Request) -> bool:
		"""Require a matching Origin header or Referer origin for unsafe cookie requests."""
		origin = request.headers.get("Origin")
		if origin:
			return self._is_allowed_origin(origin, request)

		referer = request.headers.get("Referer")
		if not referer:
			return False
		return self._is_allowed_origin(referer, request)

	async def dispatch(self, request: Request, call_next: Callable) -> Response:
		# 1. Get token from cookie, or generate new one
		csrf_token = request.cookies.get("csrf_token")
		new_token = False
		# Rotate token when serving login page to avoid reusing stale tokens.
		if request.url.path == "/login" and request.method in SAFE_METHODS:
			csrf_token = secrets.token_urlsafe(32)
			new_token = True
		if not csrf_token:
			csrf_token = secrets.token_urlsafe(32)
			new_token = True

		# 2. Attach to request state for templates
		request.state.csrf_token = csrf_token

		# 3. Validation for unsafe methods on protected paths
		if (
			request.method not in SAFE_METHODS
			and self._requires_csrf(request.url.path)
			and not _is_header_only_bearer_request(request)
			and self._is_cookie_authenticated_api_request(request)
		):
			# Origin check
			if not self._check_origin_or_referer(request):
				return JSONResponse(
					content={"detail": "Cross-origin request blocked"},
					status_code=403
				)
			
			# CSRF token validation (constant-time comparison)
			submitted_token = request.headers.get("X-CSRF-Token")
			if not submitted_token:
				content_type = request.headers.get("Content-Type", "").lower()
				if "application/x-www-form-urlencoded" in content_type:
					try:
						content_length = int(request.headers.get("Content-Length") or "0")
					except ValueError:
						return JSONResponse(
							content={"detail": "Invalid Content-Length header"},
							status_code=400,
						)
					if content_length > _CSRF_FORM_MAX_BYTES:
						return JSONResponse(
							content={"detail": "CSRF form payload too large"},
							status_code=413,
						)
					try:
						raw_body = await request.body()
						if len(raw_body) > _CSRF_FORM_MAX_BYTES:
							return JSONResponse(
								content={"detail": "CSRF form payload too large"},
								status_code=413,
							)
						parsed = parse_qs(raw_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
						submitted_token = parsed.get("csrf_token", [None])[0]
					except Exception:
						submitted_token = None
				elif "multipart/form-data" in content_type:
					return JSONResponse(
						content={"detail": "CSRF token header required for multipart requests"},
						status_code=403,
					)
			
			if not submitted_token or not secrets.compare_digest(csrf_token, submitted_token):
				return JSONResponse(
					content={"detail": "CSRF token missing or invalid"},
					status_code=403
				)

		# 4. Process request
		response = await call_next(request)

		# 5. Set cookie only when a token was newly generated.
		if new_token:
			response.set_cookie(
				key="csrf_token",
				value=csrf_token,
				httponly=False,  # Needs to be readable by JavaScript
				secure=_is_secure_cookie_request(request),
				samesite="strict",
				max_age=3600,
				path="/",
			)

		return response
