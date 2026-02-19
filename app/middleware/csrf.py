#!/usr/bin/env python3
#
# app/middleware/csrf.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""CSRF protection middleware for UI routes."""

from __future__ import annotations

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

# UI path prefixes that require CSRF protection
UI_PREFIXES = ("/ui/", "/login")


class CSRFMiddleware(BaseHTTPMiddleware):
	"""Double-Submit-Cookie CSRF Protection.
	
	1. Generates a random token and sets it as a cookie (HttpOnly=False).
	2. On state-changing methods (POST, etc.), validates that the
	   header 'X-CSRF-Token' matches the cookie.
	3. Optional: Origin header check for additional hardening.
	"""

	def __init__(self, app: ASGIApp):
		super().__init__(app)

	def _requires_csrf(self, path: str) -> bool:
		"""Check if path requires CSRF protection."""
		normalized = posixpath.normpath(path).lower()
		
		for prefix in UI_PREFIXES:
			norm_prefix = posixpath.normpath(prefix).lower()
			if normalized.startswith(norm_prefix + "/") or normalized == norm_prefix:
				return True
		return False

	def _check_origin(self, request: Request) -> bool:
		"""Validate Origin header matches request scheme and host."""
		origin = request.headers.get("Origin")
		if not origin:
			return True

		try:
			origin_parsed = urlparse(origin)
			req_scheme = request.url.scheme
			req_host = (request.url.hostname or "").lower()
			origin_scheme = (origin_parsed.scheme or "").lower()
			origin_host = (origin_parsed.hostname or "").lower()
			if not origin_scheme or not origin_host:
				return False
			if origin_scheme != req_scheme:
				return False
			return origin_host == req_host
		except Exception:
			return False

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
		if request.method not in SAFE_METHODS and self._requires_csrf(request.url.path):
			# Origin check
			if not self._check_origin(request):
				return JSONResponse(
					content={"detail": "Cross-origin request blocked"},
					status_code=403
				)
			
			# CSRF token validation (constant-time comparison)
			submitted_token = request.headers.get("X-CSRF-Token")
			if not submitted_token:
				content_type = request.headers.get("Content-Type", "")
				if "application/x-www-form-urlencoded" in content_type:
					try:
						raw_body = await request.body()
						parsed = parse_qs(raw_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
						submitted_token = parsed.get("csrf_token", [None])[0]
					except Exception:
						submitted_token = None
				elif "multipart/form-data" in content_type:
					try:
						form = await request.form()
						val = form.get("csrf_token")
						submitted_token = val if isinstance(val, str) else None
					except Exception:
						submitted_token = None
			
			if not submitted_token or not secrets.compare_digest(csrf_token, submitted_token):
				return JSONResponse(
					content={"detail": "CSRF token missing or invalid"},
					status_code=403
				)

		# 4. Process request
		response = await call_next(request)

		# 5. Set cookie on new token or refresh existing
		if new_token:
			response.set_cookie(
				key="csrf_token",
				value=csrf_token,
				httponly=False,  # Needs to be readable by JavaScript
				secure=request.url.scheme == "https",
				samesite="strict",
				max_age=3600,
			)

		return response
