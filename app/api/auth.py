#!/usr/bin/env python3
#
# app/api/auth.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Authentication API routes and dependencies."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..db import sqlite as sqlite_db
from ..models.users import LoginRequest
from ..utils.crypto import new_token, verify_password, generate_token_expiry, DUMMY_PASSWORD_HASH
from ..utils.deps import get_conn
from ..utils.rate_limit import limiter, RATE_LIMIT_AUTH
from .response import ok_response

_log = logging.getLogger(__name__)
_security = HTTPBearer(auto_error=False)

router = APIRouter(tags=["auth"])

# Cookie-based auth allowed only on UI routes (not API endpoints)
_COOKIE_AUTH_PREFIXES = ("/ui",)

# Trusted proxy IPs for X-Forwarded-For validation
# Only trust proxy headers if request comes from these IPs
# Set to None to disable proxy header parsing (direct connections only)
_TRUSTED_PROXIES = {"127.0.0.1", "::1"}  # Localhost only by default


def _allow_cookie_auth_for_path(path: str) -> bool:
	"""Return True if cookie-based auth is allowed for this request path."""
	normalized = path.rstrip("/") or "/"
	return any(
		normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/")
		for prefix in _COOKIE_AUTH_PREFIXES
	)


def _get_client_ip(request: Request) -> str:
	"""Extract client IP from request with proxy validation.
	
	Only trusts X-Forwarded-For/X-Real-IP if request comes from trusted proxy.
	This prevents IP spoofing for rate limiting and lockout mechanisms.
	"""
	direct_ip = request.client.host if request.client else "unknown"
	
	# Only check proxy headers if request comes from trusted proxy
	if _TRUSTED_PROXIES and direct_ip in _TRUSTED_PROXIES:
		# Check X-Forwarded-For for reverse proxy setups
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for:
			return forwarded_for.split(",")[0].strip()
		
		x_real_ip = request.headers.get("X-Real-IP")
		if x_real_ip:
			return x_real_ip.strip()
	
	return direct_ip


# ---------------------------------------------------------------------------
# Authentication Dependencies
# ---------------------------------------------------------------------------

def _get_user_by_token(
	token: str,
	conn: sqlite3.Connection,
	check_active: bool = True,
) -> Optional[sqlite3.Row]:
	"""Helper to get user by token with optional is_active check."""
	user = sqlite_db.get_user_by_token(conn, token)
	if user and check_active and not user["is_active"]:
		return None
	return user


def get_current_user_optional(
	request: Request,
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
	conn: sqlite3.Connection = Depends(get_conn),
) -> Optional[sqlite3.Row]:
	"""Get the authenticated user, or None if not authenticated.
	
	Note: Still checks is_active to prevent disabled users from accessing resources.
	"""
	# 1. Explicit Bearer token
	if credentials and credentials.credentials:
		return _get_user_by_token(credentials.credentials, conn, check_active=True)

	# 2. Cookie-based auth (UI routes only)
	path = request.url.path
	if not _allow_cookie_auth_for_path(path):
		return None
	
	token = request.cookies.get("auth_token")
	if token:
		return _get_user_by_token(token, conn, check_active=True)
	
	return None


def get_current_user(
	request: Request,
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
	conn: sqlite3.Connection = Depends(get_conn),
) -> sqlite3.Row:
	"""FastAPI dependency that enforces authentication."""
	# Prefer explicit bearer tokens
	if credentials and credentials.credentials:
		user = _get_user_by_token(credentials.credentials, conn, check_active=False)
		if user:
			if not user["is_active"]:
				raise HTTPException(status_code=403, detail="Account disabled")
			return user
		raise HTTPException(status_code=401, detail="Invalid or expired token")

	# Allow cookie-based auth on UI routes
	path = request.url.path
	if _allow_cookie_auth_for_path(path):
		token = request.cookies.get("auth_token")
		if token:
			user = _get_user_by_token(token, conn, check_active=False)
			if user:
				if not user["is_active"]:
					raise HTTPException(status_code=403, detail="Account disabled")
				return user

	raise HTTPException(status_code=401, detail="Not authenticated")


def require_admin(user_row: sqlite3.Row = Depends(get_current_user)) -> sqlite3.Row:
	"""FastAPI dependency that enforces admin privileges."""
	if not user_row["is_admin"]:
		raise HTTPException(status_code=403, detail="Admin privileges required")
	return user_row


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------

@router.post("/login")
@limiter.limit(RATE_LIMIT_AUTH)
def login(
	request: Request,
	response: Response,
	payload: LoginRequest,
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Authenticate a user and return a bearer token."""
	client_ip = _get_client_ip(request)

	# Check if IP is locked out
	is_locked, seconds_remaining = sqlite_db.is_ip_locked(conn, client_ip)
	if is_locked:
		_log.info("LOGIN_LOCKED ip=%s remaining=%ds", client_ip, seconds_remaining)
		raise HTTPException(
			status_code=429,
			detail="Too many failed attempts. Please try again later.",
			headers={"Retry-After": str(seconds_remaining)},
		)
	
	# Validate credentials
	user = sqlite_db.get_user_by_username(conn, payload.username)
	
	# Always verify password hash to prevent timing attacks
	# Use dummy hash if user doesn't exist to maintain constant time
	password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
	password_valid = verify_password(payload.password, password_hash)
	
	if not user or not password_valid:
		sqlite_db.record_failed_login(conn, client_ip)
		# Log with next lockout info for admin visibility
		is_now_locked, lockout_secs = sqlite_db.is_ip_locked(conn, client_ip)
		if is_now_locked:
			_log.warning("LOGIN_FAILED ip=%s username=%s locked_for=%ds", client_ip, payload.username, lockout_secs)
		else:
			_log.info("LOGIN_FAILED ip=%s username=%s", client_ip, payload.username)
		raise HTTPException(status_code=401, detail="Invalid username or password")
	
	if not user["is_active"]:
		_log.info("LOGIN_INACTIVE ip=%s username=%s", client_ip, payload.username)
		raise HTTPException(status_code=403, detail="Account disabled")
	
	# Clear failed attempts and generate token
	sqlite_db.clear_login_attempts(conn, client_ip)
	
	token = new_token()
	expires_at, max_expires_at = generate_token_expiry()
	
	sqlite_db.create_auth_token(conn, user["id"], token, expires_at, max_expires_at)
	sqlite_db.update_last_login(conn, user["id"], client_ip)

	now = datetime.now(timezone.utc)
	max_age = max(0, int((expires_at - now).total_seconds()))
	response.set_cookie(
		key="auth_token",
		value=token,
		httponly=True,
		secure=(request.url.scheme == "https"),
		samesite="strict",
		max_age=max_age,
		path="/",
	)
	
	_log.info("LOGIN_SUCCESS ip=%s username=%s", client_ip, payload.username)
	data = {
		"token": token,
		"expires_at": expires_at,
		"token_type": "Bearer",
	}
	return ok_response(data=data, **data)


@router.post("/logout")
def logout(
	request: Request,
	response: Response,
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Logout and invalidate the current token."""
	token = None
	
	if credentials and credentials.credentials:
		token = credentials.credentials
	else:
		token = request.cookies.get("auth_token")
	
	if token:
		sqlite_db.delete_auth_token(conn, token)

	response.delete_cookie(key="auth_token", path="/")
	response.delete_cookie(key="csrf_token", path="/")
	return ok_response(message="Logged out")


@router.get("/me")
def get_current_user_info(user: sqlite3.Row = Depends(get_current_user)):
	"""Get the current authenticated user's info."""
	data = {
		"id": user["id"],
		"username": user["username"],
		"is_admin": bool(user["is_admin"]),
		"is_active": bool(user["is_active"]),
	}
	return ok_response(data=data, **data)
