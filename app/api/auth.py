#!/usr/bin/env python3
#
# app/api/auth.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Authentication API routes and dependencies."""

from __future__ import annotations

import base64
import ipaddress
import io
import logging
import os
import sqlite3
import re
import threading
import time
import zipfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..db.sqlite_auth import (
	clear_login_attempts,
	create_auth_token,
	delete_auth_token,
	get_user_by_token,
	is_ip_locked,
	record_failed_login,
)
from ..db.sqlite_users import (
	decrypt_otp_secret,
	get_user_by_username,
	update_user_recovery_codes,
	update_last_login,
	confirm_user_otp,
)
from ..models.users import (
	LoginRequest,
	MFAVerifyRequest,
	OTPConfirmRequest,
	RecoveryDownloadRequest,
)
from ..utils.crypto import DUMMY_PASSWORD_HASH, generate_token_expiry, new_token, verify_password
from ..utils.deps import get_conn
from ..utils.network import parse_ip_str
from ..utils.otp import (
	build_provisioning_uri,
	generate_recovery_codes,
	serialize_recovery_codes,
	use_recovery_code,
	verify_otp,
)
from ..utils.rate_limit import RATE_LIMIT_AUTH, limiter
from .response import ok_response

_log = logging.getLogger(__name__)
_security = HTTPBearer(auto_error=False)

router = APIRouter(tags=["auth"])

_DUMMY_OTP_SECRET = "JBSWY3DPEHPK3PXP"
_MFA_CHALLENGE_TTL_SECONDS = 180
_RECOVERY_DOWNLOAD_TTL_SECONDS = 300
_AUTH_COOKIE = "auth_token"
_CSRF_COOKIE = "csrf_token"
_DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.0/8,::1/128"
_mfa_challenge_cache: dict[str, tuple[int, str, str, float]] = {}
_mfa_challenge_cache_lock = threading.Lock()
_recovery_download_cache: dict[str, tuple[int, str, list[str], float]] = {}
_recovery_download_cache_lock = threading.Lock()

# Cookie-based auth allowed on UI and API routes.
# CSRF validation for UI mutations is enforced by CSRFMiddleware.
_COOKIE_AUTH_PREFIXES = ("/ui", "/api", "/status")
_COOKIE_AUTH_PREFIXES_NORMALIZED = tuple(prefix.rstrip("/") for prefix in _COOKIE_AUTH_PREFIXES)


def _load_trusted_proxy_networks() -> tuple[ipaddress._BaseNetwork, ...]:
	"""Load trusted proxy CIDRs from env with safe defaults."""
	raw = os.environ.get("TRUSTED_PROXY_CIDRS", _DEFAULT_TRUSTED_PROXY_CIDRS)
	networks: list[ipaddress._BaseNetwork] = []
	for cidr in (item.strip() for item in raw.split(",")):
		if not cidr:
			continue
		try:
			networks.append(ipaddress.ip_network(cidr, strict=False))
		except ValueError:
			_log.warning("Ignoring invalid TRUSTED_PROXY_CIDRS entry: %s", cidr)
	if not networks:
		networks = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
	return tuple(networks)


_TRUSTED_PROXY_NETWORKS = _load_trusted_proxy_networks()


def _is_trusted_proxy_ip(ip_text: str) -> bool:
	"""Return True when the socket IP belongs to trusted proxy CIDRs."""
	try:
		ip_obj = ipaddress.ip_address(ip_text)
	except ValueError:
		return False
	return any(ip_obj in network for network in _TRUSTED_PROXY_NETWORKS)


def _parse_ip(value: str | None) -> str | None:
	"""Return normalized IP string or None when invalid."""
	return parse_ip_str(value)


def _store_mfa_challenge(user_id: int, username: str, client_ip: str) -> str:
	"""Store one-time MFA challenge and return challenge token."""
	token = new_token()
	expires_at = time.monotonic() + _MFA_CHALLENGE_TTL_SECONDS
	with _mfa_challenge_cache_lock:
		now = time.monotonic()
		expired = [key for key, value in _mfa_challenge_cache.items() if value[3] <= now]
		for key in expired:
			_mfa_challenge_cache.pop(key, None)
		_mfa_challenge_cache[token] = (user_id, username, client_ip, expires_at)
	return token


def _consume_mfa_challenge(token: str, username: str, client_ip: str) -> int | None:
	"""Consume one-time MFA challenge token and return bound user_id when valid."""
	with _mfa_challenge_cache_lock:
		entry = _mfa_challenge_cache.pop(token, None)
	if not entry:
		return None
	user_id, expected_username, expected_ip, expires_at = entry
	if expires_at <= time.monotonic():
		return None
	if expected_username != username:
		return None
	if expected_ip != client_ip:
		return None
	return user_id


def _store_recovery_download(user_id: int, username: str, codes: list[str]) -> str:
	"""Store one-time recovery download payload and return a token."""
	token = new_token()
	expires_at = time.monotonic() + _RECOVERY_DOWNLOAD_TTL_SECONDS
	with _recovery_download_cache_lock:
		# Opportunistic cleanup of expired entries.
		now = time.monotonic()
		expired = [key for key, value in _recovery_download_cache.items() if value[3] <= now]
		for key in expired:
			_recovery_download_cache.pop(key, None)
		_recovery_download_cache[token] = (user_id, username, list(codes), expires_at)
	return token


def _consume_recovery_download(token: str, user_id: int) -> tuple[str, list[str]] | None:
	"""Consume one-time recovery download payload if token is valid for user."""
	with _recovery_download_cache_lock:
		entry = _recovery_download_cache.pop(token, None)
	if not entry:
		return None
	stored_user_id, username, codes, expires_at = entry
	if stored_user_id != user_id:
		return None
	if expires_at <= time.monotonic():
		return None
	return username, codes


def _allow_cookie_auth_for_path(path: str) -> bool:
	"""Return True if cookie-based auth is allowed for this request path."""
	normalized = path.rstrip("/") or "/"
	return any(
		normalized == prefix or normalized.startswith(prefix + "/")
		for prefix in _COOKIE_AUTH_PREFIXES_NORMALIZED
	)


def _get_client_ip(request: Request) -> str:
	"""Extract client IP from request with proxy validation.
	
	SECURITY: Reads the ORIGINAL socket IP from request.scope["client"] before
	Uvicorn's proxy middleware processes --forwarded-allow-ips. This prevents
	IP spoofing attacks where an attacker sends X-Forwarded-For: 127.0.0.1
	to bypass rate limiting.
	
	Only trusts X-Forwarded-For/X-Real-IP if the ACTUAL socket connection
	comes from a trusted proxy IP.
	"""
	# Get the REAL socket IP before any proxy header processing
	# This is immune to --forwarded-allow-ips spoofing
	scope_client = request.scope.get("client")
	if not scope_client or not scope_client[0]:
		raise HTTPException(status_code=400, detail="Unable to determine client IP")
	socket_ip = _parse_ip(scope_client[0])
	if not socket_ip:
		raise HTTPException(status_code=400, detail="Unable to determine client IP")
	
	# Trust proxy headers only when the socket peer is a configured trusted proxy.
	if _is_trusted_proxy_ip(socket_ip):
		# Trust proxy headers only when socket IP is a local proxy
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for:
			# Take first IP in chain (client IP before proxies)
			candidate = _parse_ip(forwarded_for.split(",")[0])
			if candidate:
				return candidate

		x_real_ip = request.headers.get("X-Real-IP")
		if x_real_ip:
			candidate = _parse_ip(x_real_ip)
			if candidate:
				return candidate

	# Direct connection or untrusted proxy - use socket IP
	return socket_ip


def _is_https(request: Request) -> bool:
	"""Determine HTTPS while honoring trusted reverse proxy headers."""
	if request.url.scheme == "https":
		return True

	scope_client = request.scope.get("client")
	socket_ip = _parse_ip(scope_client[0]) if scope_client and scope_client[0] else None
	if socket_ip and _is_trusted_proxy_ip(socket_ip):
		return request.headers.get("X-Forwarded-Proto", "").lower() == "https"

	return False


# ---------------------------------------------------------------------------
# Authentication Dependencies
# ---------------------------------------------------------------------------

def _lookup_user_by_token(
	token: str,
	conn: sqlite3.Connection,
	require_active: bool = True,
) -> Optional[sqlite3.Row]:
	"""Helper to get user by token with optional is_active check."""
	user = get_user_by_token(conn, token)
	if user and require_active and not user["is_active"]:
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
		return _lookup_user_by_token(credentials.credentials, conn, require_active=True)

	# 2. Cookie-based auth (UI routes only)
	path = request.url.path
	if not _allow_cookie_auth_for_path(path):
		return None
	
	token = request.cookies.get(_AUTH_COOKIE)
	if token:
		return _lookup_user_by_token(token, conn, require_active=True)
	
	return None


def get_current_user(
	request: Request,
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
	conn: sqlite3.Connection = Depends(get_conn),
) -> sqlite3.Row:
	"""FastAPI dependency that enforces authentication."""
	# Prefer explicit bearer tokens
	if credentials and credentials.credentials:
		user = _lookup_user_by_token(credentials.credentials, conn, require_active=False)
		if user:
			if not user["is_active"]:
				raise HTTPException(status_code=403, detail="Account disabled")
			return user
		raise HTTPException(status_code=401, detail="Invalid or expired token")

	# Allow cookie-based auth on UI routes
	path = request.url.path
	if _allow_cookie_auth_for_path(path):
		token = request.cookies.get(_AUTH_COOKIE)
		if token:
			user = _lookup_user_by_token(token, conn, require_active=False)
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
	log_username = payload.username.replace("\n", "").replace("\r", "")[:128]

	is_locked, seconds_remaining = is_ip_locked(conn, client_ip)
	if is_locked:
		_log.info("LOGIN_LOCKED ip=%s remaining=%ds", client_ip, seconds_remaining)
		raise HTTPException(
			status_code=429,
			detail="Too many failed attempts. Please try again later.",
			headers={"Retry-After": str(seconds_remaining)},
		)
	
	user = get_user_by_username(conn, payload.username)
	
	# Always verify password hash to prevent timing attacks
	# Use dummy hash if user doesn't exist to maintain constant time
	password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
	password_valid = verify_password(payload.password, password_hash)
	
	if not user or not password_valid:
		record_failed_login(conn, client_ip)
		# Log with next lockout info for admin visibility
		is_now_locked, lockout_secs = is_ip_locked(conn, client_ip)
		if is_now_locked:
			_log.warning("LOGIN_FAILED ip=%s username=%s locked_for=%ds", client_ip, log_username, lockout_secs)
		else:
			_log.info("LOGIN_FAILED ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=401, detail="Invalid username or password")
	
	if not user["is_active"]:
		_log.info("LOGIN_INACTIVE ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=403, detail="Account disabled")
	
	clear_login_attempts(conn, client_ip)

	# Check if OTP is fully enabled -> require MFA
	if bool(user["otp_enabled"]):
		mfa_token = _store_mfa_challenge(user["id"], user["username"], client_ip)
		_log.info("LOGIN_MFA_REQUIRED ip=%s username=%s", client_ip, log_username)
		return ok_response(
			data={
				"mfa_required": True,
				"mfa_token": mfa_token,
			}
		)

	# Check if OTP setup is pending (secret set but not confirmed)
	otp_setup_pending = bool(user["otp_secret"]) and not bool(user["otp_enabled"])
	
	now = datetime.now(timezone.utc)
	token = new_token()
	expires_at, max_expires_at = generate_token_expiry(now=now)
	
	create_auth_token(conn, user["id"], token, expires_at, max_expires_at)
	update_last_login(conn, user["id"], client_ip)

	max_age = max(0, int((expires_at - now).total_seconds()))
	response.set_cookie(
		key=_AUTH_COOKIE,
		value=token,
		httponly=True,
		secure=_is_https(request),
		samesite="strict",
		max_age=max_age,
		path="/",
	)
	
	_log.info("LOGIN_SUCCESS ip=%s username=%s", client_ip, log_username)
	data = {
		"token": token,
		"expires_at": expires_at,
		"token_type": "Bearer",
	}

	if otp_setup_pending:
		_log.info("LOGIN_OTP_SETUP_PENDING ip=%s username=%s", client_ip, log_username)
		data["otp_setup_pending"] = True

	return ok_response(data=data)


@router.post("/mfa/verify")
@limiter.limit(RATE_LIMIT_AUTH)
def verify_mfa(
	request: Request,
	response: Response,
	payload: MFAVerifyRequest,
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Complete MFA verification and issue an auth token."""
	client_ip = _get_client_ip(request)
	log_username = payload.username.replace("\n", "").replace("\r", "")[:128]

	is_locked, seconds_remaining = is_ip_locked(conn, client_ip)
	if is_locked:
		_log.info("LOGIN_LOCKED ip=%s remaining=%ds", client_ip, seconds_remaining)
		raise HTTPException(
			status_code=429,
			detail="Too many failed attempts. Please try again later.",
			headers={"Retry-After": str(seconds_remaining)},
		)

	challenge_user_id = _consume_mfa_challenge(payload.mfa_token, payload.username, client_ip)
	if challenge_user_id is None:
		record_failed_login(conn, client_ip)
		_log.warning("LOGIN_MFA_CHALLENGE_INVALID ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")

	user = get_user_by_username(conn, payload.username)
	if not user or int(user["id"]) != int(challenge_user_id):
		record_failed_login(conn, client_ip)
		_log.warning("LOGIN_MFA_CHALLENGE_MISMATCH ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")

	if not bool(user["is_active"]):
		_log.info("LOGIN_INACTIVE ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=403, detail="Account disabled")

	if not bool(user["otp_enabled"]):
		record_failed_login(conn, client_ip)
		_log.info("LOGIN_FAILED ip=%s username=%s", client_ip, log_username)
		raise HTTPException(status_code=401, detail="Invalid MFA code")

	if not user["otp_secret"]:
		_log.error("LOGIN_MFA_MISCONFIG user_id=%s username=%s", user["id"], log_username)
		raise HTTPException(status_code=500, detail="OTP is enabled but no secret is configured")

	# Decrypt OTP secret for verification (stored encrypted at rest)
	raw_secret = decrypt_otp_secret(user["otp_secret"])
	user_secret = raw_secret if raw_secret else _DUMMY_OTP_SECRET
	otp_valid = verify_otp(user_secret, payload.code)

	used_recovery = False

	if not otp_valid:
		recovery_ok, updated_recovery_json = use_recovery_code(payload.code, user["otp_recovery_codes"])
		if recovery_ok:
			update_user_recovery_codes(conn, user["id"], updated_recovery_json)
			used_recovery = True
			_log.warning(
				"LOGIN_MFA_RECOVERY_USED ip=%s username=%s",
				client_ip,
				log_username,
			)
		else:
			record_failed_login(conn, client_ip)
			is_now_locked, lockout_secs = is_ip_locked(conn, client_ip)
			if is_now_locked:
				_log.warning("LOGIN_FAILED ip=%s username=%s locked_for=%ds", client_ip, log_username, lockout_secs)
			else:
				_log.info("LOGIN_FAILED ip=%s username=%s", client_ip, log_username)
			raise HTTPException(status_code=401, detail="Invalid MFA code")

	clear_login_attempts(conn, client_ip)

	now = datetime.now(timezone.utc)
	token = new_token()
	expires_at, max_expires_at = generate_token_expiry(now=now)

	create_auth_token(conn, user["id"], token, expires_at, max_expires_at)
	update_last_login(conn, user["id"], client_ip)

	max_age = max(0, int((expires_at - now).total_seconds()))
	response.set_cookie(
		key=_AUTH_COOKIE,
		value=token,
		httponly=True,
		secure=_is_https(request),
		samesite="strict",
		max_age=max_age,
		path="/",
	)

	if used_recovery:
		_log.info("LOGIN_SUCCESS ip=%s username=%s mfa=recovery", client_ip, log_username)
	else:
		_log.info("LOGIN_SUCCESS ip=%s username=%s mfa=totp", client_ip, log_username)

	data = {
		"token": token,
		"expires_at": expires_at,
		"token_type": "Bearer",
	}
	return ok_response(data=data)


@router.post("/logout")
@limiter.limit(RATE_LIMIT_AUTH)
def logout(
	request: Request,
	response: Response,
	user: Optional[sqlite3.Row] = Depends(get_current_user_optional),
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Logout and invalidate the current token."""
	token = None
	
	if credentials and credentials.credentials:
		token = credentials.credentials
	else:
		token = request.cookies.get(_AUTH_COOKIE)
	
	if token:
		delete_auth_token(conn, token)

	try:
		log_ip = _get_client_ip(request)
	except HTTPException:
		log_ip = "unknown"

	if user:
		_log.info("LOGOUT ip=%s username=%s", log_ip, user["username"])
	else:
		_log.info("LOGOUT_ANON ip=%s", log_ip)

	response.delete_cookie(key=_AUTH_COOKIE, path="/")
	response.delete_cookie(key=_CSRF_COOKIE, path="/")
	return ok_response(message="Logged out")


@router.get("/me")
def get_current_user_info(user: sqlite3.Row = Depends(get_current_user)):
	"""Get the current authenticated user's info."""
	data = {
		"id": user["id"],
		"username": user["username"],
		"is_admin": bool(user["is_admin"]),
		"is_active": bool(user["is_active"]),
		"otp_enabled": bool(user["otp_enabled"]),
		"otp_setup_pending": bool(user["otp_secret"]) and not bool(user["otp_enabled"]),
	}
	return ok_response(data=data)


@router.get("/me/otp/setup")
def get_otp_setup_info(user: sqlite3.Row = Depends(get_current_user)):
	"""Get OTP provisioning info for the current user (only if setup is pending)."""
	if not user["otp_secret"]:
		raise HTTPException(status_code=400, detail="OTP setup not initiated")

	if bool(user["otp_enabled"]):
		raise HTTPException(status_code=400, detail="OTP is already enabled")

	# Decrypt for display
	plaintext_secret = decrypt_otp_secret(user["otp_secret"])
	if not plaintext_secret:
		raise HTTPException(status_code=500, detail="Unable to decrypt OTP secret")

	provisioning_uri = build_provisioning_uri(
		secret=plaintext_secret,
		username=user["username"],
	)

	# Generate QR code data URL
	import qrcode

	img = qrcode.make(provisioning_uri)
	buffer = io.BytesIO()
	img.save(buffer, format="PNG")
	qr_code_data_url = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode('ascii')}"

	return ok_response(
		data={
			"provisioning_uri": provisioning_uri,
			"secret": plaintext_secret,
			"qr_code_data_url": qr_code_data_url,
		}
	)


@router.post("/me/otp/confirm")
@limiter.limit(RATE_LIMIT_AUTH)
def confirm_my_otp_setup(
	request: Request,
	payload: OTPConfirmRequest,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(get_current_user),
):
	"""Confirm OTP setup for the current user."""
	if not user["otp_secret"]:
		raise HTTPException(status_code=400, detail="OTP setup not initiated")

	if bool(user["otp_enabled"]):
		raise HTTPException(status_code=400, detail="OTP is already enabled")

	# Decrypt for verification
	plaintext_secret = decrypt_otp_secret(user["otp_secret"])
	if not plaintext_secret:
		raise HTTPException(status_code=500, detail="Unable to decrypt OTP secret")

	if not verify_otp(plaintext_secret, payload.code):
		raise HTTPException(status_code=401, detail="Invalid OTP code")

	recovery_codes = generate_recovery_codes()
	serialized_codes = serialize_recovery_codes(recovery_codes)
	if not confirm_user_otp(conn, user["id"], serialized_codes):
		raise HTTPException(status_code=500, detail="Unable to enable OTP")

	_log.info("USER_OTP_SELF_CONFIRMED user_id=%d username=%s", user["id"], user["username"])
	recovery_download_token = _store_recovery_download(user["id"], user["username"], recovery_codes)
	return ok_response(
		data={
			"otp_enabled": True,
			"recovery_codes": recovery_codes,
			"recovery_download_token": recovery_download_token,
		}
	)


@router.post("/me/otp/recovery-codes/zip")
@limiter.limit(RATE_LIMIT_AUTH)
def download_my_recovery_codes_zip(
	request: Request,
	payload: RecoveryDownloadRequest,
	user: sqlite3.Row = Depends(get_current_user),
):
	"""Create a ZIP containing current recovery codes (no encryption)."""
	token = payload.token
	if not token:
		raise HTTPException(status_code=400, detail="Download token is required")

	resolved = _consume_recovery_download(token, int(user["id"]))
	if not resolved:
		raise HTTPException(status_code=400, detail="Download token invalid or expired")
	username, codes = resolved

	safe_username = re.sub(r"[^A-Za-z0-9_-]", "_", username) or "user"
	text_name = f"wirebuddy-recovery-codes-{safe_username}.txt"
	zip_name = f"wirebuddy-recovery-codes-{safe_username}.zip"
	content = (
		f"WireBuddy Recovery Codes for {safe_username}\n"
		"\n"
		+ "\n".join(codes)
		+ "\n"
	)

	buf = io.BytesIO()
	with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
		zf.writestr(text_name, content)

	headers = {
		"Content-Disposition": f'attachment; filename="{zip_name}"',
		"Cache-Control": "no-store",
	}
	return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)
