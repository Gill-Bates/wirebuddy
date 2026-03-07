#!/usr/bin/env python3
#
# app/api/passkeys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Passkey (WebAuthn) API routes for registration and authentication."""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..db.sqlite_auth import (
	clear_login_attempts,
	create_auth_token,
	is_ip_locked,
	record_failed_login,
)
from ..db.sqlite_passkeys import (
	any_passkeys_exist,
	count_user_passkeys,
	create_passkey,
	delete_passkey,
	get_credential_ids_for_user,
	get_passkey_by_credential_id,
	get_passkey_by_id,
	get_passkeys_for_user,
	update_passkey_sign_count,
)
from ..db.sqlite_users import (
	clear_passkey_onboarding,
	disable_user_passkeys,
	get_user_by_id,
	get_user_by_username,
	set_passkey_pending,
	update_last_login,
	update_user_auth_method,
)
from ..utils.crypto import generate_token_expiry, new_token
from ..utils.deps import get_conn
from ..utils.passkeys import (
	consume_authentication_challenge,
	consume_registration_challenge,
	get_authentication_options,
	get_registration_options,
	serialize_transports,
	verify_authentication,
	verify_registration,
	InvalidChallengeError,
)
from ..utils.rate_limit import RATE_LIMIT_AUTH, limiter
from .auth import _get_client_ip, _is_https, get_current_user, require_admin
from .response import ok_response

_log = logging.getLogger(__name__)

router = APIRouter(tags=["passkeys"])

_AUTH_COOKIE = "auth_token"


def _get_rp_id(request: Request) -> str:
	"""Get the Relying Party ID from the request host.
	
	For development with localhost, use 'localhost'.
	For production, use the domain without port.
	"""
	host = request.headers.get("host", "localhost")
	# Strip port if present
	if ":" in host:
		host = host.split(":")[0]
	return host


def _get_origin(request: Request) -> str:
	"""Get the expected origin from the request."""
	scheme = "https" if _is_https(request) else "http"
	host = request.headers.get("host", "localhost")
	return f"{scheme}://{host}"


def _get_rp_name() -> str:
	"""Get the Relying Party name."""
	return os.environ.get("PASSKEY_RP_NAME", "WireBuddy")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class PasskeyRegisterFinishRequest(BaseModel):
	"""Request body for completing passkey registration."""
	credential: dict[str, Any] = Field(..., description="WebAuthn credential response")
	device_name: str | None = Field(None, max_length=100, description="User-friendly device name")


class PasskeyLoginStartRequest(BaseModel):
	"""Optional request body for starting passkey login."""
	username: str | None = Field(None, max_length=64, description="Username (optional for discoverable credentials)")


class PasskeyLoginFinishRequest(BaseModel):
	"""Request body for completing passkey login."""
	credential: dict[str, Any] = Field(..., description="WebAuthn credential response")


class PasskeyPublic(BaseModel):
	"""Public representation of a passkey."""
	id: int
	device_name: str | None
	created_at: datetime
	transports: list[str] | None


# ---------------------------------------------------------------------------
# Registration Endpoints
# ---------------------------------------------------------------------------


@router.post("/register/start")
def passkey_register_start(
	request: Request,
	user: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Start passkey registration for the current user.
	
	Returns PublicKeyCredentialCreationOptions for navigator.credentials.create()
	"""
	rp_id = _get_rp_id(request)
	rp_name = _get_rp_name()

	# Get existing credential IDs to exclude (prevent re-registration)
	existing_creds = get_credential_ids_for_user(conn, user["id"])

	options = get_registration_options(
		conn=conn,
		rp_id=rp_id,
		rp_name=rp_name,
		user_id=user["id"],
		username=user["username"],
		existing_credential_ids=existing_creds,
	)

	_log.info(
		"PASSKEY_REGISTER_START user_id=%s username=%s",
		user["id"],
		user["username"],
	)

	return ok_response(data=options)


@router.post("/register/finish")
def passkey_register_finish(
	request: Request,
	payload: PasskeyRegisterFinishRequest,
	user: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Complete passkey registration.
	
	Verifies the WebAuthn response and stores the credential.
	"""
	rp_id = _get_rp_id(request)
	origin = _get_origin(request)

	# Extract challenge from credential response
	try:
		client_data_json = payload.credential.get("response", {}).get("clientDataJSON", "")
		import base64
		import json
		# clientDataJSON is base64url encoded
		padding = 4 - len(client_data_json) % 4
		if padding != 4:
			client_data_json += "=" * padding
		client_data = json.loads(base64.urlsafe_b64decode(client_data_json))
		challenge = client_data.get("challenge", "")
	except Exception as e:
		_log.warning("PASSKEY_REGISTER_FINISH invalid clientDataJSON: %s", e)
		raise HTTPException(status_code=400, detail="Invalid credential response")

	# Verify challenge and get bound user info
	try:
		bound_user_id, bound_username = consume_registration_challenge(conn, challenge)
	except InvalidChallengeError as e:
		_log.warning(
			"PASSKEY_REGISTER_FINISH invalid/expired challenge user_id=%s: %s",
			user["id"],
			e,
		)
		raise HTTPException(status_code=400, detail="Invalid or expired registration challenge")

	if bound_user_id != user["id"]:
		_log.warning(
			"PASSKEY_REGISTER_FINISH user mismatch challenge_user=%s actual_user=%s",
			bound_user_id,
			user["id"],
		)
		raise HTTPException(status_code=400, detail="Challenge was not issued for this user")

	try:
		result = verify_registration(
			credential_json=payload.credential,
			expected_challenge=challenge,
			expected_origin=origin,
			expected_rp_id=rp_id,
		)
	except Exception as e:
		_log.warning(
			"PASSKEY_REGISTER_FINISH verification failed user_id=%s error=%s",
			user["id"],
			e,
		)
		raise HTTPException(status_code=400, detail="Passkey registration verification failed")

	# Store the credential
	passkey_id = create_passkey(
		conn=conn,
		user_id=user["id"],
		credential_id=result.credential_id,
		public_key=result.public_key,
		sign_count=result.sign_count,
		device_name=payload.device_name,
		transports=serialize_transports(result.transports),
	)

	# Complete onboarding if passkey_pending was set (admin-initiated setup)
	if user["passkey_pending"] and not user["passkey_enabled"]:
		clear_passkey_onboarding(conn, user["id"])
		_log.info("PASSKEY_ONBOARDING_COMPLETE user_id=%s", user["id"])
	elif not user["otp_enabled"]:
		# Regular passkey registration (user-initiated): enable passkey auth
		update_user_auth_method(conn, user["id"], "passkey", passkey_enabled=True)

	_log.info(
		"PASSKEY_REGISTER_FINISH success user_id=%s passkey_id=%s device=%s",
		user["id"],
		passkey_id,
		payload.device_name or "unnamed",
	)

	return ok_response(
		message="Passkey registered successfully",
		data={"passkey_id": passkey_id},
	)


# ---------------------------------------------------------------------------
# Login Endpoints
# ---------------------------------------------------------------------------


@router.post("/login/start")
@limiter.limit(RATE_LIMIT_AUTH)
def passkey_login_start(
	request: Request,
	payload: PasskeyLoginStartRequest = None,
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Start passkey authentication.
	
	Can be called with or without a username:
	- With username: Returns options with allowCredentials for that user's passkeys
	- Without username: Returns options for discoverable credential (usernameless) flow
	
	Returns PublicKeyCredentialRequestOptions for navigator.credentials.get()
	"""
	client_ip = _get_client_ip(request)

	# Check for lockout
	is_locked, seconds_remaining = is_ip_locked(conn, client_ip)
	if is_locked:
		raise HTTPException(
			status_code=429,
			detail="Too many failed attempts. Please try again later.",
			headers={"Retry-After": str(seconds_remaining)},
		)

	rp_id = _get_rp_id(request)
	user_id = None
	credential_ids = None

	if payload and payload.username:
		# Username provided - fetch user's credentials
		user = get_user_by_username(conn, payload.username)
		if user and user["is_active"]:
			user_id = user["id"]
			credential_ids = get_credential_ids_for_user(conn, user_id)
			if not credential_ids:
				# User has no passkeys
				_log.info("PASSKEY_LOGIN_START no passkeys for user=%s", payload.username)
				raise HTTPException(status_code=400, detail="No passkeys registered for this user")
		else:
			# Don't reveal user existence - still generate options
			_log.debug("PASSKEY_LOGIN_START unknown/inactive user=%s", payload.username)

	options = get_authentication_options(
		conn=conn,
		rp_id=rp_id,
		user_id=user_id,
		credential_ids=credential_ids,
	)

	_log.debug("PASSKEY_LOGIN_START rp_id=%s user_id=%s", rp_id, user_id)

	return ok_response(data=options)


@router.post("/login/finish")
@limiter.limit(RATE_LIMIT_AUTH)
def passkey_login_finish(
	request: Request,
	response: Response,
	payload: PasskeyLoginFinishRequest,
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Complete passkey authentication.
	
	Verifies the WebAuthn response, creates a session, and sets auth cookie.
	"""
	client_ip = _get_client_ip(request)
	rp_id = _get_rp_id(request)
	origin = _get_origin(request)

	# Check for lockout
	is_locked, seconds_remaining = is_ip_locked(conn, client_ip)
	if is_locked:
		raise HTTPException(
			status_code=429,
			detail="Too many failed attempts. Please try again later.",
			headers={"Retry-After": str(seconds_remaining)},
		)

	# Extract credential ID and challenge from response
	try:
		credential_id = payload.credential.get("id", "")
		client_data_json = payload.credential.get("response", {}).get("clientDataJSON", "")
		import base64
		import json
		padding = 4 - len(client_data_json) % 4
		if padding != 4:
			client_data_json += "=" * padding
		client_data = json.loads(base64.urlsafe_b64decode(client_data_json))
		challenge = client_data.get("challenge", "")
	except Exception as e:
		_log.warning("PASSKEY_LOGIN_FINISH invalid clientDataJSON: %s", e)
		record_failed_login(conn, client_ip)
		raise HTTPException(status_code=400, detail="Invalid credential response")

	# Consume challenge (validates it existed and hasn't expired)
	try:
		challenge_result = consume_authentication_challenge(conn, challenge)
		challenge_user_id = challenge_result.user_id  # None is valid for discoverable credentials
	except InvalidChallengeError as e:
		_log.warning("PASSKEY_LOGIN_FINISH invalid challenge: %s ip=%s", e, client_ip)
		record_failed_login(conn, client_ip)
		raise HTTPException(status_code=400, detail="Invalid or expired authentication challenge")

	# Look up the credential by ID to find the user
	passkey_row = get_passkey_by_credential_id(conn, credential_id)
	if not passkey_row:
		_log.warning("PASSKEY_LOGIN_FINISH unknown credential_id ip=%s", client_ip)
		record_failed_login(conn, client_ip)
		raise HTTPException(status_code=401, detail="Invalid passkey")

	user_id = passkey_row["user_id"]
	username = passkey_row["username"]

	# If challenge was bound to a user, verify it matches
	if challenge_user_id is not None and challenge_user_id != user_id:
		_log.warning(
			"PASSKEY_LOGIN_FINISH user mismatch challenge_user=%s credential_user=%s ip=%s",
			challenge_user_id,
			user_id,
			client_ip,
		)
		record_failed_login(conn, client_ip)
		raise HTTPException(status_code=401, detail="Invalid passkey")

	# Check user is active
	if not passkey_row["is_active"]:
		_log.info("PASSKEY_LOGIN_FINISH inactive user=%s ip=%s", username, client_ip)
		raise HTTPException(status_code=403, detail="Account disabled")

	# Verify the authentication response
	try:
		result = verify_authentication(
			credential_json=payload.credential,
			expected_challenge=challenge,
			expected_origin=origin,
			expected_rp_id=rp_id,
			credential_public_key=passkey_row["public_key"],
			credential_current_sign_count=passkey_row["sign_count"],
		)
	except Exception as e:
		_log.warning(
			"PASSKEY_LOGIN_FINISH verification failed user=%s ip=%s error=%s",
			username,
			client_ip,
			e,
		)
		record_failed_login(conn, client_ip)
		raise HTTPException(status_code=401, detail="Passkey verification failed")

	# Update sign count for replay protection
	update_passkey_sign_count(conn, passkey_row["id"], result.new_sign_count)

	# Clear any login attempt lockouts
	clear_login_attempts(conn, client_ip)

	# Create session token (same as password login)
	now = datetime.now(timezone.utc)
	token = new_token()
	expires_at, max_expires_at = generate_token_expiry(now=now)

	create_auth_token(conn, user_id, token, expires_at, max_expires_at)
	update_last_login(conn, user_id, client_ip)

	# Set auth cookie
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

	_log.info("PASSKEY_LOGIN_SUCCESS ip=%s username=%s", client_ip, username)

	return ok_response(
		data={
			"token": token,
			"expires_at": expires_at,
			"token_type": "Bearer",
		}
	)


# ---------------------------------------------------------------------------
# Management Endpoints
# ---------------------------------------------------------------------------


@router.get("")
def list_passkeys(
	user: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""List all passkeys for the current user."""
	rows = get_passkeys_for_user(conn, user["id"])

	passkeys = []
	for row in rows:
		transports = None
		if row["transports"]:
			import json
			try:
				transports = json.loads(row["transports"])
			except (json.JSONDecodeError, TypeError):
				transports = None

		passkeys.append({
			"id": row["id"],
			"device_name": row["device_name"],
			"created_at": row["created_at"],
			"transports": transports,
		})

	return ok_response(data=passkeys)


@router.delete("/{passkey_id}")
def delete_passkey_endpoint(
	passkey_id: int,
	user: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Delete a passkey belonging to the current user."""
	passkey = get_passkey_by_id(conn, passkey_id)
	if not passkey:
		raise HTTPException(status_code=404, detail="Passkey not found")

	if passkey["user_id"] != user["id"]:
		raise HTTPException(status_code=403, detail="Cannot delete another user's passkey")

	delete_passkey(conn, passkey_id, user["id"])

	# Check if user has any remaining passkeys
	remaining = count_user_passkeys(conn, user["id"])
	if remaining == 0:
		# Disable passkey auth method
		auth_method = "password_mfa" if user["otp_enabled"] else "password"
		update_user_auth_method(conn, user["id"], auth_method, passkey_enabled=False)

	_log.info(
		"PASSKEY_DELETE user_id=%s passkey_id=%s remaining=%s",
		user["id"],
		passkey_id,
		remaining,
	)

	return ok_response(message="Passkey deleted")


@router.post("/reset/{user_id}")
def reset_user_passkeys(
	user_id: int,
	admin: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Admin endpoint: Reset all passkeys for a user."""
	target_user = get_user_by_id(conn, user_id)
	if not target_user:
		raise HTTPException(status_code=404, detail="User not found")

	deleted_count = disable_user_passkeys(conn, user_id)

	_log.warning(
		"PASSKEY_RESET_BY_ADMIN admin=%s target_user=%s deleted_count=%s",
		admin["username"],
		target_user["username"],
		deleted_count,
	)

	return ok_response(
		message=f"Reset {deleted_count} passkey(s) for user",
		data={"deleted_count": deleted_count},
	)


@router.get("/user/{user_id}")
def list_user_passkeys_admin(
	user_id: int,
	admin: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Admin endpoint: List passkeys for any user."""
	target_user = get_user_by_id(conn, user_id)
	if not target_user:
		raise HTTPException(status_code=404, detail="User not found")

	rows = get_passkeys_for_user(conn, user_id)

	passkeys = []
	for row in rows:
		transports = None
		if row["transports"]:
			import json
			try:
				transports = json.loads(row["transports"])
			except (json.JSONDecodeError, TypeError):
				transports = None

		passkeys.append({
			"id": row["id"],
			"device_name": row["device_name"],
			"created_at": row["created_at"],
			"transports": transports,
		})

	return ok_response(data=passkeys)


@router.get("/check")
def check_passkey_support(request: Request):
	"""Check if passkey login is available (returns RP ID for frontend)."""
	rp_id = _get_rp_id(request)
	return ok_response(data={"rp_id": rp_id, "enabled": True})


@router.get("/available")
def check_passkeys_available(conn: sqlite3.Connection = Depends(get_conn)):
	"""Check if any passkeys are configured in the system (public endpoint)."""
	available = any_passkeys_exist(conn)
	return ok_response(data={"available": available})


# ---------------------------------------------------------------------------
# Admin Passkey Management
# ---------------------------------------------------------------------------


@router.post("/enable/{user_id}")
def enable_user_passkey(
	user_id: int,
	admin: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Admin endpoint: Enable passkey authentication for a user.
	
	Sets passkey_pending=1, user will be prompted to register passkey on next login.
	"""
	target_user = get_user_by_id(conn, user_id)
	if not target_user:
		raise HTTPException(status_code=404, detail="User not found")

	# Check if already enabled
	if target_user["passkey_enabled"]:
		return ok_response(message="Passkey already enabled for user")

	if not set_passkey_pending(conn, user_id, True):
		raise HTTPException(status_code=500, detail="Failed to enable passkey")

	_log.info(
		"PASSKEY_ENABLED_BY_ADMIN admin=%s target_user=%s",
		admin["username"],
		target_user["username"],
	)

	return ok_response(
		message="Passkey enabled. User will set up passkey on next login.",
		data={"passkey_pending": True},
	)


@router.post("/disable/{user_id}")
def disable_user_passkey(
	user_id: int,
	admin: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Admin endpoint: Disable passkey authentication for a user.
	
	Deletes all passkeys and resets passkey_enabled and passkey_pending.
	"""
	target_user = get_user_by_id(conn, user_id)
	if not target_user:
		raise HTTPException(status_code=404, detail="User not found")

	deleted_count = disable_user_passkeys(conn, user_id)

	_log.warning(
		"PASSKEY_DISABLED_BY_ADMIN admin=%s target_user=%s deleted_count=%d",
		admin["username"],
		target_user["username"],
		deleted_count,
	)

	return ok_response(
		message="Passkey disabled for user",
		data={"deleted_count": deleted_count},
	)

