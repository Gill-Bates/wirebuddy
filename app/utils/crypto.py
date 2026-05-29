#!/usr/bin/env python3
#
# app/utils/crypto.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Cryptographic helpers for password hashing and token generation."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = 600_000
_MIN_PBKDF2_ITERATIONS = 100_000
_MAX_PBKDF2_ITERATIONS = 1_000_000
_PASSWORD_SALT_BYTES = 16
_PASSWORD_HASH_BYTES = hashlib.new(_PBKDF2_ALGORITHM).digest_size
_MAX_TOKEN_HOURS = 24 * 30

# Dummy hash for timing attack prevention when username doesn't exist
# Pre-computed with 600k iterations to match real password verification timing
DUMMY_PASSWORD_HASH = (
	"pbkdf2:sha256:600000"
	"$00000000000000000000000000000000"
	"$0000000000000000000000000000000000000000000000000000000000000000"
)


def hash_password(password: str) -> str:
	"""Hash a password using PBKDF2-SHA256 with random salt.
	
	Returns:
		Format: 'pbkdf2:sha256:iterations$salt$hash'
	"""
	salt = os.urandom(_PASSWORD_SALT_BYTES)
	iterations = _PBKDF2_ITERATIONS  # OWASP recommended minimum for PBKDF2-SHA256
	
	dk = hashlib.pbkdf2_hmac(
		_PBKDF2_ALGORITHM,
		password.encode("utf-8"),
		salt,
		iterations,
	)
	
	salt_hex = salt.hex()
	hash_hex = dk.hex()
	
	return f"pbkdf2:sha256:{iterations}${salt_hex}${hash_hex}"


def verify_password(password: str, password_hash: str) -> bool:
	"""Verify a password against a stored hash.
	
	Uses constant-time comparison to prevent timing attacks.
	"""
	try:
		# Parse the hash format
		parts = password_hash.split("$")
		if len(parts) != 3:
			return False
		
		method_parts = parts[0].split(":")
		if len(method_parts) != 3 or method_parts[0] != "pbkdf2":
			return False
		
		algorithm = method_parts[1]
		if algorithm != _PBKDF2_ALGORITHM:
			return False

		iterations = int(method_parts[2])
		if not (_MIN_PBKDF2_ITERATIONS <= iterations <= _MAX_PBKDF2_ITERATIONS):
			return False

		salt = bytes.fromhex(parts[1])
		if len(salt) != _PASSWORD_SALT_BYTES:
			return False

		stored_hash = bytes.fromhex(parts[2])
		if len(stored_hash) != _PASSWORD_HASH_BYTES:
			return False
		
		# Compute hash of provided password
		dk = hashlib.pbkdf2_hmac(
			algorithm,
			password.encode("utf-8"),
			salt,
			iterations,
		)
		
		# Constant-time comparison
		return hmac.compare_digest(dk, stored_hash)
		
	except (ValueError, IndexError, TypeError):
		return False


def new_token() -> str:
	"""Generate a new secure random token (32 bytes, URL-safe base64)."""
	return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
	"""Hash a token for storage using SHA-256.
	
	We hash tokens before storage so that database leaks don't
	directly expose valid authentication tokens.
	"""
	return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_expired(expires_at: datetime) -> bool:
	"""Check if a token has expired."""
	now = datetime.now(timezone.utc)
	if expires_at.tzinfo is None:
		return True
	return now >= expires_at.astimezone(timezone.utc)


def generate_token_expiry(
	hours: int = 1,
	max_hours: int = 24,
	now: datetime | None = None,
) -> tuple[datetime, datetime]:
	"""Generate token expiry timestamps.
	
	Args:
		hours: Initial validity period in hours (default: 1)
		max_hours: Maximum validity period in hours (default: 24)
		now: Optional anchor time (UTC). Uses current UTC time when omitted.
	
	Returns:
		Tuple of (expires_at, max_expires_at) datetimes
	"""
	if hours < 1:
		raise ValueError("hours must be >= 1")
	if max_hours < 1:
		raise ValueError("max_hours must be >= 1")
	if hours > max_hours:
		raise ValueError("hours must not exceed max_hours")
	if max_hours > _MAX_TOKEN_HOURS:
		raise ValueError("max_hours exceeds allowed maximum")
	if now is not None and now.tzinfo is None:
		raise ValueError("now must be timezone-aware")

	now = now or datetime.now(timezone.utc)
	expires_at = now + timedelta(hours=hours)
	max_expires_at = now + timedelta(hours=max_hours)
	return expires_at, max_expires_at
