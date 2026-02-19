#!/usr/bin/env python3
#
# app/utils/crypto.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Cryptographic helpers for password hashing and token generation."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

# Dummy hash for timing attack prevention when username doesn't exist
# Pre-computed with 600k iterations to match real password verification timing
DUMMY_PASSWORD_HASH = "pbkdf2:sha256:600000$0000000000000000000000000000000000000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"


def hash_password(password: str) -> str:
	"""Hash a password using PBKDF2-SHA256 with random salt.
	
	Returns:
		Format: 'pbkdf2:sha256:iterations$salt$hash'
	"""
	salt = os.urandom(16)
	iterations = 600_000  # OWASP recommended minimum for PBKDF2-SHA256
	
	dk = hashlib.pbkdf2_hmac(
		"sha256",
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
		iterations = int(method_parts[2])
		salt = bytes.fromhex(parts[1])
		stored_hash = bytes.fromhex(parts[2])
		
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
	return now >= expires_at


def generate_token_expiry(hours: int = 1, max_hours: int = 24) -> tuple[datetime, datetime]:
	"""Generate token expiry timestamps.
	
	Args:
		hours: Initial validity period in hours (default: 1)
		max_hours: Maximum validity period in hours (default: 24)
	
	Returns:
		Tuple of (expires_at, max_expires_at) datetimes
	"""
	now = datetime.now(timezone.utc)
	expires_at = now + timedelta(hours=hours)
	max_expires_at = now + timedelta(hours=max_hours)
	return expires_at, max_expires_at
