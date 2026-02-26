#!/usr/bin/env python3
#
# app/utils/otp.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""TOTP/OTP utility helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets

import pyotp

_OTP_RE = re.compile(r"^\d{6,8}$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


def _normalize_recovery_code(code: str) -> str:
	"""Normalize recovery code input for consistent handling."""
	return code.strip().lower()


def _hash_recovery_code(code: str) -> str:
	"""One-way hash a recovery code for safe storage."""
	normalized = _normalize_recovery_code(code)
	return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _is_sha256_hex(value: str) -> bool:
	"""Return True when value looks like a SHA-256 hex digest."""
	return bool(_SHA256_HEX_RE.fullmatch(value))


def generate_otp_secret() -> str:
	"""Create a new random base32 secret for TOTP."""
	return pyotp.random_base32()


def build_provisioning_uri(secret: str, username: str, issuer: str = "WireBuddy") -> str:
	"""Build an otpauth provisioning URI for authenticator apps."""
	totp = pyotp.TOTP(secret)
	return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_otp(secret: str, code: str) -> bool:
	"""Verify a TOTP code with a small clock skew window."""
	if not _OTP_RE.fullmatch(str(code or "").strip()):
		return False
	totp = pyotp.TOTP(secret)
	return bool(totp.verify(str(code).strip(), valid_window=0))


def generate_recovery_codes(n: int = 8, byte_length: int = 8) -> list[str]:
	"""Generate one-time recovery codes."""
	count = int(n)
	length = int(byte_length)
	if count <= 0 or length <= 0:
		return []
	return [secrets.token_hex(length) for _ in range(count)]


def serialize_recovery_codes(codes: list[str]) -> str:
	"""Serialize recovery codes into JSON for storage."""
	hashed = [_hash_recovery_code(code) for code in codes if _normalize_recovery_code(str(code))]
	return json.dumps(hashed)


def deserialize_recovery_codes(raw: str | None) -> list[str]:
	"""Deserialize stored recovery codes JSON string."""
	if not raw:
		return []
	try:
		loaded = json.loads(raw)
	except (json.JSONDecodeError, TypeError):
		return []
	if not isinstance(loaded, list):
		return []
	return [str(item).strip().lower() for item in loaded if str(item).strip()]


def use_recovery_code(candidate: str, stored_json: str | None) -> tuple[bool, str]:
	"""Verify and consume a recovery code; returns (success, updated_json)."""
	stored_codes = deserialize_recovery_codes(stored_json)
	normalized_candidate = _normalize_recovery_code(candidate)
	if not normalized_candidate:
		return (False, json.dumps([c for c in stored_codes if _is_sha256_hex(c)]))

	candidate_hash = _hash_recovery_code(normalized_candidate)
	remaining_hashed: list[str] = []
	found = False

	for stored in stored_codes:
		stored_norm = _normalize_recovery_code(stored)
		if not stored_norm:
			continue

		match = False
		if not found:
			if _is_sha256_hex(stored_norm):
				match = hmac.compare_digest(candidate_hash, stored_norm)
			else:
				match = hmac.compare_digest(normalized_candidate, stored_norm)

		if match and not found:
			found = True
			continue

		remaining_hashed.append(stored_norm if _is_sha256_hex(stored_norm) else _hash_recovery_code(stored_norm))

	return (found, json.dumps(remaining_hashed))
