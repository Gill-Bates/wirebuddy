#!/usr/bin/env python3
#
# app/utils/enrollment_keys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Master-side storage of the Ed25519 enrollment-token signing key.

The 32-byte seed lives in the ``settings`` table, vault-encrypted with
``WIREBUDDY_SECRET_KEY`` (so it is part of every v2 backup and useless without
that secret). It is never written unencrypted, logged or returned by an API.
Nodes never call into this module.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import get_setting
from . import enrollment_signing, vault
from .node_token import (
	MAX_TOKEN_AGE,
	generate_enrollment_token,
	generate_enrollment_token_v2,
	token_version,
	verify_enrollment_token,
	verify_enrollment_token_v2,
)
from .time import utcnow

__all__ = [
	"EnrollmentKeyError",
	"get_public_key_info",
	"get_signing_key",
	"issue_token",
	"record_v1_use",
	"rotate_signing_key",
	"verify_any",
]

_log = logging.getLogger(__name__)

SIGNING_KEY_SETTING = "enrollment_signing_key_v2"
SIGNING_KID_SETTING = "enrollment_signing_kid_v2"
V1_LAST_USED_SETTING = "enrollment_v1_last_used_at"

_lock = threading.Lock()


class EnrollmentKeyError(RuntimeError):
	"""The signing key is missing or cannot be read; callers must fail closed."""


def _write(conn: sqlite3.Connection, key: str, value: str, *, replace: bool) -> None:
	# Not set_setting: INSERT OR IGNORE keeps a concurrent first creation from overwriting
	# the winner's key, and the value is already vault-encrypted.
	verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
	conn.execute(f"{verb} INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (key, value, utcnow()))


def _store_new(conn: sqlite3.Connection, secret_key: str, *, replace: bool) -> None:
	key = enrollment_signing.generate_private_key()
	seed = enrollment_signing.private_key_seed(key)
	encrypted = vault.encrypt(enrollment_signing.b64u_encode(seed), secret_key)
	kid = enrollment_signing.key_id(key.public_key())
	with transaction(conn, immediate=True):
		_write(conn, SIGNING_KEY_SETTING, encrypted, replace=replace)
		if replace or get_setting(conn, SIGNING_KID_SETTING) is None:
			_write(conn, SIGNING_KID_SETTING, kid, replace=True)
	_log.info("Enrollment signing key %s (kid=%s)", "rotated" if replace else "generated", kid)


def _load(conn: sqlite3.Connection, secret_key: str) -> Ed25519PrivateKey:
	stored = get_setting(conn, SIGNING_KEY_SETTING)
	if stored is None:
		raise EnrollmentKeyError("Enrollment signing key is missing")
	try:
		seed_b64 = vault.decrypt(stored, secret_key)
		return enrollment_signing.private_key_from_seed(enrollment_signing.b64u_decode(seed_b64))
	except ValueError as exc:
		_log.error("Enrollment signing key is unreadable (restored under a different WIREBUDDY_SECRET_KEY?); rotate it")
		raise EnrollmentKeyError("Enrollment signing key is unreadable; rotate it") from exc


def get_signing_key(conn: sqlite3.Connection, secret_key: str) -> Ed25519PrivateKey:
	"""Return the master signing key, creating it on first use.

	An unreadable stored key is never regenerated silently (that would hide a
	restore under the wrong secret); it raises ``EnrollmentKeyError``.
	"""
	if not secret_key:
		raise EnrollmentKeyError("WIREBUDDY_SECRET_KEY is required")
	with _lock:
		if get_setting(conn, SIGNING_KEY_SETTING) is None:
			_store_new(conn, secret_key, replace=False)  # INSERT OR IGNORE: safe across processes
		return _load(conn, secret_key)


def rotate_signing_key(conn: sqlite3.Connection, secret_key: str) -> Ed25519PrivateKey:
	"""Replace the signing key; all unused v2 tokens become invalid."""
	if not secret_key:
		raise EnrollmentKeyError("WIREBUDDY_SECRET_KEY is required")
	with _lock:
		_store_new(conn, secret_key, replace=True)
		return _load(conn, secret_key)


def get_public_key_info(conn: sqlite3.Connection, secret_key: str) -> dict[str, str]:
	"""Return ``{"verify_key": "wbpk2:...", "kid": ...}`` for display; contains no secret."""
	public = get_signing_key(conn, secret_key).public_key()
	return {"verify_key": enrollment_signing.encode_public_key(public), "kid": enrollment_signing.key_id(public)}


def issue_token(
	conn: sqlite3.Connection,
	secret_key: str,
	*,
	version: int,
	master_url: str,
	node_id: str,
	node_name: str,
) -> tuple[str, str]:
	"""Issue ``(token, api_secret)`` in the requested protocol version (1 or 2)."""
	if version == 1:
		return generate_enrollment_token(master_url, node_id, node_name, secret_key)
	if version == 2:
		return generate_enrollment_token_v2(master_url, node_id, node_name, get_signing_key(conn, secret_key))
	raise ValueError("Unsupported enrollment token version")


def verify_any(
	conn: sqlite3.Connection,
	token_string: str,
	secret_key: str,
	*,
	accept_v1: bool,
	max_age: timedelta | None = MAX_TOKEN_AGE,
) -> tuple[dict[str, str], int]:
	"""Verify a token of either version; returns ``(payload, version)``.

	The version comes from the token prefix only. A v1 token is refused with
	ValueError when ``accept_v1`` is off. ``EnrollmentKeyError`` means the
	server-side key is unusable (not a client error). Never creates the signing
	key: a v2 token cannot be valid before one was issued.
	"""
	if token_version(token_string) == 2:
		# Verify path is read-only: an anonymous request must not create the key.
		if not secret_key:
			raise EnrollmentKeyError("WIREBUDDY_SECRET_KEY is required")
		if get_setting(conn, SIGNING_KEY_SETTING) is None:
			raise ValueError("Invalid enrollment token")
		public = _load(conn, secret_key).public_key()
		return verify_enrollment_token_v2(token_string, public, max_age), 2
	if not accept_v1:
		raise ValueError("Legacy enrollment tokens are no longer accepted; regenerate the token")
	return verify_enrollment_token(token_string, secret_key, max_age), 1


def record_v1_use(conn: sqlite3.Connection, node_id: str) -> None:
	"""Log and remember that a legacy token was accepted (migration progress)."""
	_log.warning("Accepted deprecated v1 (HMAC) enrollment token for node=%s; regenerate it as v2", node_id)
	with transaction(conn):
		_write(conn, V1_LAST_USED_SETTING, utcnow().isoformat(), replace=True)
