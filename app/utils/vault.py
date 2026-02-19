#!/usr/bin/env python3
#
# app/utils/vault.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Fernet-based encryption for secrets at rest (private keys, preshared keys).

Each value is encrypted with a unique Fernet key derived from:
  - A random 16-byte salt (stored alongside the ciphertext)
  - The application secret key (pepper) from WIREBUDDY_SECRET_KEY

Storage format:  "vault:1:<salt_hex>:<fernet_token>"
  - "vault:1" = version tag for forward compatibility
  - salt_hex  = 32-char hex-encoded random salt
  - fernet_token = base64 Fernet ciphertext (contains its own IV + HMAC)

This ensures every row has a unique encryption key even when the pepper
is the same, and a database dump alone is useless without the env secret.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

_log = logging.getLogger(__name__)

_VAULT_PREFIX = "vault:1:"


def _derive_key(pepper: str, salt: bytes) -> bytes:
	"""Derive a 32-byte Fernet key from pepper + salt via PBKDF2-SHA256."""
	dk = hashlib.pbkdf2_hmac(
		"sha256",
		pepper.encode("utf-8"),
		salt,
		iterations=480_000,
	)
	# Fernet requires url-safe base64-encoded 32-byte key
	return base64.urlsafe_b64encode(dk)


def encrypt(plaintext: str, pepper: str) -> str:
	"""Encrypt a plaintext secret.

	Returns a vault-formatted string:  vault:1:<salt_hex>:<fernet_token>
	"""
	if not pepper:
		raise ValueError("WIREBUDDY_SECRET_KEY is not set")
	salt = os.urandom(16)
	key = _derive_key(pepper, salt)
	f = Fernet(key)
	token = f.encrypt(plaintext.encode("utf-8"))
	return f"{_VAULT_PREFIX}{salt.hex()}:{token.decode('ascii')}"


def decrypt(stored: str, pepper: str) -> str:
	"""Decrypt a vault-formatted string back to plaintext.

	If the value is not vault-formatted (legacy plaintext), it is
	returned as-is so that the migration can happen gradually.
	"""
	if not pepper:
		raise ValueError("WIREBUDDY_SECRET_KEY is not set")
	
	if not stored or not stored.startswith(_VAULT_PREFIX):
		# Legacy plaintext — return unchanged
		return stored

	try:
		rest = stored[len(_VAULT_PREFIX):]
		salt_hex, fernet_token = rest.split(":", 1)
		salt = bytes.fromhex(salt_hex)
		if len(salt) != 16:
			raise ValueError("Invalid salt length")
		key = _derive_key(pepper, salt)
		f = Fernet(key)
		return f.decrypt(fernet_token.encode("ascii")).decode("utf-8")
	except (InvalidToken, ValueError) as exc:
		_log.exception("vault decrypt failed")
		raise ValueError("Cannot decrypt secret — wrong WIREBUDDY_SECRET_KEY?") from exc


def is_encrypted(value: str | None) -> bool:
	"""Check whether a value is already vault-encrypted."""
	return bool(value and value.startswith(_VAULT_PREFIX))
