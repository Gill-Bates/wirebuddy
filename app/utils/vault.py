#!/usr/bin/env python3
#
# app/utils/vault.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Fernet-based encryption for secrets at rest (private keys, preshared keys).

Security model:
- Fernet provides authenticated encryption.
- Peppers must remain high-entropy secrets.
- Vault payload integrity depends on Fernet MAC validation.
- Fernet tokens expose encryption timestamps in plaintext metadata.
- Secret material may exist in immutable Python objects during encrypt/decrypt
	and rotation flows; memory zeroization is not guaranteed in CPython.

Supported storage formats:
  - ``vault:1:<salt_hex>:<fernet_token>``
    PBKDF2-SHA256 directly on ``pepper + row_salt`` for every row
  - ``vault:2:<salt_hex>:<fernet_token>``
    PBKDF2-SHA256 once per pepper to derive a master key, then HKDF-SHA256
    with the per-row salt to derive the row key

Both formats preserve the "unique key per row" property. ``vault:2`` is the
default for new writes because it avoids the old per-row PBKDF2 cost while
remaining backwards-compatible with existing ``vault:1`` values.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_log = logging.getLogger(__name__)

_VAULT_PREFIX = "vault:"
_VAULT_VERSION_1 = "1"
_VAULT_VERSION_2 = "2"
_VAULT_CURRENT_VERSION = _VAULT_VERSION_2
_VAULT_INFO_V2 = b"wirebuddy-vault-v2"
_MASTER_SALT_V2 = b"wirebuddy-vault-master-v2"
_PBKDF2_ITERATIONS = int(os.getenv("WIREBUDDY_PBKDF2_ITERATIONS", "480000"))
_MAX_TOKEN_LENGTH = 16_384


def _vault_info_v2() -> bytes:
	"""Return deployment-scoped HKDF context when configured."""
	deployment_id = os.getenv("WIREBUDDY_DEPLOYMENT_ID", "").strip()
	if not deployment_id:
		return _VAULT_INFO_V2
	return f"{_VAULT_INFO_V2.decode('ascii')}:{deployment_id}".encode("utf-8")


def _validate_pepper(pepper: str) -> None:
	"""Reject missing peppers early at the vault boundary."""
	if not pepper:
		raise ValueError("WIREBUDDY_SECRET_KEY is not set")


def _format_value(version: str, salt: bytes, token: bytes) -> str:
	"""Assemble a vault payload from its parsed components."""
	return f"{_VAULT_PREFIX}{version}:{salt.hex()}:{token.decode('ascii')}"


def _parse_value(stored: str) -> tuple[str, bytes, str]:
	"""Parse a vault payload and return ``(version, salt, token)``.

	Raises:
		ValueError: If the payload is malformed or unsupported.
	"""
	if not stored:
		raise ValueError("empty secret")
	if not stored.startswith(_VAULT_PREFIX):
		raise ValueError("not vault-encrypted")

	parts = stored.split(":", 3)
	if len(parts) != 4:
		raise ValueError("invalid vault field count")

	_, version, salt_hex, fernet_token = parts
	if version not in {_VAULT_VERSION_1, _VAULT_VERSION_2}:
		raise ValueError(f"unsupported vault version: {version}")

	try:
		salt = bytes.fromhex(salt_hex)
	except ValueError as exc:
		raise ValueError("invalid salt hex") from exc
	if len(salt) != 16:
		raise ValueError("invalid salt length")
	if not fernet_token:
		raise ValueError("missing fernet token")
	if len(fernet_token) > _MAX_TOKEN_LENGTH:
		raise ValueError("vault token too large")
	return version, salt, fernet_token


def _derive_key_v1(pepper: str, salt: bytes) -> bytes:
	"""Derive a Fernet key using the legacy per-row PBKDF2 scheme."""
	dk = hashlib.pbkdf2_hmac(
		"sha256",
		pepper.encode("utf-8"),
		salt,
		iterations=_PBKDF2_ITERATIONS,
	)
	return base64.urlsafe_b64encode(dk)


@functools.lru_cache(maxsize=8)
def _derive_master_key_v2(pepper: str) -> bytes:
	"""Derive and cache the vault v2 master key for a pepper."""
	dk = hashlib.pbkdf2_hmac(
		"sha256",
		pepper.encode("utf-8"),
		_MASTER_SALT_V2,
		iterations=_PBKDF2_ITERATIONS,
	)
	return dk


def _derive_key_v2(pepper: str, salt: bytes) -> bytes:
	"""Derive a Fernet key via HKDF from the cached v2 master key."""
	hkdf = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		info=_vault_info_v2(),
	)
	return base64.urlsafe_b64encode(hkdf.derive(_derive_master_key_v2(pepper)))


def _derive_key(version: str, pepper: str, salt: bytes) -> bytes:
	"""Dispatch to the correct versioned key derivation algorithm."""
	if version == _VAULT_VERSION_1:
		return _derive_key_v1(pepper, salt)
	if version == _VAULT_VERSION_2:
		return _derive_key_v2(pepper, salt)
	raise ValueError(f"unsupported vault version: {version}")


def encrypt(plaintext: str, pepper: str) -> str:
	"""Encrypt a plaintext secret.

	Returns a vault-formatted string using the current vault version.
	"""
	_validate_pepper(pepper)
	if plaintext == "":
		raise ValueError("Cannot encrypt empty secret")
	if is_encrypted(plaintext):
		raise ValueError("Refusing to double-encrypt a vault value")
	salt = os.urandom(16)
	key = _derive_key(_VAULT_CURRENT_VERSION, pepper, salt)
	fernet = Fernet(key)
	token = fernet.encrypt(plaintext.encode("utf-8"))
	return _format_value(_VAULT_CURRENT_VERSION, salt, token)


def encrypt_if_needed(value: str | None, pepper: str) -> str | None:
	"""Encrypt ``value`` unless it is empty or already vault-encrypted."""
	if value is None or value == "":
		return value
	if is_encrypted(value):
		return value
	return encrypt(value, pepper)


def decrypt_if_needed(value: str | None, pepper: str) -> str | None:
	"""Decrypt ``value`` if it is vault-encrypted, otherwise return it unchanged."""
	if value is None or not is_encrypted(value):
		return value
	return decrypt(value, pepper)


def decrypt_required(value: str | None, pepper: str) -> str | None:
	"""Decrypt a value that is expected to already be vault-encrypted."""
	if value is None:
		return None
	if not is_encrypted(value):
		raise ValueError("Expected encrypted vault value")
	return decrypt(value, pepper)


def decrypt(stored: str, pepper: str) -> str:
	"""Decrypt a vault-formatted string back to plaintext.
	"""
	_validate_pepper(pepper)
	try:
		version, salt, fernet_token = _parse_value(stored)
	except ValueError as exc:
		_log.warning("vault decrypt failed")
		raise ValueError(f"Corrupt vault payload: {exc}") from exc

	if version == _VAULT_VERSION_1:
		_log.warning("Decrypting deprecated vault:1 payload")

	try:
		key = _derive_key(version, pepper, salt)
		fernet = Fernet(key)
		return fernet.decrypt(fernet_token.encode("ascii")).decode("utf-8")
	except InvalidToken as exc:
		_log.warning("vault decrypt failed")
		raise ValueError("Cannot decrypt secret — wrong WIREBUDDY_SECRET_KEY?") from exc


def rotate(stored: str | None, old_pepper: str, new_pepper: str) -> str | None:
	"""Re-encrypt a stored value with a new pepper.

	Plaintext values are accepted to simplify migration tooling.
	Already-encrypted values are decrypted with ``old_pepper`` first.
	"""
	if stored is None or stored == "":
		return stored
	plaintext = decrypt(stored, old_pepper) if is_encrypted(stored) else stored
	return encrypt(plaintext, new_pepper)


def is_encrypted(value: str | None) -> bool:
	"""Check whether a value is already vault-encrypted."""
	return bool(
		value
		and value.startswith(_VAULT_PREFIX)
		and value.count(":") == 3
	)


def clear_cached_keys() -> None:
	"""Clear cached derived master keys, e.g. during rotation or shutdown."""
	_derive_master_key_v2.cache_clear()
