#!/usr/bin/env python3
#
# app/utils/enrollment_signing.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Ed25519 signing primitives for enrollment tokens (protocol v2).

Token wire format: ``wb2.<b64url(payload_json)>.<b64url(signature)>``.
The private key exists only on the master; nodes pin the public key
(``wbpk2:<b64url raw key>``) and can therefore verify but never forge tokens.
This module holds no payload policy and no storage; see ``node_token`` and
``enrollment_keys``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = [
	"PUBLIC_KEY_PREFIX",
	"TOKEN_V2_PREFIX",
	"b64u_decode",
	"b64u_encode",
	"decode_token_v2",
	"encode_public_key",
	"encode_token_v2",
	"generate_private_key",
	"is_public_key_string",
	"is_token_v2",
	"key_id",
	"parse_public_key",
	"private_key_from_seed",
	"private_key_seed",
	"sign",
	"verify",
]

TOKEN_V2_PREFIX = "wb2."  # noqa: S105 - wire prefix, not a credential
PUBLIC_KEY_PREFIX = "wbpk2:"
# Domain separation: a signature made here is never valid in another context.
_SIGNING_CONTEXT = b"wirebuddy-enrollment-token-v2\0"
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_PAYLOAD_B64_LEN = 16_384
_SIGNATURE_LEN = 64
_KEY_LEN = 32


def b64u_encode(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
	"""Strict unpadded base64url decode; rejects any character outside the alphabet."""
	if not isinstance(text, str) or not text or _B64URL_RE.fullmatch(text) is None:
		raise ValueError("Invalid token encoding")
	try:
		return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
	except (binascii.Error, ValueError) as exc:
		raise ValueError("Invalid token encoding") from exc


def is_token_v2(token_string: str) -> bool:
	"""Return True when the string carries the v2 prefix (decided before any decoding)."""
	return isinstance(token_string, str) and token_string.startswith(TOKEN_V2_PREFIX)


def is_public_key_string(value: str | None) -> bool:
	"""Return True when ``value`` is formatted as a v2 public verification key."""
	return isinstance(value, str) and value.strip().startswith(PUBLIC_KEY_PREFIX)


def generate_private_key() -> Ed25519PrivateKey:
	return Ed25519PrivateKey.generate()


def private_key_seed(key: Ed25519PrivateKey) -> bytes:
	return key.private_bytes(
		serialization.Encoding.Raw,
		serialization.PrivateFormat.Raw,
		serialization.NoEncryption(),
	)


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
	if len(seed) != _KEY_LEN:
		raise ValueError("Invalid signing key")
	return Ed25519PrivateKey.from_private_bytes(seed)


def _raw_public(key: Ed25519PublicKey) -> bytes:
	return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encode_public_key(key: Ed25519PublicKey) -> str:
	"""Return the operator-facing ``wbpk2:`` form of a public key (not secret)."""
	return PUBLIC_KEY_PREFIX + b64u_encode(_raw_public(key))


def parse_public_key(value: str) -> Ed25519PublicKey:
	"""Parse a ``wbpk2:`` string; raises ValueError with a constant message."""
	if not is_public_key_string(value):
		raise ValueError("Invalid enrollment verification key")
	try:
		raw = b64u_decode(value.strip()[len(PUBLIC_KEY_PREFIX) :])
		if len(raw) != _KEY_LEN:
			raise ValueError("bad length")
		return Ed25519PublicKey.from_public_bytes(raw)
	except ValueError as exc:
		raise ValueError("Invalid enrollment verification key") from exc


def key_id(key: Ed25519PublicKey) -> str:
	"""Short public-key fingerprint (16 hex chars); an identifier, not a trust anchor."""
	return hashlib.sha256(_raw_public(key)).hexdigest()[:16]


def sign(payload: bytes, key: Ed25519PrivateKey) -> bytes:
	return key.sign(_SIGNING_CONTEXT + payload)


def verify(payload: bytes, signature: bytes, key: Ed25519PublicKey) -> None:
	"""Verify a signature; raises ValueError with a constant message on failure."""
	try:
		key.verify(signature, _SIGNING_CONTEXT + payload)
	except InvalidSignature as exc:
		raise ValueError("Token signature verification failed") from exc


def encode_token_v2(payload: bytes, signature: bytes) -> str:
	return f"{TOKEN_V2_PREFIX}{b64u_encode(payload)}.{b64u_encode(signature)}"


def decode_token_v2(token_string: str) -> tuple[bytes, bytes]:
	"""Split and strictly decode a v2 token into ``(payload_bytes, signature)``."""
	if not is_token_v2(token_string):
		raise ValueError("Not a v2 enrollment token")
	parts = token_string[len(TOKEN_V2_PREFIX) :].split(".")
	if len(parts) != 2 or len(parts[0]) > _MAX_PAYLOAD_B64_LEN:
		raise ValueError("Malformed token")
	payload = b64u_decode(parts[0])
	signature = b64u_decode(parts[1])
	if len(signature) != _SIGNATURE_LEN:
		raise ValueError("Malformed token signature")
	return payload, signature
