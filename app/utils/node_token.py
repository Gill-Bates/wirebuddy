#!/usr/bin/env python3
#
# app/utils/node_token.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Enrollment token generation and verification for Master-Node architecture.

Two wire formats exist; the format is decided by the literal prefix:

- v2 (default): ``wb2.<b64url payload>.<b64url Ed25519 signature>``. Signed with
  a private key that exists only on the master; nodes verify with the pinned
  public key and cannot forge tokens.
- v1 (legacy, deprecated): base64url(JSON_PAYLOAD.HMAC_HEX), HMAC-SHA256 keyed
  with a key derived from WIREBUDDY_SECRET_KEY, which nodes must hold to verify.

The payload contains the master URL, node identity, and a one-time API secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import enrollment_signing
from .key_domains import derive_enrollment_hmac_key

MAX_TOKEN_AGE = timedelta(hours=24)
_CLOCK_SKEW = timedelta(minutes=5)
_MAX_TOKEN_SIZE = 16_384
_MAX_DECODED_TOKEN_SIZE = 65_536
_MAX_CERT_PEM_SIZE = 65_536
_MIN_SECRET_KEY_BYTES = 32
_MAX_NODE_ID_LENGTH = 64
_MAX_NODE_NAME_LENGTH = 128
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_API_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

_REQUIRED_PAYLOAD_FIELDS = frozenset({"master_url", "node_id", "node_name", "api_secret", "created_at"})
_V2_PAYLOAD_FIELDS = _REQUIRED_PAYLOAD_FIELDS | {"v", "kid"}
_REQUIRED_PAYLOAD_FIELD_TYPES = {
	"master_url": str,
	"node_id": str,
	"node_name": str,
	"api_secret": str,
	"created_at": str,
}


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment Token
# ─────────────────────────────────────────────────────────────────────────────


def _require_secret_key(secret_key: str) -> None:
	"""Ensure the shared secret key has sufficient length."""
	if not isinstance(secret_key, str) or not secret_key:
		raise ValueError("secret_key must not be empty")
	if len(secret_key.encode("utf-8")) < _MIN_SECRET_KEY_BYTES:
		raise ValueError(f"secret_key must be at least {_MIN_SECRET_KEY_BYTES} bytes")


def _normalize_master_url(master_url: str) -> str:
	"""Normalize master_url consistently before signing."""
	if not isinstance(master_url, str):
		raise ValueError("master_url must be a string")
	normalized = master_url.strip().rstrip("/")
	if not normalized:
		raise ValueError("master_url must not be empty")
	parsed = urlsplit(normalized)
	if parsed.scheme != "https":
		raise ValueError("master_url must use https")
	if not parsed.hostname:
		raise ValueError("master_url must include hostname")
	if parsed.username or parsed.password:
		raise ValueError("master_url must not contain credentials")
	if parsed.query or parsed.fragment:
		raise ValueError("master_url must not contain query or fragment")

	host = parsed.hostname.rstrip(".").lower()
	try:
		addr = ipaddress.ip_address(host)
	except ValueError:
		pass
	else:
		# urlsplit() strips the required brackets from an IPv6 literal; restore
		# them so the reassembled authority stays a valid IPv6 URL.
		if addr.version == 6:
			host = f"[{addr.compressed}]"
	netloc = host if parsed.port is None else f"{host}:{parsed.port}"
	return urlunsplit(("https", netloc, parsed.path.rstrip("/"), "", ""))


def _validate_node_id(node_id: str) -> str:
	"""Validate node identifiers used in tokens and certificate labels."""
	if not isinstance(node_id, str):
		raise ValueError("node_id must be a string")
	normalized = node_id.strip()
	if not normalized:
		raise ValueError("node_id must not be empty")
	if len(normalized) > _MAX_NODE_ID_LENGTH:
		raise ValueError("node_id too long")
	if _NODE_ID_RE.fullmatch(normalized) is None:
		raise ValueError("node_id contains unsupported characters")
	return normalized


def _validate_node_name(node_name: str) -> str:
	"""Validate human-readable node names for token payloads."""
	if not isinstance(node_name, str):
		raise ValueError("node_name must be a string")
	normalized = node_name.strip()
	if not normalized:
		raise ValueError("node_name must not be empty")
	if len(normalized) > _MAX_NODE_NAME_LENGTH:
		raise ValueError("node_name too long")
	if any(ch in normalized for ch in ("\n", "\r", "\x00")):
		raise ValueError("node_name contains unsafe control characters")
	return normalized


def _serialize_payload(payload: dict[str, str]) -> str:
	"""Return the canonical JSON representation for token payloads."""
	return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _sign_payload(payload_json: str, secret_key: str) -> str:
	"""Return the HMAC-SHA256 hex signature for a serialized payload."""
	return hmac.new(
		derive_enrollment_hmac_key(secret_key),
		payload_json.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()


def _encode_token(payload_json: str, signature: str) -> str:
	"""Encode payload JSON and signature into the wire token format."""
	raw = payload_json + "." + signature
	return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_token(token_string: str) -> tuple[str, str]:
	"""Decode a wire token into payload JSON and signature parts."""
	if len(token_string) > _MAX_TOKEN_SIZE:
		raise ValueError("Token too large")
	try:
		decoded = base64.urlsafe_b64decode(token_string.encode("ascii"))
	except Exception as exc:
		raise ValueError("Invalid token encoding") from exc
	if len(decoded) > _MAX_DECODED_TOKEN_SIZE:
		raise ValueError("Decoded token payload too large")
	try:
		raw = decoded.decode("utf-8")
	except UnicodeDecodeError as exc:
		raise ValueError("Invalid token encoding") from exc

	if "." not in raw:
		raise ValueError("Malformed token: missing signature separator")

	payload_json, signature = raw.rsplit(".", 1)
	if len(signature) != 64:
		raise ValueError("Malformed token signature")
	return payload_json, signature


def _parse_created_at(created_at_raw: str) -> datetime:
	"""Parse and validate the created_at field from a token payload."""
	if not isinstance(created_at_raw, str):
		raise ValueError("Token field 'created_at' must be a string")

	try:
		created_at = datetime.fromisoformat(created_at_raw)
	except ValueError as exc:
		raise ValueError("Token field 'created_at' is not a valid ISO timestamp") from exc

	if created_at.tzinfo is None:
		raise ValueError("Token field 'created_at' must include a timezone offset")

	return created_at


def generate_enrollment_token(
	master_url: str,
	node_id: str,
	node_name: str,
	secret_key: str,
) -> tuple[str, str]:
	"""Generate a signed enrollment token.

	Returns:
		(token_string, api_secret)
		The caller must hash api_secret before DB storage.
		The returned token embeds api_secret and must therefore be handled as
		a one-time credential, not as a non-sensitive identifier.
	"""
	_require_secret_key(secret_key)
	master_url = _normalize_master_url(master_url)
	node_id = _validate_node_id(node_id)
	node_name = _validate_node_name(node_name)

	api_secret = secrets.token_urlsafe(32)
	payload = {
		"master_url": master_url,
		"node_id": node_id,
		"node_name": node_name,
		"api_secret": api_secret,
		"created_at": datetime.now(UTC).isoformat(),
	}
	payload_json = _serialize_payload(payload)
	signature = _sign_payload(payload_json, secret_key)
	return _encode_token(payload_json, signature), api_secret


def _validate_payload(payload: object, max_age: timedelta | None) -> dict:
	"""Validate field types, normalize values and enforce the token lifetime."""
	if not isinstance(payload, dict):
		raise ValueError("Token payload must be a JSON object")

	for field in _REQUIRED_PAYLOAD_FIELDS:
		if field not in payload:
			raise ValueError(f"Token missing required field: {field}")
	for field, expected_type in _REQUIRED_PAYLOAD_FIELD_TYPES.items():
		value = payload.get(field)
		if not isinstance(value, expected_type):
			raise ValueError(f"Invalid token field type: {field}")

	payload["master_url"] = _normalize_master_url(payload["master_url"])
	payload["node_id"] = _validate_node_id(payload["node_id"])
	payload["node_name"] = _validate_node_name(payload["node_name"])
	if _API_SECRET_RE.fullmatch(payload["api_secret"].strip()) is None:
		raise ValueError("Token field 'api_secret' has invalid format")

	created_at = _parse_created_at(payload["created_at"])
	now = datetime.now(UTC)
	if created_at > now + _CLOCK_SKEW:
		raise ValueError("Token created_at is in the future")

	if max_age is not None and now - created_at > max_age:
		raise ValueError("Token has expired")

	return payload


def token_version(token_string: str) -> int:
	"""Return the protocol version of a token from its prefix (2 for ``wb2.``, else 1)."""
	return 2 if enrollment_signing.is_token_v2(token_string) else 1


def verify_enrollment_token(
	token_string: str,
	secret_key: str,
	max_age: timedelta | None = MAX_TOKEN_AGE,
) -> dict[str, str]:
	"""Decode and verify a legacy (v1, HMAC) enrollment token.

	Returns the parsed payload dict on success.
	Raises ValueError on any verification failure, including a v2 token.
	"""
	_require_secret_key(secret_key)
	if enrollment_signing.is_token_v2(token_string):
		raise ValueError("Token is not a legacy v1 token")
	payload_json, signature = _decode_token(token_string)
	expected = _sign_payload(payload_json, secret_key)

	if not hmac.compare_digest(expected, signature):
		raise ValueError("Token signature verification failed")

	try:
		payload = json.loads(payload_json)
	except json.JSONDecodeError as exc:
		raise ValueError("Token payload is not valid JSON") from exc
	return _validate_payload(payload, max_age)


def generate_enrollment_token_v2(
	master_url: str,
	node_id: str,
	node_name: str,
	signing_key: Ed25519PrivateKey,
) -> tuple[str, str]:
	"""Generate a v2 enrollment token signed with the master's Ed25519 key.

	Returns:
		(token_string, api_secret); same one-time-credential rules as v1.
	"""
	master_url = _normalize_master_url(master_url)
	node_id = _validate_node_id(node_id)
	node_name = _validate_node_name(node_name)

	api_secret = secrets.token_urlsafe(32)
	payload = {
		"v": 2,
		"kid": enrollment_signing.key_id(signing_key.public_key()),
		"master_url": master_url,
		"node_id": node_id,
		"node_name": node_name,
		"api_secret": api_secret,
		"created_at": datetime.now(UTC).isoformat(),
	}
	payload_bytes = _serialize_payload(payload).encode("utf-8")
	signature = enrollment_signing.sign(payload_bytes, signing_key)
	return enrollment_signing.encode_token_v2(payload_bytes, signature), api_secret


def verify_enrollment_token_v2(
	token_string: str,
	public_key: Ed25519PublicKey,
	max_age: timedelta | None = MAX_TOKEN_AGE,
) -> dict[str, str]:
	"""Verify a v2 token against a pinned public key.

	Raises ValueError on any failure: bad encoding, signature, key id, schema
	(unknown or missing fields, version mismatch), content or lifetime.
	"""
	if len(token_string) > _MAX_TOKEN_SIZE:
		raise ValueError("Token too large")
	payload_bytes, signature = enrollment_signing.decode_token_v2(token_string)
	enrollment_signing.verify(payload_bytes, signature, public_key)

	try:
		payload = json.loads(payload_bytes.decode("utf-8"))
	except (UnicodeDecodeError, json.JSONDecodeError) as exc:
		raise ValueError("Token payload is not valid JSON") from exc
	if not isinstance(payload, dict):
		raise ValueError("Token payload must be a JSON object")
	if set(payload) != _V2_PAYLOAD_FIELDS:
		raise ValueError("Token payload has unexpected fields")
	if payload["v"] != 2 or isinstance(payload["v"], bool):
		raise ValueError("Unsupported token version")
	if payload["kid"] != enrollment_signing.key_id(public_key):
		raise ValueError("Token was signed by a different master key")
	return _validate_payload(payload, max_age)


# ─────────────────────────────────────────────────────────────────────────────
# Self-Signed Certificate (for Node identity)
# ─────────────────────────────────────────────────────────────────────────────


def generate_node_cert(node_id: str) -> tuple[bytes, bytes]:
	"""Generate a self-signed EC P-256 certificate for node identity.

	The returned private key is unencrypted PKCS#8 PEM. Callers that persist it
	must protect it with restrictive filesystem permissions or external
	secret-wrapping.

	Returns:
		(cert_pem, key_pem) as bytes
	"""
	node_id = _validate_node_id(node_id)
	key = ec.generate_private_key(ec.SECP256R1())
	node_label = f"wirebuddy-node-{node_id[:8]}"

	subject = issuer = x509.Name(
		[
			x509.NameAttribute(NameOID.COMMON_NAME, node_label),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WireBuddy"),
		]
	)

	now = datetime.now(UTC)
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now)
		.not_valid_after(now + timedelta(days=365))
		.add_extension(
			x509.SubjectAlternativeName([x509.DNSName(node_label)]),
			critical=False,
		)
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.add_extension(
			x509.KeyUsage(
				digital_signature=True,
				content_commitment=False,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=False,
				crl_sign=False,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		)
		.add_extension(
			x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
			critical=False,
		)
		.sign(key, hashes.SHA256())
	)

	cert_pem = cert.public_bytes(serialization.Encoding.PEM)
	key_pem = key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.PKCS8,
		serialization.NoEncryption(),
	)
	return cert_pem, key_pem


def get_cert_fingerprint(cert_pem: bytes) -> str:
	"""Return the SHA-256 fingerprint of a PEM-encoded certificate."""
	if len(cert_pem) > _MAX_CERT_PEM_SIZE:
		raise ValueError("Certificate PEM too large")
	cert = x509.load_pem_x509_certificate(cert_pem)
	return cert.fingerprint(hashes.SHA256()).hex()
