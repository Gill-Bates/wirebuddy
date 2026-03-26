#!/usr/bin/env python3
#
# app/utils/node_token.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Enrollment token generation and verification for Master-Node architecture.

Token format: base64url(JSON_PAYLOAD.HMAC_HEX)

The payload contains the master URL, node identity, and a one-time API
secret.  The HMAC-SHA256 signature (keyed with WIREBUDDY_SECRET_KEY)
prevents forgery and guarantees the token was issued by this master.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MAX_TOKEN_AGE = timedelta(hours=24)


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment Token
# ─────────────────────────────────────────────────────────────────────────────


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
	if not secret_key:
		raise ValueError("secret_key must not be empty")

	api_secret = secrets.token_urlsafe(32)
	payload = {
		"master_url": master_url,
		"node_id": node_id,
		"node_name": node_name,
		"api_secret": api_secret,
		"created_at": datetime.now(timezone.utc).isoformat(),
	}
	payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
	signature = hmac.new(
		secret_key.encode("utf-8"),
		payload_json.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()

	raw = payload_json + "." + signature
	token = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
	return token, api_secret


def verify_enrollment_token(
	token_string: str,
	secret_key: str,
	max_age: timedelta | None = MAX_TOKEN_AGE,
) -> dict[str, str]:
	"""Decode and verify an enrollment token.

	Returns the parsed payload dict on success.
	Raises ValueError on any verification failure.
	"""
	if not secret_key:
		raise ValueError("secret_key must not be empty")

	try:
		raw = base64.urlsafe_b64decode(token_string.encode("ascii")).decode("utf-8")
	except Exception as exc:
		raise ValueError("Invalid token encoding") from exc

	if "." not in raw:
		raise ValueError("Malformed token: missing signature separator")

	payload_json, signature = raw.rsplit(".", 1)

	expected = hmac.new(
		secret_key.encode("utf-8"),
		payload_json.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()

	if not hmac.compare_digest(expected, signature):
		raise ValueError("Token signature verification failed")

	try:
		payload = json.loads(payload_json)
	except json.JSONDecodeError as exc:
		raise ValueError("Token payload is not valid JSON") from exc

	for field in ("master_url", "node_id", "node_name", "api_secret", "created_at"):
		if field not in payload:
			raise ValueError(f"Token missing required field: {field}")

	created_at_raw = payload["created_at"]
	if not isinstance(created_at_raw, str):
		raise ValueError("Token field 'created_at' must be a string")

	try:
		created_at = datetime.fromisoformat(created_at_raw)
	except ValueError as exc:
		raise ValueError("Token field 'created_at' is not a valid ISO timestamp") from exc

	if created_at.tzinfo is None:
		raise ValueError("Token field 'created_at' must include a timezone offset")

	if max_age is not None and datetime.now(timezone.utc) - created_at > max_age:
		raise ValueError("Token has expired")

	return payload


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
	key = ec.generate_private_key(ec.SECP256R1())

	subject = issuer = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, f"wirebuddy-node-{node_id[:8]}"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WireBuddy"),
	])

	now = datetime.now(timezone.utc)
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now)
		.not_valid_after(now + timedelta(days=3650))
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
	cert = x509.load_pem_x509_certificate(cert_pem)
	return cert.fingerprint(hashes.SHA256()).hex()
