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
import logging
import secrets
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_log = logging.getLogger(__name__)


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
	"""
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
) -> dict:
	"""Decode and verify an enrollment token.

	Returns the parsed payload dict on success.
	Raises ValueError on any verification failure.
	"""
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

	for field in ("master_url", "node_id", "node_name", "api_secret"):
		if field not in payload:
			raise ValueError(f"Token missing required field: {field}")

	return payload


# ─────────────────────────────────────────────────────────────────────────────
# Self-Signed Certificate (for Node identity)
# ─────────────────────────────────────────────────────────────────────────────


def generate_node_cert(node_id: str) -> tuple[bytes, bytes]:
	"""Generate a self-signed EC P-256 certificate for node identity.

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
		.not_valid_after(now.replace(year=now.year + 10))
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
