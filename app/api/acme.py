#!/usr/bin/env python3
#
# app/api/acme.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Lightweight ACME client for Let's Encrypt certificates."""

from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from email.utils import parsedate_to_datetime
from datetime import UTC, datetime, timedelta
from pathlib import Path as PathLib

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, EmailStr, Field

from ..api.auth import get_current_user, require_admin
from ..utils.rate_limit import RATE_LIMIT_HEAVY, limiter
from ..utils.config import Config, get_config
from .response import OkResponse

_log = logging.getLogger(__name__)

router = APIRouter(tags=["acme"])

# Let's Encrypt ACME endpoints
ACME_DIRECTORY_PROD = "https://acme-v02.api.letsencrypt.org/directory"
ACME_DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Domain name validation pattern (RFC 1123 hostname)
# Used by CertificateRequest model and delete_certificate path parameter
_DOMAIN_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"

# Challenge TTL in seconds (10 minutes)
CHALLENGE_TTL = 600

# Domain lock file descriptor storage (prevents GC from closing locked files)
# SECURITY: Without this, Python's GC can close the file object and release
#           the fcntl lock prematurely, breaking domain locking guarantees
_domain_lock_fds: dict[int, tuple[object, PathLib]] = {}  # fd_num -> (file object, lock path)
_domain_lock_fds_lock = threading.Lock()

# Domain lock file helpers (worker-safe)
def _acquire_domain_lock(certs_dir: PathLib, domain: str) -> int | None:
	"""Acquire exclusive lock for domain order. Returns file descriptor or None.
	
	CRITICAL: Must keep file object alive to prevent GC from closing it and
	releasing the lock. File object is stored in _domain_lock_fds dict.
	"""
	lock_dir = certs_dir / ".locks"
	lock_dir.mkdir(parents=True, exist_ok=True)
	lock_file = lock_dir / f"{domain}.lock"
	fd_obj = None
	
	try:
		fd_obj = open(lock_file, "w")
		fcntl.flock(fd_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
		fd_obj.write(str(time.time()))
		fd_obj.flush()
		
		# Store file object to prevent GC from closing it
		fd_num = fd_obj.fileno()
		with _domain_lock_fds_lock:
			_domain_lock_fds[fd_num] = (fd_obj, lock_file)
		return fd_num
	except (IOError, OSError):
		if fd_obj is not None:
			fd_obj.close()
		return None

def _release_domain_lock(fd: int) -> None:
	"""Release domain lock by file descriptor."""
	# Retrieve and remove file object from storage
	with _domain_lock_fds_lock:
		lock_entry = _domain_lock_fds.pop(fd, None)
	if lock_entry is None:
		return
	fd_obj, lock_file = lock_entry
	
	try:
		fcntl.flock(fd_obj.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
		fd_obj.close()  # type: ignore
	except Exception:
		pass
	try:
		lock_file.unlink(missing_ok=True)
	except OSError:
		pass


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class CertificateRequest(BaseModel):
	"""Request to issue a new certificate."""
	domain: str = Field(..., min_length=1, max_length=253, pattern=_DOMAIN_PATTERN)
	email: EmailStr
	staging: bool = Field(default=False, description="Use staging environment for testing")


class CertificateInfo(BaseModel):
	"""Certificate information."""
	domain: str
	issued_at: str | None = None
	expires_at: str | None = None
	issuer: str | None = None
	serial: str | None = None
	exists: bool = False
	is_staging: bool = False
	days_until_expiry: int | None = None
	needs_renewal: bool = False


class ChallengeStatus(BaseModel):
	"""ACME challenge status for HTTP-01."""
	token: str
	key_authorization: str
	status: str


class CertificateIssueData(BaseModel):
	"""Successful certificate issuance payload."""
	domain: str
	staging: bool
	cert_path: str
	key_path: str


class CertificateDeleteData(BaseModel):
	"""Certificate deletion payload."""
	success: bool
	domain: str
	staging: bool


class RenewalCandidate(BaseModel):
	"""Single certificate renewal candidate."""
	domain: str
	expires_at: str | None = None
	days_until_expiry: int | None = None


class RenewalCheckData(BaseModel):
	"""Certificate renewal summary payload."""
	total_certificates: int
	needs_renewal_count: int
	needs_renewal: list[RenewalCandidate]


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_certs_dir(config: Config) -> PathLib:
	"""Public wrapper for certificate directory resolution."""
	certs_dir = config.data_dir / "certs"
	certs_dir.mkdir(parents=True, exist_ok=True)
	return certs_dir


def _b64url(data: bytes) -> str:
	"""Base64url encode without padding."""
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(data: bytes) -> bytes:
	"""SHA256 hash."""
	return hashlib.sha256(data).digest()


def _parse_acme_error(resp: httpx.Response) -> str:
	"""Parse ACME error response to extract detailed message."""
	try:
		error = resp.json()
		detail = error.get("detail", "")
		error_type = error.get("type", "")
		if detail:
			return f"{detail} ({error_type})" if error_type else detail
		return resp.text
	except Exception:
		return resp.text


def _parse_retry_after(resp: httpx.Response, fallback_delay: float) -> float:
	"""Parse Retry-After header as seconds, falling back to the provided delay."""
	raw_value = resp.headers.get("Retry-After")
	if not raw_value:
		return fallback_delay

	raw_value = raw_value.strip()
	try:
		return max(0.0, float(raw_value))
	except ValueError:
		pass

	try:
		retry_at = parsedate_to_datetime(raw_value)
		if retry_at.tzinfo is None:
			retry_at = retry_at.replace(tzinfo=UTC)
		return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
	except Exception:
		return fallback_delay


def _jwk_thumbprint(jwk: dict) -> str:
	"""Calculate JWK thumbprint (RFC 7638)."""
	# Canonical JSON: keys in sorted order, no whitespace
	if "kty" not in jwk:
		raise ValueError("Missing kty in JWK")
	
	if jwk["kty"] == "EC":
		canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
	elif jwk["kty"] == "RSA":
		canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
	else:
		raise ValueError(f"Unsupported key type: {jwk['kty']}")
	
	canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
	return _b64url(_sha256(canonical_json.encode("utf-8")))


def _atomic_write_bytes(path: PathLib, data: bytes, mode: int) -> None:
	"""Write bytes atomically and apply mode."""
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp_name = tempfile.mkstemp(
		prefix=f".{path.name}.",
		suffix=".tmp",
		dir=str(path.parent),
	)
	try:
		with os.fdopen(fd, "wb") as tmp:
			tmp.write(data)
			tmp.flush()
			os.fsync(tmp.fileno())
		os.chmod(tmp_name, mode)
		os.replace(tmp_name, path)
		path.chmod(mode)
	finally:
		try:
			if os.path.exists(tmp_name):
				os.unlink(tmp_name)
		except OSError:
			pass



def _atomic_write_text(path: PathLib, data: str, mode: int) -> None:
	"""Write text atomically and apply mode."""
	_atomic_write_bytes(path, data.encode("utf-8"), mode)


class ACMEClient:
	"""Lightweight ACME v2 client."""
	
	def __init__(self, directory_url: str, certs_dir: PathLib):
		self.directory_url = directory_url
		self.certs_dir = certs_dir
		self.directory: dict = {}
		self.nonce: str | None = None
		self.account_key: ec.EllipticCurvePrivateKey | None = None
		self.account_url: str | None = None
		self.http_client: httpx.AsyncClient | None = None
		self._cached_thumbprint: str | None = None
		
		# Paths
		self.account_key_path = certs_dir / "account_key.pem"
		self.account_url_path = certs_dir / "account_url.txt"
		self.account_thumbprint_path = certs_dir / "account_thumbprint.txt"
	
	async def __aenter__(self):
		limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
		self.http_client = httpx.AsyncClient(timeout=30.0, limits=limits)
		return self
	
	async def __aexit__(self, *args):
		if self.http_client:
			await self.http_client.aclose()
	
	async def _fetch_directory(self) -> None:
		"""Fetch ACME directory."""
		if not self.http_client:
			raise RuntimeError("HTTP client not initialized")
		
		resp = await self.http_client.get(self.directory_url)
		resp.raise_for_status()
		self.directory = resp.json()
	
	async def _get_nonce(self) -> str:
		"""Get a fresh nonce with fallback."""
		if not self.http_client:
			raise RuntimeError("HTTP client not initialized")
		
		if self.nonce:
			nonce = self.nonce
			self.nonce = None
			return nonce
		
		try:
			resp = await self.http_client.head(self.directory["newNonce"])
			if "Replay-Nonce" in resp.headers:
				return resp.headers["Replay-Nonce"]
		except Exception:
			pass
		
		# Fallback: GET request to newNonce
		resp = await self.http_client.get(self.directory["newNonce"])
		if "Replay-Nonce" not in resp.headers:
			raise HTTPException(status_code=500, detail="Failed to obtain ACME nonce")
		return resp.headers["Replay-Nonce"]
	
	def _load_or_create_account_key(self) -> ec.EllipticCurvePrivateKey:
		"""Load existing account key or create a new one."""
		if self.account_key_path.exists():
			key_pem = self.account_key_path.read_bytes()
			key = serialization.load_pem_private_key(key_pem, password=None)
			if isinstance(key, ec.EllipticCurvePrivateKey):
				return key
			raise ValueError("Account key is not an EC key")
		
		# Generate new P-256 key
		key = ec.generate_private_key(ec.SECP256R1())
		key_pem = key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption(),
		)
		_atomic_write_bytes(self.account_key_path, key_pem, 0o600)
		_log.info("Created new ACME account key")
		return key

	def _load_existing_account_url(self, current_thumbprint: str) -> str | None:
		"""Load persisted account URL when it still matches the current key."""
		if not self.account_url_path.exists():
			return None
		if self.account_thumbprint_path.exists():
			stored_thumbprint = self.account_thumbprint_path.read_text().strip()
			if stored_thumbprint != current_thumbprint:
				_log.warning(
					"Account key changed (thumbprint mismatch). "
					"Removing stale account URL to re-register."
				)
				self.account_url_path.unlink(missing_ok=True)
				self.account_thumbprint_path.unlink(missing_ok=True)
				return None
			return self.account_url_path.read_text().strip()
		_log.warning("ACME account metadata incomplete, re-registering account")
		self.account_url_path.unlink(missing_ok=True)
		return None

	def _save_account_metadata(self, account_url: str, current_thumbprint: str) -> None:
		"""Persist account URL and thumbprint."""
		_atomic_write_text(self.account_url_path, account_url, 0o600)
		_atomic_write_text(self.account_thumbprint_path, current_thumbprint, 0o600)
	
	def _get_jwk(self) -> dict:
		"""Get JWK representation of account key."""
		if not self.account_key:
			raise RuntimeError("Account key not loaded")
		
		pub = self.account_key.public_key()
		numbers = pub.public_numbers()
		
		# P-256 coordinates are 32 bytes each
		x_bytes = numbers.x.to_bytes(32, "big")
		y_bytes = numbers.y.to_bytes(32, "big")
		
		return {
			"kty": "EC",
			"crv": "P-256",
			"x": _b64url(x_bytes),
			"y": _b64url(y_bytes),
		}
	
	def _get_jwk_thumbprint(self) -> str:
		"""Return JWK thumbprint, computing and caching it on first call."""
		if self._cached_thumbprint is None:
			self._cached_thumbprint = _jwk_thumbprint(self._get_jwk())
		return self._cached_thumbprint

	def _sign_payload(self, payload: bytes) -> bytes:
		"""Sign payload with account key (ES256)."""
		if not self.account_key:
			raise RuntimeError("Account key not loaded")
		
		from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
		
		sig_der = self.account_key.sign(payload, ec.ECDSA(hashes.SHA256()))
		r, s = decode_dss_signature(sig_der)
		
		# ES256 signature is r || s, each 32 bytes
		return r.to_bytes(32, "big") + s.to_bytes(32, "big")
	
	async def _signed_request(self, url: str, payload: dict | None) -> httpx.Response:
		"""Make a signed JWS request to ACME server."""
		if not self.http_client:
			raise RuntimeError("HTTP client not initialized")
		
		nonce = await self._get_nonce()
		
		# Build protected header
		protected = {
			"alg": "ES256",
			"nonce": nonce,
			"url": url,
		}
		
		if self.account_url:
			protected["kid"] = self.account_url
		else:
			protected["jwk"] = self._get_jwk()
		
		protected_b64 = _b64url(json.dumps(protected).encode("utf-8"))
		
		if payload is None:
			payload_b64 = ""
		else:
			payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))
		
		# Sign
		signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
		signature = self._sign_payload(signing_input)
		signature_b64 = _b64url(signature)
		
		# JWS compact serialization for POST
		body = {
			"protected": protected_b64,
			"payload": payload_b64,
			"signature": signature_b64,
		}
		
		resp = await self.http_client.post(
			url,
			json=body,
			headers={"Content-Type": "application/jose+json"},
		)
		
		# Store replay nonce for next request
		if "Replay-Nonce" in resp.headers:
			self.nonce = resp.headers["Replay-Nonce"]
		
		return resp
	
	async def register_or_fetch_account(self, email: str) -> str:
		"""Register new account or fetch existing one."""
		await self._fetch_directory()
		self.account_key = await asyncio.to_thread(self._load_or_create_account_key)
		
		# Calculate current key thumbprint
		current_thumbprint = self._get_jwk_thumbprint()
		
		# Check for existing account URL
		self.account_url = await asyncio.to_thread(self._load_existing_account_url, current_thumbprint)
		if self.account_url:
			_log.info("Using existing ACME account: %s", self.account_url)
			return self.account_url
		
		# Register new account
		payload = {
			"termsOfServiceAgreed": True,
			"contact": [f"mailto:{email}"],
		}
		
		resp = await self._signed_request(self.directory["newAccount"], payload)
		
		if resp.status_code not in (200, 201):
			raise HTTPException(status_code=500, detail=f"Failed to register account: {_parse_acme_error(resp)}")
		
		self.account_url = resp.headers.get("Location")
		if not self.account_url:
			raise HTTPException(status_code=500, detail="No account URL in response")
		
		# Save account URL and thumbprint
		await asyncio.to_thread(self._save_account_metadata, self.account_url, current_thumbprint)
		_log.info("Registered new ACME account: %s", self.account_url)
		
		return self.account_url
	
	async def order_certificate(self, domain: str) -> tuple[str, dict]:
		"""Create a new certificate order."""
		payload = {
			"identifiers": [{"type": "dns", "value": domain}],
		}
		
		resp = await self._signed_request(self.directory["newOrder"], payload)
		
		if resp.status_code not in (200, 201):
			raise HTTPException(status_code=500, detail=f"Failed to create order: {_parse_acme_error(resp)}")
		
		order_url = resp.headers.get("Location")
		order = resp.json()
		
		return order_url, order
	
	async def get_authorization(self, auth_url: str) -> dict:
		"""Get authorization details including challenges."""
		resp = await self._signed_request(auth_url, None)
		
		if resp.status_code != 200:
			raise HTTPException(status_code=500, detail=f"Failed to get authorization: {_parse_acme_error(resp)}")
		
		return resp.json()
	
	def get_http01_challenge(self, authorization: dict) -> tuple[str, str]:
		"""Extract HTTP-01 challenge token and key authorization."""
		for challenge in authorization.get("challenges", []):
			if challenge["type"] == "http-01":
				token = challenge["token"]
				key_auth = f"{token}.{self._get_jwk_thumbprint()}"
				return token, key_auth
		
		raise HTTPException(status_code=400, detail="No HTTP-01 challenge found")
	
	async def respond_to_challenge(self, challenge_url: str) -> dict:
		"""Respond to a challenge (tell ACME server we're ready)."""
		resp = await self._signed_request(challenge_url, {})
		
		if resp.status_code not in (200, 202):
			raise HTTPException(status_code=500, detail=f"Failed to respond to challenge: {_parse_acme_error(resp)}")
		
		return resp.json()

	async def poll_authorization(self, auth_url: str, max_attempts: int = 15, delay: float = 4.0) -> dict:
		"""Poll authorization status until the challenge is validated or fails."""
		for _ in range(max_attempts):
			resp = await self._signed_request(auth_url, None)

			if resp.status_code != 200:
				raise HTTPException(status_code=500, detail=f"Failed to poll authorization: {_parse_acme_error(resp)}")

			authorization = resp.json()
			status = authorization.get("status")

			if status == "valid":
				return authorization
			if status in ("invalid", "expired", "revoked", "deactivated"):
				raise HTTPException(status_code=400, detail=f"Authorization failed: {status}")

			await asyncio.sleep(_parse_retry_after(resp, delay))

		raise HTTPException(status_code=408, detail="Timeout waiting for authorization to become valid")
	
	async def poll_order(self, order_url: str, max_attempts: int = 15, delay: float = 4.0) -> dict:
		"""Poll order status until ready or failed."""
		for _ in range(max_attempts):
			resp = await self._signed_request(order_url, None)
			
			if resp.status_code != 200:
				raise HTTPException(status_code=500, detail=f"Failed to poll order: {_parse_acme_error(resp)}")
			
			order = resp.json()
			status = order.get("status")
			
			if status == "ready":
				return order
			elif status == "valid":
				return order
			elif status in ("invalid", "expired", "revoked"):
				raise HTTPException(status_code=400, detail=f"Order failed: {status}")
			
			await asyncio.sleep(_parse_retry_after(resp, delay))
		
		raise HTTPException(status_code=408, detail="Timeout waiting for order to be ready")
	
	def _generate_domain_key_and_csr(self, domain: str) -> tuple[bytes, bytes]:
		"""Generate RSA domain key and CSR (CPU-intensive, run in threadpool)."""
		domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		csr = (
			x509.CertificateSigningRequestBuilder()
			.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
			.add_extension(
				x509.SubjectAlternativeName([x509.DNSName(domain)]),
				critical=False,
			)
			.sign(domain_key, hashes.SHA256())
		)
		csr_der = csr.public_bytes(serialization.Encoding.DER)
		key_pem = domain_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption(),
		)
		return csr_der, key_pem

	async def finalize_order(self, finalize_url: str, order_url: str, domain: str) -> tuple[bytes, bytes]:
		"""Finalize order with CSR and get certificate."""
		# Generate domain key + CSR in a threadpool (RSA keygen is CPU-intensive)
		csr_der, key_pem = await asyncio.to_thread(self._generate_domain_key_and_csr, domain)
		
		payload = {"csr": _b64url(csr_der)}
		resp = await self._signed_request(finalize_url, payload)
		
		if resp.status_code not in (200, 201):
			raise HTTPException(status_code=500, detail=_parse_acme_error(resp))
		
		order = resp.json()
		
		# Wait for certificate
		if order.get("status") != "valid":
			order = await self.poll_order(order_url)
		
		# Download certificate
		cert_url = order.get("certificate")
		if not cert_url:
			raise HTTPException(status_code=500, detail="No certificate URL in order")
		
		cert_resp = await self._signed_request(cert_url, None)
		
		if cert_resp.status_code != 200:
			raise HTTPException(status_code=500, detail=f"Failed to download certificate: {_parse_acme_error(cert_resp)}")
		
		cert_pem = cert_resp.text.encode("utf-8")
		
		return cert_pem, key_pem
	
	def save_certificate(self, domain: str, cert_pem: bytes, key_pem: bytes, is_staging: bool = False) -> PathLib:
		"""Save certificate, chain, and key to disk."""
		# Create domain directory
		domain_dir = self.certs_dir / domain
		domain_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
		
		suffix = "_staging" if is_staging else ""
		
		# Parse certificates from PEM bundle
		certs = []
		pem_data = cert_pem
		while b"-----BEGIN CERTIFICATE-----" in pem_data:
			start = pem_data.find(b"-----BEGIN CERTIFICATE-----")
			end = pem_data.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
			cert_block = pem_data[start:end]
			certs.append(cert_block)
			pem_data = pem_data[end:]
		
		# Save files
		fullchain_path = domain_dir / f"fullchain{suffix}.pem"
		key_path = domain_dir / f"privkey{suffix}.pem"
		
		# Always save fullchain (all certs)
		_atomic_write_bytes(fullchain_path, cert_pem, 0o644)
		_atomic_write_bytes(key_path, key_pem, 0o600)
		
		# Split cert.pem (leaf) and chain.pem (intermediates)
		if len(certs) >= 1:
			cert_path = domain_dir / f"cert{suffix}.pem"
			_atomic_write_bytes(cert_path, certs[0] + b"\n", 0o644)
		
		if len(certs) >= 2:
			chain_path = domain_dir / f"chain{suffix}.pem"
			_atomic_write_bytes(chain_path, b"\n".join(certs[1:]) + b"\n", 0o644)
		
		_log.info("Saved certificate for %s to %s", domain, domain_dir)
		
		return domain_dir


# ---------------------------------------------------------------------------
# Challenge response storage (file-based with TTL)
# ---------------------------------------------------------------------------

def _get_challenge_file(certs_dir: PathLib) -> PathLib:
	"""Get path to challenge storage file."""
	return certs_dir / ".challenges.json"


def _get_challenge_lock_file(certs_dir: PathLib) -> PathLib:
	"""Get path to challenge storage lock file."""
	return certs_dir / ".challenges.lock"


def _read_valid_challenges(challenge_file: PathLib) -> dict[str, dict]:
	"""Read challenge file contents and drop expired entries."""
	if not challenge_file.exists():
		return {}
	try:
		content = challenge_file.read_text()
		data = json.loads(content) if content else {}
	except (OSError, json.JSONDecodeError):
		return {}
	now = time.time()
	valid: dict[str, dict] = {}
	for token, entry in data.items():
		if isinstance(entry, dict) and entry.get("expires", 0) > now:
			valid[token] = entry
	return valid


def _load_challenges(certs_dir: PathLib) -> dict[str, dict]:
	"""Load challenges from file, cleaning expired entries."""
	challenge_file = _get_challenge_file(certs_dir)
	lock_file = _get_challenge_lock_file(certs_dir)
	
	if not challenge_file.exists():
		return {}
	
	try:
		lock_file.touch(exist_ok=True)
		with open(lock_file, "r") as lock_handle:
			fcntl.flock(lock_handle.fileno(), fcntl.LOCK_SH)
			return _read_valid_challenges(challenge_file)
	except Exception as exc:
		_log.warning("Failed to load challenges from %s: %s", challenge_file, exc)
		return {}


def _save_challenge(certs_dir: PathLib, token: str, key_auth: str) -> None:
	"""Save challenge to file with TTL (thread-safe with file lock)."""
	challenge_file = _get_challenge_file(certs_dir)
	lock_file = _get_challenge_lock_file(certs_dir)
	lock_file.touch(exist_ok=True)
	with open(lock_file, "r+") as lock_handle:
		fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
		valid = _read_valid_challenges(challenge_file)
		valid[token] = {
			"key_auth": key_auth,
			"expires": time.time() + CHALLENGE_TTL,
		}
		_atomic_write_bytes(challenge_file, json.dumps(valid).encode("utf-8"), 0o600)


def _remove_challenge(certs_dir: PathLib, token: str) -> None:
	"""Remove challenge from file (thread-safe with file lock)."""
	challenge_file = _get_challenge_file(certs_dir)
	lock_file = _get_challenge_lock_file(certs_dir)
	
	if not challenge_file.exists() and not lock_file.exists():
		return
	
	lock_file.touch(exist_ok=True)
	with open(lock_file, "r+") as lock_handle:
		fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
		challenges = _read_valid_challenges(challenge_file)
		challenges.pop(token, None)
		_atomic_write_bytes(challenge_file, json.dumps(challenges).encode("utf-8"), 0o600)


async def _delayed_challenge_cleanup(certs_dir: PathLib, token: str, delay_seconds: float = 120.0) -> None:
	"""Delay challenge cleanup to avoid racing late ACME validation retries."""
	try:
		await asyncio.sleep(delay_seconds)
	finally:
		_pending_challenges.pop(token, None)
		await asyncio.to_thread(_remove_challenge, certs_dir, token)


def get_challenge_response(token: str, certs_dir: PathLib | None = None) -> str | None:
	"""Get challenge response for ACME HTTP-01 validation.
	
	MULTI-WORKER SAFETY: With multiple Uvicorn workers, the in-memory cache
	is per-process and can miss cross-worker challenges. File-based fallback
	ensures Let's Encrypt can validate challenges regardless of which worker
	receives the validation request. The in-memory dict is purely a fast-path
	optimization for the common case.
	"""
	# Try in-memory first (for current process)
	entry = _pending_challenges.get(token)
	if entry:
		key_auth, expires_at = entry
		if expires_at > time.time():
			return key_auth
		_pending_challenges.pop(token, None)
	
	# Try file-based (for multi-worker/restart scenarios)
	if certs_dir:
		challenges = _load_challenges(certs_dir)
		entry = challenges.get(token)
		if entry:
			return entry.get("key_auth")
	
	return None


# In-memory cache for current process (fast path only)
# WARNING: This dict is per-process. With UVICORN_WORKERS > 1, challenges
# stored in one worker won't be visible in another. File-based storage
# (_save_challenge) ensures cross-worker compatibility.
_pending_challenges: dict[str, tuple[str, float]] = {}


def _prune_pending_challenges(now: float | None = None) -> None:
	"""Drop expired in-memory challenges."""
	current_time = time.time() if now is None else now
	expired_tokens = [token for token, value in _pending_challenges.items() if value[1] <= current_time]
	for token in expired_tokens:
		_pending_challenges.pop(token, None)


async def _get_certs_dir_dep(config: Config = Depends(get_config)) -> PathLib:
	"""Dependency to get certs directory without blocking the event loop."""
	return await asyncio.to_thread(get_certs_dir, config)


def _delete_certificate_files(domain_dir: PathLib, suffix: str) -> bool:
	"""Delete certificate artifacts for one domain/suffix pair."""
	if not domain_dir.exists():
		return False
	deleted = False
	for filename in (
		f"fullchain{suffix}.pem",
		f"privkey{suffix}.pem",
		f"cert{suffix}.pem",
		f"chain{suffix}.pem",
	):
		file_path = domain_dir / filename
		if file_path.exists():
			file_path.unlink()
			deleted = True
	try:
		domain_dir.rmdir()
	except OSError:
		pass
	return deleted


@router.get("/certificates", response_model=OkResponse[list[CertificateInfo]])
async def list_certificates(
	certs_dir: PathLib = Depends(_get_certs_dir_dep),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all certificates."""
	certificates = await asyncio.to_thread(_list_certificates_internal, certs_dir)
	return OkResponse[list[CertificateInfo]](data=certificates)


def _list_certificates_internal(certs_dir: PathLib) -> list[CertificateInfo]:
	"""Internal certificate listing logic used by multiple routes."""
	certificates = []
	
	if not certs_dir.exists():
		return certificates
	
	now = datetime.now(UTC)
	renewal_threshold = timedelta(days=30)
	
	for domain_dir in certs_dir.iterdir():
		if not domain_dir.is_dir() or domain_dir.name.startswith("."):
			continue
		
		# Check for certificate files
		for suffix, is_staging in [("", False), ("_staging", True)]:
			cert_path = domain_dir / f"fullchain{suffix}.pem"
			
			if not cert_path.exists():
				continue
			
			try:
				cert_pem = cert_path.read_bytes()
				cert = x509.load_pem_x509_certificate(cert_pem)
				
				expires_at = cert.not_valid_after_utc
				days_until_expiry = (expires_at - now).days
				# Use timedelta comparison to avoid rounding issues
				needs_renewal = (expires_at - now) <= renewal_threshold
				
				info = CertificateInfo(
					domain=domain_dir.name,
					issued_at=cert.not_valid_before_utc.isoformat(),
					expires_at=expires_at.isoformat(),
					issuer=cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) else "Unknown",
					serial=format(cert.serial_number, "x"),
					exists=True,
					is_staging=is_staging,
					days_until_expiry=days_until_expiry,
					needs_renewal=needs_renewal,
				)
				certificates.append(info)
			except Exception as e:
				_log.warning("Failed to parse certificate %s: %s", cert_path, e)
				certificates.append(CertificateInfo(
					domain=domain_dir.name,
					exists=True,
					is_staging=is_staging,
				))
	
	return certificates


@router.post("/certificates/request", response_model=OkResponse[CertificateIssueData])
@limiter.limit(RATE_LIMIT_HEAVY)
async def request_certificate(
	request: Request,
	req: CertificateRequest,
	certs_dir: PathLib = Depends(_get_certs_dir_dep),
	_: sqlite3.Row = Depends(require_admin),
):
	"""
	Request a new certificate from Let's Encrypt.
	
	IMPORTANT: Before calling this, ensure:
	1. The domain points to this server
	2. Port 80 is accessible for HTTP-01 challenge
	3. The /.well-known/acme-challenge/ path is served by this app
	"""
	# Prevent parallel orders for the same domain (worker-safe file lock)
	lock_fd = await asyncio.to_thread(_acquire_domain_lock, certs_dir, req.domain)
	if lock_fd is None:
		raise HTTPException(
			status_code=409,
			detail=f"Certificate request for '{req.domain}' already in progress"
		)
	
	try:
		directory_url = ACME_DIRECTORY_STAGING if req.staging else ACME_DIRECTORY_PROD
		
		_log.info("Requesting certificate for %s (staging=%s)", req.domain, req.staging)
		
		async with ACMEClient(directory_url, certs_dir) as client:
			# Register or fetch account
			await client.register_or_fetch_account(req.email)
			
			# Create order
			order_url, order = await client.order_certificate(req.domain)
			_log.info("Created order: %s", order_url)
			
			# Get authorization
			if not order.get("authorizations"):
				raise HTTPException(status_code=500, detail="No authorizations in order")
			
			auth_url = order["authorizations"][0]
			authorization = await client.get_authorization(auth_url)
			
			# Get HTTP-01 challenge
			token, key_auth = client.get_http01_challenge(authorization)
			
			# Store challenge response (both in-memory and file)
			_prune_pending_challenges()
			_pending_challenges[token] = (key_auth, time.time() + CHALLENGE_TTL)
			await asyncio.to_thread(_save_challenge, certs_dir, token, key_auth)
			_log.info("Challenge token: %s", token)
			
			try:
				# Find and respond to challenge
				challenge_url = None
				for challenge in authorization.get("challenges", []):
					if challenge["type"] == "http-01":
						challenge_url = challenge["url"]
						break
				
				if not challenge_url:
					raise HTTPException(status_code=500, detail="No HTTP-01 challenge URL")
				
				# Tell ACME server we're ready
				await client.respond_to_challenge(challenge_url)

				# Poll authorization explicitly so we observe invalid/expired states
				# before advancing to order polling/finalization.
				await client.poll_authorization(auth_url)
				
				# Wait for order to be ready
				order = await client.poll_order(order_url)
				
				# Finalize order
				cert_pem, key_pem = await client.finalize_order(order["finalize"], order_url, req.domain)
				
				# Save certificate (blocking file I/O — offload to thread)
				cert_dir = await asyncio.to_thread(
					client.save_certificate, req.domain, cert_pem, key_pem, req.staging
				)
				
				suffix = "_staging" if req.staging else ""
				return OkResponse[CertificateIssueData](
					message="Certificate issued successfully",
					data=CertificateIssueData(
						domain=req.domain,
						staging=req.staging,
						cert_path=str(cert_dir / f"fullchain{suffix}.pem"),
						key_path=str(cert_dir / f"privkey{suffix}.pem"),
					),
				)
			
			finally:
				# Delay cleanup so late validation retries do not race immediate deletion.
				asyncio.create_task(_delayed_challenge_cleanup(certs_dir, token))
	
	finally:
		await asyncio.to_thread(_release_domain_lock, lock_fd)


@router.delete("/certificates/{domain}", response_model=OkResponse[CertificateDeleteData])
@limiter.limit(RATE_LIMIT_HEAVY)
async def delete_certificate(
	request: Request,
	domain: str = Path(..., min_length=1, max_length=253, pattern=_DOMAIN_PATTERN),
	staging: bool = False,
	certs_dir: PathLib = Depends(_get_certs_dir_dep),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a certificate."""
	domain_dir = certs_dir / domain
	
	if not await asyncio.to_thread(domain_dir.exists):
		raise HTTPException(status_code=404, detail="Certificate not found")
	
	suffix = "_staging" if staging else ""
	deleted = await asyncio.to_thread(_delete_certificate_files, domain_dir, suffix)
	
	if not deleted:
		raise HTTPException(status_code=404, detail="Certificate files not found")
	
	_log.info("Deleted certificate for %s (staging=%s)", domain, staging)
	
	return OkResponse[CertificateDeleteData](
		message="Certificate deleted",
		data=CertificateDeleteData(success=True, domain=domain, staging=staging),
	)


@router.get("/certificates/challenge/{token}", response_class=PlainTextResponse)
async def serve_challenge(
	token: str,
	certs_dir: PathLib = Depends(_get_certs_dir_dep),
) -> PlainTextResponse:
	"""
	Serve ACME HTTP-01 challenge response.
	
	This endpoint should be accessible at:
	http://<domain>/.well-known/acme-challenge/<token>
	
	Configure your reverse proxy to forward this path.
	"""
	# Validate token format to prevent log spam
	if not re.match(r"^[A-Za-z0-9_\-]+$", token):
		raise HTTPException(status_code=404, detail="Invalid token format")
	
	key_auth = await asyncio.to_thread(get_challenge_response, token, certs_dir)
	
	if not key_auth:
		raise HTTPException(status_code=404, detail="Challenge not found")
	
	return PlainTextResponse(content=key_auth, media_type="text/plain")


@router.get("/certificates/renewal-check", response_model=OkResponse[RenewalCheckData])
async def check_renewals(
	certs_dir: PathLib = Depends(_get_certs_dir_dep),
	_: sqlite3.Row = Depends(require_admin),
):
	"""
	Check which certificates need renewal (expires in <= 30 days).
	
	Use this endpoint to determine which certificates to renew.
	For automatic renewal, call this periodically (e.g., via cron)
	and issue new certificates for domains where needs_renewal is True.
	"""
	certificates = await asyncio.to_thread(_list_certificates_internal, certs_dir)
	
	needs_renewal = [
		cert for cert in certificates
		if cert.needs_renewal and not cert.is_staging
	]
	
	data = RenewalCheckData(
		total_certificates=len([c for c in certificates if not c.is_staging]),
		needs_renewal_count=len(needs_renewal),
		needs_renewal=[
			RenewalCandidate(
				domain=cert.domain,
				expires_at=cert.expires_at,
				days_until_expiry=cert.days_until_expiry,
			)
			for cert in needs_renewal
		],
	)
	return OkResponse[RenewalCheckData](data=data)
