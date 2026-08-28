#!/usr/bin/env python3
#
# app/utils/tls.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""TLS material resolution for the built-in HTTPS listener.

WireBuddy can terminate TLS itself instead of relying on a reverse proxy.
Certificate selection is deliberately simple and predictable:

1. A Let's Encrypt certificate for the configured FQDN, if one exists and is
   still valid, is always preferred.
2. Otherwise a self-signed certificate is generated on demand so HTTPS can be
   switched on before (or without) obtaining an ACME certificate.

The two never fight over the same files: ACME material lives under
``certs/<domain>/`` and is written exclusively by the ACME client, while the
self-signed fallback lives under ``certs/_selfsigned/`` and is written
exclusively here.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_log = logging.getLogger(__name__)

__all__ = [
	"TlsMaterial",
	"describe_gui_certificate",
	"resolve_gui_certificate",
	"ensure_self_signed_cert",
	"load_certificate_expiry",
	"normalize_hostname",
]

# Directory holding the generated fallback certificate.
SELFSIGNED_DIRNAME = "_selfsigned"

# Regenerate the self-signed certificate once it has less than this left.
_SELFSIGNED_RENEW_BEFORE = _dt.timedelta(days=30)
_SELFSIGNED_VALIDITY = _dt.timedelta(days=825)

# A hostname doubles as a directory name under ``certs_dir``, so only a plain
# label sequence is accepted: an absolute path or an embedded separator would
# otherwise resolve outside that directory.
_HOSTNAME_RE = re.compile(
	r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
	r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True)
class TlsMaterial:
	"""Resolved certificate/key pair for the HTTPS listener."""

	certfile: Path
	keyfile: Path
	source: str  # "letsencrypt" | "self-signed"
	domain: str
	expires_at: _dt.datetime | None = None

	@property
	def is_self_signed(self) -> bool:
		return self.source == "self-signed"


def load_certificate_expiry(cert_path: Path) -> _dt.datetime | None:
	"""Return the notAfter timestamp of a PEM certificate, or None."""
	try:
		data = cert_path.read_bytes()
	except OSError:
		return None
	try:
		cert = x509.load_pem_x509_certificate(data)
	except Exception:
		_log.warning("TLS_CERT_UNPARSEABLE path=%s", cert_path)
		return None
	try:
		return cert.not_valid_after_utc
	except AttributeError:  # cryptography < 42
		return cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)


def normalize_hostname(fqdn: str | None) -> str:
	"""Normalize the configured FQDN into a hostname safe to use as a path.

	The result names a directory under ``certs_dir`` and is embedded in the
	certificate, so anything that is not a plain hostname or IP literal degrades
	to ``localhost``. Falling back rather than raising keeps the promise that
	enabling HTTPS always yields a usable certificate.
	"""
	raw = (fqdn or "").strip().strip("[]").rstrip(".")
	if not raw:
		return "localhost"

	try:
		return str(ipaddress.ip_address(raw))
	except ValueError:
		pass

	try:
		# Punycode first so an IDN survives; the codec passes ASCII labels
		# through unchecked, hence the pattern test afterwards.
		candidate = raw.encode("idna").decode("ascii").lower()
	except (UnicodeError, ValueError):
		candidate = ""

	if not candidate or _HOSTNAME_RE.fullmatch(candidate) is None:
		_log.warning("TLS_INVALID_HOSTNAME fqdn=%r - using localhost", fqdn)
		return "localhost"
	return candidate


def _public_key_matches(certfile: Path, keyfile: Path) -> bool:
	"""Check that a certificate and a private key actually belong together."""
	try:
		cert = x509.load_pem_x509_certificate(certfile.read_bytes())
		key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
		encoding = serialization.Encoding.DER
		fmt = serialization.PublicFormat.SubjectPublicKeyInfo
		return (
			cert.public_key().public_bytes(encoding, fmt)
			== key.public_key().public_bytes(encoding, fmt)
		)
	except Exception:
		# Unreadable or unsupported material is unusable either way: the
		# listener could not load it, so report it as not matching.
		return False


def _letsencrypt_material(certs_dir: Path, domain: str) -> TlsMaterial | None:
	"""Return usable ACME material for ``domain``, if present and valid.

	Staging certificates are ignored: they live in ``certs/<domain>_staging/``
	and are never looked at here, because they are not trusted by clients and
	silently serving them would look like a broken production setup.
	"""
	domain_dir = certs_dir / domain
	certfile = domain_dir / "fullchain.pem"
	keyfile = domain_dir / "privkey.pem"
	if not certfile.is_file() or not keyfile.is_file():
		return None

	expires_at = load_certificate_expiry(certfile)
	now = _dt.datetime.now(_dt.timezone.utc)
	if expires_at is None:
		# Unparseable: the listener would fail to start on it, so treat it as
		# absent instead of handing it out as valid material.
		_log.warning(
			"TLS_LE_CERT_UNREADABLE domain=%s - falling back to self-signed", domain,
		)
		return None
	if expires_at <= now:
		_log.warning(
			"TLS_LE_CERT_EXPIRED domain=%s expired_at=%s - falling back to self-signed",
			domain, expires_at.isoformat(),
		)
		return None
	if not _public_key_matches(certfile, keyfile):
		_log.warning(
			"TLS_LE_KEY_MISMATCH domain=%s - falling back to self-signed", domain,
		)
		return None

	return TlsMaterial(
		certfile=certfile,
		keyfile=keyfile,
		source="letsencrypt",
		domain=domain,
		expires_at=expires_at,
	)


def _san_entries(hostname: str) -> list[x509.GeneralName]:
	"""Build SAN entries covering the FQDN plus local access."""
	names: list[x509.GeneralName] = []
	seen: set[str] = set()

	for candidate in (hostname, "localhost"):
		if not candidate or candidate in seen:
			continue
		seen.add(candidate)
		try:
			ip = ipaddress.ip_address(candidate)
		except ValueError:
			names.append(x509.DNSName(candidate))
		else:
			names.append(x509.IPAddress(ip))

	for raw_ip in ("127.0.0.1", "::1"):
		if raw_ip in seen:
			continue
		seen.add(raw_ip)
		names.append(x509.IPAddress(ipaddress.ip_address(raw_ip)))

	return names


def ensure_self_signed_cert(certs_dir: Path, hostname: str) -> TlsMaterial:
	"""Return a self-signed certificate for ``hostname``, generating if needed.

	The certificate is regenerated when it is missing, unparseable, close to
	expiry, or no longer covers the requested hostname (e.g. after the FQDN
	setting changed).
	"""
	target_dir = certs_dir / SELFSIGNED_DIRNAME
	certfile = target_dir / "cert.pem"
	keyfile = target_dir / "privkey.pem"

	if _self_signed_is_usable(certfile, keyfile, hostname):
		return TlsMaterial(
			certfile=certfile,
			keyfile=keyfile,
			source="self-signed",
			domain=hostname,
			expires_at=load_certificate_expiry(certfile),
		)

	target_dir.mkdir(parents=True, exist_ok=True)
	now = _dt.datetime.now(_dt.timezone.utc)
	key = ec.generate_private_key(ec.SECP256R1())
	subject = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64]),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WireBuddy"),
	])
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(subject)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - _dt.timedelta(minutes=5))
		.not_valid_after(now + _SELFSIGNED_VALIDITY)
		.add_extension(x509.SubjectAlternativeName(_san_entries(hostname)), critical=False)
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.sign(key, hashes.SHA256())
	)

	# Stage both files before either rename, so the window in which cert and
	# key can disagree on disk is two adjacent renames rather than a keygen.
	key_tmp = _stage_write(
		keyfile,
		key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption(),
		),
		0o600,
	)
	try:
		cert_tmp = _stage_write(certfile, cert.public_bytes(serialization.Encoding.PEM), 0o644)
	except BaseException:
		key_tmp.unlink(missing_ok=True)
		raise
	key_tmp.replace(keyfile)
	cert_tmp.replace(certfile)
	_sync_dir(target_dir)

	_log.info("TLS_SELFSIGNED_GENERATED hostname=%s path=%s", hostname, certfile)
	return TlsMaterial(
		certfile=certfile,
		keyfile=keyfile,
		source="self-signed",
		domain=hostname,
		expires_at=now + _SELFSIGNED_VALIDITY,
	)


def _self_signed_is_usable(certfile: Path, keyfile: Path, hostname: str) -> bool:
	"""Check an existing self-signed pair for reuse."""
	if not certfile.is_file() or not keyfile.is_file():
		return False

	expires_at = load_certificate_expiry(certfile)
	if expires_at is None:
		return False
	if expires_at - _dt.datetime.now(_dt.timezone.utc) < _SELFSIGNED_RENEW_BEFORE:
		_log.info("TLS_SELFSIGNED_STALE expires_at=%s - regenerating", expires_at.isoformat())
		return False

	# Regenerate when the FQDN changed and is no longer covered.
	try:
		cert = x509.load_pem_x509_certificate(certfile.read_bytes())
		san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
		covered = set(san.get_values_for_type(x509.DNSName))
		covered |= {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
	except Exception:
		return False

	if hostname not in covered:
		_log.info("TLS_SELFSIGNED_HOSTNAME_CHANGED hostname=%s - regenerating", hostname)
		return False

	# Certificate and key are two separate files: a crash between the two
	# writes leaves a pair that parses fine but cannot serve TLS.
	if not _public_key_matches(certfile, keyfile):
		_log.warning("TLS_SELFSIGNED_KEY_MISMATCH - regenerating")
		return False
	return True


def _stage_write(path: Path, data: bytes, mode: int) -> Path:
	"""Write bytes to a durable temp file beside ``path`` and return it.

	The caller renames it into place. A unique name is used so that a second
	process writing the same target cannot land in a half-written temp file.
	"""
	fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
	tmp = Path(tmp_name)
	try:
		with os.fdopen(fd, "wb") as handle:
			handle.write(data)
			handle.flush()
			os.fsync(handle.fileno())
		os.chmod(tmp, mode)
	except BaseException:
		tmp.unlink(missing_ok=True)
		raise
	return tmp


def _sync_dir(path: Path) -> None:
	"""Flush directory entries so the renames survive a crash."""
	try:
		fd = os.open(path, os.O_RDONLY)
	except OSError:
		return
	try:
		os.fsync(fd)
	finally:
		os.close(fd)


def resolve_gui_certificate(certs_dir: Path, fqdn: str | None) -> TlsMaterial:
	"""Pick the certificate the HTTPS listener should present.

	Let's Encrypt material for ``fqdn`` wins when it exists and is still valid;
	otherwise a self-signed certificate is generated. Callers get a concrete,
	always-usable pair so enabling HTTPS can never leave the server without a
	certificate.
	"""
	certs_dir.mkdir(parents=True, exist_ok=True)
	hostname = normalize_hostname(fqdn)

	material = _letsencrypt_material(certs_dir, hostname)
	if material is not None:
		_log.info(
			"TLS_USING_LETSENCRYPT domain=%s expires_at=%s",
			material.domain,
			material.expires_at.isoformat() if material.expires_at else "unknown",
		)
		return material

	return ensure_self_signed_cert(certs_dir, hostname)


def describe_gui_certificate(certs_dir: Path, fqdn: str | None) -> dict[str, object]:
	"""Report which certificate WOULD be served, without generating anything.

	Used by the settings UI so an administrator can see whether enabling HTTPS
	will present the Let's Encrypt certificate or a self-signed fallback.
	Purely read-only, unlike resolve_gui_certificate().
	"""
	hostname = normalize_hostname(fqdn)
	material = _letsencrypt_material(certs_dir, hostname)
	if material is not None:
		return {
			"source": "letsencrypt",
			"domain": hostname,
			"expires_at": material.expires_at.isoformat() if material.expires_at else None,
			"exists": True,
		}

	certfile = certs_dir / SELFSIGNED_DIRNAME / "cert.pem"
	expires_at = load_certificate_expiry(certfile) if certfile.is_file() else None
	return {
		"source": "self-signed",
		"domain": hostname,
		"expires_at": expires_at.isoformat() if expires_at else None,
		"exists": certfile.is_file(),
	}
