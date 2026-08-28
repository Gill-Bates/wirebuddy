#!/usr/bin/env python3
#
# tests/test_tls_material.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for TLS material selection for the built-in HTTPS listener.

Locks the rules that keep the listener from ever being handed a certificate it
cannot serve: unusable ACME material must lose to the self-signed fallback, and
the configured FQDN must not be able to point the lookup outside ``certs_dir``.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.utils.tls import (
    describe_gui_certificate,
    ensure_self_signed_cert,
    normalize_hostname,
    resolve_gui_certificate,
)


def _write_cert_pair(directory: Path, hostname: str, *, not_after: dt.datetime) -> None:
    """Write a plausible ACME-style fullchain/privkey pair."""
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - dt.timedelta(days=90))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    (directory / "fullchain.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "privkey.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


# ─── normalize_hostname ──────────────────────────────────────────────────────


@pytest.mark.parametrize("raw", ["/etc/ssl", "../../etc", "evil/subpath", "-bad.com", "a" * 70])
def test_normalize_hostname_rejects_non_hostnames(raw):
    assert normalize_hostname(raw) == "localhost"


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_normalize_hostname_defaults_to_localhost(raw):
    assert normalize_hostname(raw) == "localhost"


def test_normalize_hostname_lowercases_and_strips_root_dot():
    assert normalize_hostname("VPN.Example.COM.") == "vpn.example.com"


def test_normalize_hostname_keeps_ip_literals():
    assert normalize_hostname("192.168.1.1") == "192.168.1.1"
    assert normalize_hostname("[::1]") == "::1"


def test_normalize_hostname_punycodes_idn():
    assert normalize_hostname("münchen.de") == "xn--mnchen-3ya.de"


def test_hostname_cannot_escape_certs_dir(tmp_path):
    """An absolute FQDN must not redirect the lookup out of certs_dir."""
    material = resolve_gui_certificate(tmp_path, "/etc/ssl")
    assert material.certfile.resolve().is_relative_to(tmp_path.resolve())


# ─── ACME material selection ─────────────────────────────────────────────────


def test_valid_letsencrypt_material_is_preferred(tmp_path):
    _write_cert_pair(
        tmp_path / "vpn.example.com",
        "vpn.example.com",
        not_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60),
    )
    assert resolve_gui_certificate(tmp_path, "vpn.example.com").source == "letsencrypt"


def test_unparseable_letsencrypt_cert_falls_back(tmp_path):
    """A cert that cannot be parsed would break the listener, so it must lose."""
    domain_dir = tmp_path / "vpn.example.com"
    domain_dir.mkdir(parents=True)
    (domain_dir / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\nnope\n")
    (domain_dir / "privkey.pem").write_text("also not a key")

    assert resolve_gui_certificate(tmp_path, "vpn.example.com").source == "self-signed"
    assert describe_gui_certificate(tmp_path, "vpn.example.com")["source"] == "self-signed"


def test_expired_letsencrypt_cert_falls_back(tmp_path):
    _write_cert_pair(
        tmp_path / "vpn.example.com",
        "vpn.example.com",
        not_after=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
    )
    assert resolve_gui_certificate(tmp_path, "vpn.example.com").source == "self-signed"


def test_mismatched_letsencrypt_key_falls_back(tmp_path):
    """Cert and key from different pairs cannot complete a handshake."""
    domain_dir = tmp_path / "vpn.example.com"
    _write_cert_pair(
        domain_dir,
        "vpn.example.com",
        not_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60),
    )
    other = ec.generate_private_key(ec.SECP256R1())
    (domain_dir / "privkey.pem").write_bytes(
        other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    assert resolve_gui_certificate(tmp_path, "vpn.example.com").source == "self-signed"


# ─── self-signed fallback ────────────────────────────────────────────────────


def test_self_signed_pair_is_reused_and_permissioned(tmp_path):
    first = ensure_self_signed_cert(tmp_path, "vpn.example.com")
    assert first.keyfile.stat().st_mode & 0o777 == 0o600
    assert first.certfile.stat().st_mode & 0o777 == 0o644
    assert not [p for p in first.certfile.parent.iterdir() if p.name.endswith(".tmp")]

    before = first.certfile.read_bytes()
    second = ensure_self_signed_cert(tmp_path, "vpn.example.com")
    assert second.certfile.read_bytes() == before


def test_self_signed_regenerates_when_key_does_not_match_cert(tmp_path):
    """A crash between the two writes leaves a parseable but unusable pair."""
    material = ensure_self_signed_cert(tmp_path, "vpn.example.com")
    stale_cert = material.certfile.read_bytes()
    other = ec.generate_private_key(ec.SECP256R1())
    material.keyfile.write_bytes(
        other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    repaired = ensure_self_signed_cert(tmp_path, "vpn.example.com")
    assert repaired.certfile.read_bytes() != stale_cert
    cert = x509.load_pem_x509_certificate(repaired.certfile.read_bytes())
    key = serialization.load_pem_private_key(repaired.keyfile.read_bytes(), password=None)
    enc, fmt = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    assert cert.public_key().public_bytes(enc, fmt) == key.public_key().public_bytes(enc, fmt)


def test_self_signed_regenerates_when_hostname_changes(tmp_path):
    ensure_self_signed_cert(tmp_path, "old.example.com")
    material = ensure_self_signed_cert(tmp_path, "new.example.com")
    cert = x509.load_pem_x509_certificate(material.certfile.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "new.example.com" in san.get_values_for_type(x509.DNSName)
