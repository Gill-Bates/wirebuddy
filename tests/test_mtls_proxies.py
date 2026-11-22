#!/usr/bin/env python3
#
# tests/test_mtls_proxies.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""The node mTLS fingerprint header is trusted only from WIREBUDDY_MTLS_PROXIES.

The list is separate from WIREBUDDY_TRUSTED_PROXIES and empty by default, so a
proxy trusted for X-Forwarded-* cannot inject a client-cert fingerprint.
"""

from __future__ import annotations

import asyncio

import pytest

from app.api import nodes_sync
from app.utils import config as config_mod
from app.utils.socket_peer import SOCKET_PEER_SCOPE_KEY, wrap_with_proxy_headers

_FP = "a" * 64


class _FakeRequest:
	def __init__(self, client_ip: str | None, headers: dict[str, str] | None = None):
		self.scope = {"client": (client_ip, 12345) if client_ip else None, SOCKET_PEER_SCOPE_KEY: client_ip}
		self.headers = headers or {}


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
	monkeypatch.delenv(config_mod.MTLS_PROXIES_ENV, raising=False)
	monkeypatch.delenv(config_mod.TRUSTED_PROXIES_ENV, raising=False)
	# Skip full config loading (needs a secret key); only the env var is under test.
	monkeypatch.setattr(config_mod, "get_config", lambda: None)
	monkeypatch.setattr(config_mod, "_mtls_proxy_networks", None)
	monkeypatch.setattr(config_mod, "_explicit_proxy_networks", None)


def _request(ip: str) -> _FakeRequest:
	return _FakeRequest(ip, {"X-Client-Cert-Fingerprint": _FP})


def test_default_trusts_nothing():
	assert config_mod.get_mtls_proxy_networks() == ()
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("127.0.0.1")) is None


def test_configured_proxy_is_trusted(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("10.0.0.5")) == _FP
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("10.0.0.6")) is None


def test_trusted_proxies_only_is_not_trusted_for_fingerprint(monkeypatch):
	monkeypatch.setenv(config_mod.TRUSTED_PROXIES_ENV, "10.0.0.5/32,127.0.0.0/8")
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("10.0.0.5")) is None
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("127.0.0.1")) is None


def test_invalid_entries_are_skipped_and_never_widen_trust(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "not-a-cidr, *, 10.0.0.5/32")
	assert [str(n) for n in config_mod.get_mtls_proxy_networks()] == ["10.0.0.5/32"]
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("192.0.2.1")) is None


def test_only_invalid_entries_trust_nothing(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "garbage,*")
	assert config_mod.get_mtls_proxy_networks() == ()
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("10.0.0.5")) is None


def test_malformed_fingerprint_from_trusted_proxy_is_rejected(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	req = _FakeRequest("10.0.0.5", {"X-Client-Cert-Fingerprint": "xyz"})
	with pytest.raises(nodes_sync.HTTPException) as exc:
		nodes_sync._get_verified_client_cert_fingerprint(req)
	assert exc.value.status_code == 403


def test_rewritten_client_does_not_count_as_peer(monkeypatch):
	# uvicorn replaced scope["client"] with a forged X-Forwarded-For address.
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	req = _FakeRequest("192.0.2.9", {"X-Client-Cert-Fingerprint": _FP})
	req.scope["client"] = ("10.0.0.5", 1)
	assert nodes_sync._get_verified_client_cert_fingerprint(req) is None


def test_missing_captured_peer_fails_closed(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	req = _FakeRequest("10.0.0.5", {"X-Client-Cert-Fingerprint": _FP})
	del req.scope[SOCKET_PEER_SCOPE_KEY]
	assert nodes_sync._get_verified_client_cert_fingerprint(req) is None


def test_no_client_scope_is_untrusted(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	assert nodes_sync._get_verified_client_cert_fingerprint(_request(None)) is None


def test_ipv6_proxy_matching(monkeypatch):
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "::1/128, 2001:db8:1::/64")
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("::1")) == _FP
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("2001:db8:1::7")) == _FP
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("2001:db8:2::7")) is None
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("127.0.0.1")) is None


def test_ipv4_mapped_peer_is_normalized_before_matching(monkeypatch):
	# A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d.
	monkeypatch.setenv(config_mod.MTLS_PROXIES_ENV, "10.0.0.5/32")
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("::ffff:10.0.0.5")) == _FP
	assert nodes_sync._get_verified_client_cert_fingerprint(_request("::ffff:10.0.0.6")) is None


def test_middleware_keeps_peer_while_uvicorn_rewrites_client():
	seen: dict = {}

	async def inner(scope, receive, send):
		seen.update(scope)

	app = wrap_with_proxy_headers(inner, "10.0.0.9")
	scope = {
		"type": "http",
		"client": ("10.0.0.9", 1),
		"headers": [(b"x-forwarded-for", b"10.0.0.5")],
		SOCKET_PEER_SCOPE_KEY: "10.0.0.5",  # a pre-set value must be overwritten
	}
	asyncio.run(app(scope, None, None))
	assert seen["client"][0] == "10.0.0.5"
	assert seen[SOCKET_PEER_SCOPE_KEY] == "10.0.0.9"
