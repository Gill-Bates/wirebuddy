#!/usr/bin/env python3
#
# tests/test_https_auth_enforcement.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""HTTPS enforcement for authentication transport (P2.1).

The opt-in WIREBUDDY_REQUIRE_HTTPS_AUTH flag upgrades the plaintext-auth
warning to a hard rejection, with a single implicit exception for loopback
peers so local HTTP development keeps working. Default behaviour (flag off,
GUI HTTPS off) stays a warning so documented plain-HTTP LAN installs still log
in.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi import HTTPException, Request

from app.api import auth as auth_api
from app.utils import config as config_mod


class _FakeConfig:
	def __init__(self, require_https_auth: bool) -> None:
		self.require_https_auth = require_https_auth
		self.force_https = False
		# Default trusted proxies: loopback only.
		self._trusted = ("127.0.0.0/8", "::1/128")

	def is_trusted_proxy_ip(self, ip_text: str) -> bool:
		import ipaddress

		try:
			ip_obj = ipaddress.ip_address(ip_text)
		except ValueError:
			return False
		return any(ip_obj in ipaddress.ip_network(net) for net in self._trusted)


def _request(scheme: str, client_ip: str, *, forwarded_proto: str | None = None) -> Request:
	headers = []
	if forwarded_proto is not None:
		headers.append((b"x-forwarded-proto", forwarded_proto.encode()))
	return Request(
		{
			"type": "http",
			"method": "POST",
			"path": "/api/auth/login",
			"scheme": scheme,
			"server": ("wirebuddy.example", 443 if scheme == "https" else 80),
			"headers": headers,
			"query_string": b"",
			"client": (client_ip, 12345),
		}
	)


def _use_config(monkeypatch, *, require_https_auth: bool) -> None:
	cfg = _FakeConfig(require_https_auth)
	monkeypatch.setattr(config_mod, "get_config", lambda: cfg)


def test_https_request_is_allowed(conn: sqlite3.Connection, monkeypatch) -> None:
	_use_config(monkeypatch, require_https_auth=True)
	assert auth_api._enforce_https_transport(conn, _request("https", "203.0.113.5"), "test") is True


def test_plain_http_rejected_when_flag_set(conn: sqlite3.Connection, monkeypatch) -> None:
	_use_config(monkeypatch, require_https_auth=True)
	with pytest.raises(HTTPException) as exc:
		auth_api._enforce_https_transport(conn, _request("http", "203.0.113.5"), "test")
	assert exc.value.status_code == 400


def test_loopback_http_allowed_even_with_flag(conn: sqlite3.Connection, monkeypatch) -> None:
	_use_config(monkeypatch, require_https_auth=True)
	# Loopback is the single implicit dev exception; returns False (not secure)
	# but does not raise.
	assert auth_api._enforce_https_transport(conn, _request("http", "127.0.0.1"), "test") is False


def test_plain_http_allowed_with_warning_by_default(conn: sqlite3.Connection, monkeypatch) -> None:
	_use_config(monkeypatch, require_https_auth=False)
	# Flag off, GUI HTTPS off: historical behaviour preserved (warn, allow).
	assert auth_api._enforce_https_transport(conn, _request("http", "203.0.113.5"), "test") is False


@pytest.mark.parametrize(
	("client_ip", "expected"),
	[("127.0.0.1", True), ("::1", True), ("10.0.0.5", False), ("203.0.113.5", False)],
)
def test_is_loopback_peer(client_ip: str, expected: bool) -> None:
	assert auth_api._is_loopback_peer(_request("http", client_ip)) is expected


def test_spoofed_forwarded_proto_from_untrusted_peer_is_ignored(conn: sqlite3.Connection, monkeypatch) -> None:
	_use_config(monkeypatch, require_https_auth=True)
	# A non-trusted-proxy peer claiming https via X-Forwarded-Proto must not
	# bypass the requirement.
	req = _request("http", "203.0.113.5", forwarded_proto="https")
	with pytest.raises(HTTPException):
		auth_api._enforce_https_transport(conn, req, "test")
