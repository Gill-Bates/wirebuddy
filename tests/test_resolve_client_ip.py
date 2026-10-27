#!/usr/bin/env python3
#
# tests/test_resolve_client_ip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""resolve_client_ip() must not trust a blindly-taken first X-Forwarded-For hop.

The client IP drives login lockout, MFA challenge binding and auth auditing, so
a spoofable value is a security defect. When the socket peer is a trusted proxy
the forwarded chain is walked RIGHT-TO-LEFT against the same trusted-proxy
allowlist that uvicorn is configured from: trusted reporters are skipped and the
first untrusted hop from the right is the real client. An untrusted peer is
never allowed to inject a client IP through the header.
"""

from __future__ import annotations

import pytest

from app.utils import config as config_mod
from app.utils import network


class _FakeRequest:
	def __init__(self, client_ip: str | None, headers: dict[str, str] | None = None):
		self.scope = {"client": (client_ip, 12345) if client_ip else None}
		self.headers = headers or {}


@pytest.fixture()
def _trusted_loopback(monkeypatch, tmp_path):
	"""Trust the loopback /8 and ::1 (the shipped default) for these tests."""
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path / "data"))
	cfg = config_mod.load_config()
	cfg = config_mod.Config(
		base_dir=cfg.base_dir,
		db_path=cfg.db_path,
		tsdb_dir=cfg.tsdb_dir,
		dns_dir=cfg.dns_dir,
		data_dir=cfg.data_dir,
		trusted_proxies=config_mod.parse_proxy_cidrs("127.0.0.0/8,::1/128"),
	)
	# resolve_client_ip() imports get_config lazily from app.utils.config, so
	# patch it at the source module.
	monkeypatch.setattr(config_mod, "get_config", lambda: cfg)
	return cfg


def test_untrusted_peer_ignores_forwarded_header(_trusted_loopback):
	# Peer is NOT a trusted proxy: the header must be ignored entirely and the
	# socket address returned, so a spoofed XFF cannot set the client IP.
	req = _FakeRequest("203.0.113.9", {"X-Forwarded-For": "1.2.3.4"})
	assert network.resolve_client_ip(req) == "203.0.113.9"


def test_trusted_single_proxy_returns_forwarded_client(_trusted_loopback):
	# One trusted proxy on loopback forwarding a single real client.
	req = _FakeRequest("127.0.0.1", {"X-Forwarded-For": "203.0.113.9"})
	assert network.resolve_client_ip(req) == "203.0.113.9"


def test_trusted_peer_other_than_default_uvicorn(_trusted_loopback):
	# A process on 127.0.0.2 is trusted by the /8 default; the app must agree
	# with the uvicorn allowlist (both come from Config.trusted_proxies) and
	# resolve the forwarded client rather than the peer.
	req = _FakeRequest("127.0.0.2", {"X-Forwarded-For": "203.0.113.9"})
	assert network.resolve_client_ip(req) == "203.0.113.9"


def test_multi_hop_chain_takes_rightmost_untrusted(_trusted_loopback):
	# Chain: real client -> external proxy (untrusted) -> local trusted proxy.
	# The rightmost untrusted hop (198.51.100.7) is the edge the trusted chain
	# received the request from; 203.0.113.9 further left is attacker-supplied
	# and must NOT be trusted.
	req = _FakeRequest("127.0.0.1", {"X-Forwarded-For": "203.0.113.9, 198.51.100.7, 127.0.0.1"})
	assert network.resolve_client_ip(req) == "198.51.100.7"


def test_spoof_from_trusted_peer_cannot_inject_arbitrary_client(_trusted_loopback):
	# A trusted local process (127.0.0.2) appends a spoofed client. Because the
	# rightmost hop it reported is itself trusted loopback, the walk continues
	# and stops at the first untrusted address — it cannot be bypassed by
	# padding the chain with more trusted entries.
	req = _FakeRequest("127.0.0.2", {"X-Forwarded-For": "203.0.113.9, 127.0.0.1, 127.0.0.3"})
	assert network.resolve_client_ip(req) == "203.0.113.9"


def test_all_trusted_chain_falls_back_to_socket(_trusted_loopback):
	# Every hop is trusted: there is no real external client in the header, so
	# the socket address is returned rather than a trusted-proxy address.
	req = _FakeRequest("127.0.0.1", {"X-Forwarded-For": "127.0.0.3, 127.0.0.1"})
	assert network.resolve_client_ip(req) == "127.0.0.1"


def test_x_real_ip_used_when_no_forwarded_for(_trusted_loopback):
	req = _FakeRequest("127.0.0.1", {"X-Real-IP": "203.0.113.9"})
	assert network.resolve_client_ip(req) == "203.0.113.9"
