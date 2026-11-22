#!/usr/bin/env python3
#
# tests/test_resolve_client_ip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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
from app.utils.socket_peer import SOCKET_PEER_SCOPE_KEY, socket_peer_ip


class _FakeRequest:
	def __init__(self, client_ip: str | None, headers: dict[str, str] | None = None):
		self.scope = {"client": (client_ip, 12345) if client_ip else None, SOCKET_PEER_SCOPE_KEY: client_ip}
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


# (X-Forwarded-For, expected client) with loopback as the only trusted proxy range.
_CHAIN_CASES = [
	("", None),
	("127.0.0.1, ::1", None),
	("203.0.113.9", "203.0.113.9"),
	("198.51.100.1, 203.0.113.9, 127.0.0.1", "203.0.113.9"),
	("203.0.113.9, garbage, 127.0.0.1", None),
	("2001:db8::1, ::1", "2001:db8::1"),
	(" , 203.0.113.9 ,, ", "203.0.113.9"),
	("::ffff:203.0.113.9", "203.0.113.9"),
]


@pytest.mark.parametrize(("chain", "expected"), _CHAIN_CASES)
def test_forwarded_chain_walk_is_shared_by_auth_and_status(_trusted_loopback, chain, expected):
	from app.api import frontend_status

	assert network._client_from_forwarded_chain(chain, _trusted_loopback) == expected
	picked = frontend_status._pick_forwarded_client_ip(chain, set())
	assert (str(picked) if picked is not None else None) == expected


def _wrapped_stack(monkeypatch):
	"""Build the served stack (ProxyHeadersMiddleware + socket peer capture) around a probe app."""
	from starlette.applications import Starlette
	from starlette.responses import JSONResponse
	from starlette.routing import Route

	import app as app_pkg
	from app import server

	async def probe(request):
		return JSONResponse({"client": request.scope["client"][0], "peer": socket_peer_ip(request.scope), "resolved": network.resolve_client_ip(request)})

	monkeypatch.setattr(app_pkg, "create_app", lambda: Starlette(routes=[Route("/", probe)]))
	return server.create_served_app()


def test_served_stack_trusted_proxy_forwards_real_client(_trusted_loopback, monkeypatch):
	from starlette.testclient import TestClient

	client = TestClient(_wrapped_stack(monkeypatch), client=("127.0.0.1", 50000))
	body = client.get("/", headers={"X-Forwarded-For": "203.0.113.9"}).json()
	# uvicorn rewrote scope["client"]; the captured peer still names the proxy.
	assert body == {"client": "203.0.113.9", "peer": "127.0.0.1", "resolved": "203.0.113.9"}


def test_served_stack_untrusted_peer_cannot_spoof_forwarded_for(_trusted_loopback, monkeypatch):
	from starlette.testclient import TestClient

	client = TestClient(_wrapped_stack(monkeypatch), client=("198.51.100.9", 50000))
	body = client.get("/", headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "1.2.3.4"}).json()
	assert body == {"client": "198.51.100.9", "peer": "198.51.100.9", "resolved": "198.51.100.9"}


def test_missing_socket_peer_key_fails_closed(_trusted_loopback):
	req = _FakeRequest("127.0.0.1", {"X-Forwarded-For": "203.0.113.9"})
	del req.scope[SOCKET_PEER_SCOPE_KEY]
	assert network.resolve_client_ip(req) is None
	assert socket_peer_ip(req.scope) is None
