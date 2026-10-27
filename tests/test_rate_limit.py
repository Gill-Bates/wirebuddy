#!/usr/bin/env python3
#
# tests/test_rate_limit.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""In-memory rate limiter: sliding window, per-route counters, IPv6 bundling, fail-closed behaviour, 429 contract."""

from __future__ import annotations

import threading
import uuid

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.utils import rate_limit as rl
from app.utils.rate_limit import RateLimitExceededError, SlidingWindow, parse_limit, rate_limit


class _FakeRequest:
	def __init__(self, client):
		self.scope = {"client": client}
		self.headers = {}


class FakeClock:
	def __init__(self) -> None:
		self.now = 1000.0

	def __call__(self) -> float:
		return self.now


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
	("text", "expected"),
	[("5/minute", (5, 60)), ("1/second", (1, 1)), (" 10 / hour ", (10, 3600)), ("2/day", (2, 86400)), ("3/minutes", (3, 60))],
)
def test_parse_limit_valid(text, expected):
	assert parse_limit(text) == expected


@pytest.mark.parametrize("text", ["", "5", "5/week", "abc/minute", "0/minute", "-1/minute", "5 per minute", "5/minute;", None, 5])
def test_parse_limit_invalid_raises_value_error(text):
	with pytest.raises(ValueError, match="rate limit"):
		parse_limit(text)


def test_invalid_limit_fails_at_registration_not_at_request_time():
	with pytest.raises(ValueError, match="rate limit"):
		rate_limit("lots")


@pytest.mark.parametrize("name", ["RATE_LIMIT_DEFAULT", "RATE_LIMIT_AUTH", "RATE_LIMIT_HEAVY", "RATE_LIMIT_API", "RATE_LIMIT_CRITICAL", "RATE_LIMIT_UI_HEAVY"])
def test_presets_are_valid(name):
	parse_limit(getattr(rl, name))


# ---------------------------------------------------------------------------
# SlidingWindow
# ---------------------------------------------------------------------------


def test_window_allows_up_to_limit_then_reports_retry_after():
	clock = FakeClock()
	win = SlidingWindow(2, 60, clock)
	assert win.hit("a") is None
	clock.now += 10
	assert win.hit("a") is None
	clock.now += 5
	wait = win.hit("a")
	assert wait == pytest.approx(45)  # oldest hit (t=0) leaves the window at t=60


def test_window_slides_and_rejected_requests_are_not_recorded():
	clock = FakeClock()
	win = SlidingWindow(1, 60, clock)
	assert win.hit("a") is None
	for _ in range(5):
		clock.now += 1
		assert win.hit("a") is not None
	clock.now = 1060.0
	assert win.hit("a") is None  # rejections did not extend the block


def test_keys_are_independent():
	win = SlidingWindow(1, 60, FakeClock())
	assert win.hit("10.0.0.1") is None
	assert win.hit("10.0.0.2") is None
	assert win.hit("10.0.0.1") is not None


def test_ipv6_addresses_in_one_slash64_share_a_counter():
	win = SlidingWindow(1, 60, FakeClock())
	assert win.hit("2001:db8:1:2::1") is None
	assert win.hit("2001:db8:1:2:ffff::9") is not None
	assert win.hit("2001:db8:1:3::1") is None  # different /64


def test_max_keys_fails_closed_and_recovers_after_expiry(monkeypatch):
	monkeypatch.setattr(rl, "MAX_KEYS", 3)
	clock = FakeClock()
	win = SlidingWindow(5, 60, clock)
	for key in ("a", "b", "c"):
		assert win.hit(key) is None
	with pytest.raises(RuntimeError, match="capacity"):
		win.hit("d")
	assert win.hit("a") is None  # a known key is still served
	clock.now += 61
	assert win.hit("d") is None  # expired keys were evicted


def test_concurrent_hits_never_exceed_the_limit():
	win = SlidingWindow(50, 60, FakeClock())
	allowed = []

	def worker():
		allowed.append(sum(1 for _ in range(40) if win.hit("same") is None))

	threads = [threading.Thread(target=worker) for _ in range(8)]
	for t in threads:
		t.start()
	for t in threads:
		t.join()
	assert sum(allowed) == 50


# ---------------------------------------------------------------------------
# Dependency + HTTP contract
# ---------------------------------------------------------------------------


def _build_app(clock: FakeClock) -> FastAPI:
	app = FastAPI()

	@app.exception_handler(RateLimitExceededError)
	async def _handler(_request, exc):
		from fastapi.responses import JSONResponse

		return JSONResponse(
			status_code=429,
			content={"detail": "Too many requests. Please try again later."},
			headers={"Retry-After": str(exc.retry_after), "X-RateLimit-Limit": exc.limit},
		)

	def deny():
		raise HTTPException(status_code=401, detail="nope")

	@app.get("/a", dependencies=[Depends(rate_limit("2/minute", clock=clock))])
	def route_a():
		return {"ok": "a"}

	@app.get("/b", dependencies=[Depends(rate_limit("2/minute", clock=clock))])
	def route_b():
		return {"ok": "b"}

	@app.get("/secure", dependencies=[Depends(rate_limit("2/minute", clock=clock))])
	def secure(_=Depends(deny)):
		return {"ok": "secure"}

	return app


def test_counters_are_separate_per_route_even_with_identical_limit_string():
	client = TestClient(_build_app(FakeClock()))
	assert [client.get("/a").status_code for _ in range(3)] == [200, 200, 429]
	assert client.get("/b").status_code == 200


def test_429_body_and_headers():
	clock = FakeClock()
	client = TestClient(_build_app(clock))
	client.get("/a")
	clock.now += 20
	client.get("/a")
	clock.now += 10
	response = client.get("/a")
	assert response.status_code == 429
	assert response.json() == {"detail": "Too many requests. Please try again later."}
	assert response.headers["Retry-After"] == "30"
	assert response.headers["X-RateLimit-Limit"] == "2 per 1 minute"


def test_limit_is_counted_before_the_auth_dependency():
	client = TestClient(_build_app(FakeClock()))
	assert [client.get("/secure").status_code for _ in range(3)] == [401, 401, 429]


def test_unresolvable_client_address_shares_one_conservative_bucket():
	# TestClient reports the peer as "testclient", which is not an IP address.
	assert rl.rate_limit_key(_FakeRequest(None)) == "unknown"
	client = TestClient(_build_app(FakeClock()))
	assert [client.get("/a").status_code for _ in range(3)] == [200, 200, 429]


def test_internal_failure_rejects_instead_of_admitting(monkeypatch):
	def boom(self, key):
		raise RuntimeError("broken")

	monkeypatch.setattr(SlidingWindow, "hit", boom)
	client = TestClient(_build_app(FakeClock()))
	assert client.get("/a").status_code == 429


def test_client_key_uses_trusted_proxy_forwarding_only_from_trusted_peers(monkeypatch):
	from app.utils import config as config_mod

	class _Cfg:
		def is_trusted_proxy_ip(self, ip):
			return ip == "127.0.0.1"

	monkeypatch.setattr(config_mod, "get_config", _Cfg)
	trusted = _FakeRequest(("127.0.0.1", 1))
	trusted.headers = {"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}
	# Right-to-left walk: the trusted 127.0.0.1 peer received the request from
	# 10.0.0.1, which is not itself a trusted proxy, so it is the real client
	# edge. The leftmost 203.0.113.7 is attacker-supplied and must not be trusted.
	assert rl.rate_limit_key(trusted) == "10.0.0.1"
	untrusted = _FakeRequest(("198.51.100.9", 1))
	untrusted.headers = {"X-Forwarded-For": "203.0.113.7"}
	assert rl.rate_limit_key(untrusted) == "198.51.100.9"


def test_real_app_returns_429_before_authentication(monkeypatch, tmp_path):
	"""GET /api/users is RATE_LIMIT_AUTH (5/minute) and requires an admin: unauthenticated attempts still count."""
	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))  # keep the real data/ untouched
	# The route limiter is process-wide with a real clock; a unique client key gives this test a fresh
	# bucket, so other requests to /api/users (or a rerun) cannot change the 5/minute budget it observes.
	bucket = f"test-{uuid.uuid4().hex}"
	monkeypatch.setattr(rl, "rate_limit_key", lambda _request: bucket)
	client = TestClient(main.create_app(), raise_server_exceptions=False)
	codes = [client.get("/api/users").status_code for _ in range(7)]
	assert codes[:5] == [401] * 5
	assert codes[5:] == [429, 429]
	response = client.get("/api/users")
	assert response.json() == {"detail": "Too many requests. Please try again later."}
	assert int(response.headers["Retry-After"]) >= 1
	assert response.headers["X-RateLimit-Limit"] == "5 per 1 minute"
