#!/usr/bin/env python3
#
# tests/test_csrf_middleware.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Characterisation tests for the double-submit CSRF middleware.

The middleware runs in front of a minimal app so every decision it makes is
visible as a status code: 200 means the request reached the endpoint.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, Request

from app.middleware import csrf

BASE = "http://wb.test"
TOKEN = "t" * 43
SESSION = {"auth_token": "session", "csrf_token": TOKEN}


def _build_app(monkeypatch: pytest.MonkeyPatch, *, public_origin: str | None = None, extra: str = "") -> FastAPI:
	monkeypatch.setattr("app.utils.config.get_config", lambda: SimpleNamespace(public_origin=public_origin))
	monkeypatch.setenv("WIREBUDDY_CSRF_ALLOWED_ORIGINS", extra)
	monkeypatch.setattr("app.api.auth._is_https", lambda request: False)
	app = FastAPI()

	@app.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
	async def endpoint(request: Request, path: str):
		return {"csrf": request.state.csrf_token}

	app.add_middleware(csrf.CSRFMiddleware)
	return app


def _send(app: FastAPI, method: str, path: str, *, cookies=None, headers=None, content=None) -> httpx.Response:
	async def run():
		transport = httpx.ASGITransport(app=app)
		async with httpx.AsyncClient(transport=transport, base_url=BASE, cookies=cookies or {}) as client:
			return await client.request(method, path, headers=headers or {}, content=content)

	return asyncio.run(run())


@pytest.fixture()
def app(monkeypatch):
	return _build_app(monkeypatch)


def test_safe_method_passes_and_issues_a_token_cookie(app):
	response = _send(app, "GET", "/ui/dashboard")

	assert response.status_code == 200
	cookie = response.headers["set-cookie"]
	assert cookie.startswith("csrf_token=") and "SameSite=strict" in cookie
	assert response.json()["csrf"] in cookie


def test_existing_token_is_reused_without_a_new_cookie(app):
	response = _send(app, "GET", "/ui/dashboard", cookies={"csrf_token": TOKEN})

	assert response.json()["csrf"] == TOKEN
	assert "set-cookie" not in response.headers


def test_same_origin_post_with_matching_header_passes(app):
	response = _send(app, "POST", "/ui/x", cookies=SESSION, headers={"Origin": BASE, "X-CSRF-Token": TOKEN})

	assert response.status_code == 200


@pytest.mark.parametrize(
	("headers", "detail"),
	[
		({"X-CSRF-Token": TOKEN}, "Cross-origin request blocked"),
		({"Origin": "http://evil.test", "X-CSRF-Token": TOKEN}, "Cross-origin request blocked"),
		({"Origin": "http://wb.test:8080", "X-CSRF-Token": TOKEN}, "Cross-origin request blocked"),
		({"Origin": BASE}, "CSRF token missing or invalid"),
		({"Origin": BASE, "X-CSRF-Token": "wrong"}, "CSRF token missing or invalid"),
	],
)
def test_ui_post_is_rejected_without_same_origin_and_matching_token(app, headers, detail):
	response = _send(app, "POST", "/ui/x", cookies=SESSION, headers=headers)

	assert response.status_code == 403
	assert response.json()["detail"] == detail


def test_referer_is_accepted_when_origin_is_absent(app):
	response = _send(app, "POST", "/ui/x", cookies=SESSION, headers={"Referer": f"{BASE}/ui/peers", "X-CSRF-Token": TOKEN})

	assert response.status_code == 200


def test_login_path_is_protected_even_without_a_session(app):
	response = _send(app, "POST", "/login", headers={"Origin": BASE})

	assert response.status_code == 403


def test_path_normalisation_cannot_escape_the_protected_prefix(app):
	response = _send(app, "POST", "/static/../ui/x", cookies=SESSION, headers={"Origin": "http://evil.test"})

	assert response.status_code == 403


@pytest.mark.parametrize(
	("cookies", "headers", "status"),
	[
		({}, {}, 200),  # API without a session cookie is not a CSRF target
		({}, {"Authorization": "Bearer abc"}, 200),  # header-only bearer
		(SESSION, {"Authorization": "Bearer abc"}, 403),  # bearer plus cookie is still cookie-authenticated
		(SESSION, {}, 403),
		(SESSION, {"Origin": BASE, "X-CSRF-Token": TOKEN}, 200),
	],
)
def test_api_enforcement_applies_only_to_cookie_authenticated_requests(app, cookies, headers, status):
	response = _send(app, "DELETE", "/api/peers/1", cookies=cookies, headers=headers)

	assert response.status_code == status


def test_exempt_login_endpoints_skip_the_check_even_with_a_session(app):
	response = _send(app, "POST", "/api/passkeys/login/finish", cookies=SESSION)

	assert response.status_code == 200


def test_form_encoded_token_is_accepted(app):
	response = _send(
		app, "POST", "/ui/x", cookies=SESSION,
		headers={"Origin": BASE, "Content-Type": "application/x-www-form-urlencoded"},
		content=f"a=1&csrf_token={TOKEN}",
	)

	assert response.status_code == 200


@pytest.mark.parametrize(
	("headers", "content", "status"),
	[
		({"Content-Type": "multipart/form-data; boundary=x"}, b"", 403),
		({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "abc"}, None, 400),
		({"Content-Type": "application/x-www-form-urlencoded"}, b"a=" + b"x" * 20_000, 413),
	],
)
def test_form_edge_cases_are_rejected(app, headers, content, status):
	response = _send(app, "POST", "/ui/x", cookies=SESSION, headers={"Origin": BASE, **headers}, content=content)

	assert response.status_code == status


def test_configured_origins_replace_the_request_origin(monkeypatch):
	app = _build_app(monkeypatch, public_origin="https://vpn.example.com", extra="https://alt.example.com:8443")

	def post(origin):
		return _send(app, "POST", "/ui/x", cookies=SESSION, headers={"Origin": origin, "X-CSRF-Token": TOKEN}).status_code

	assert post("https://vpn.example.com") == 200
	assert post("https://VPN.example.com:443") == 200
	assert post("https://alt.example.com:8443") == 200
	assert post(BASE) == 403
