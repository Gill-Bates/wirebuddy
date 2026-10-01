#!/usr/bin/env python3
#
# tests/test_auth_session_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Regression tests: mandatory password change gate, cookie auth paths, TOTP replay."""

from __future__ import annotations

import sqlite3
import time
from datetime import timedelta

import pyotp
import pytest
from fastapi import HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.api import auth as auth_api
from app.api.frontend_shared import RedirectTo, require_user_or_redirect
from app.db import sqlite_runtime as rt
from app.db.sqlite_auth import create_auth_token
from app.db.sqlite_schema import init_schema
from app.db.sqlite_users import (
	confirm_user_otp,
	consume_otp_step,
	disable_user_otp,
	get_user_by_id,
	set_user_otp_secret,
)
from app.utils.otp import verify_otp_step
from app.utils.time import utcnow


def _request(path: str, cookie: str | None = None) -> Request:
	headers = [(b"cookie", f"auth_token={cookie}".encode())] if cookie else []
	return Request({"type": "http", "method": "GET", "path": path, "headers": headers, "query_string": b""})


def _add_user(conn: sqlite3.Connection, user_id: int, *, must_change: bool) -> str:
	conn.execute(
		"INSERT INTO users (id, username, password_hash, is_active, must_change_password, created_at) VALUES (?, ?, 'x', 1, ?, ?)",
		(user_id, f"user{user_id}", int(must_change), utcnow()),
	)
	conn.commit()
	token = f"token-{user_id}-{'x' * 32}"
	now = utcnow()
	create_auth_token(conn, user_id, token, now + timedelta(hours=1), now + timedelta(hours=8))
	return token


def _bearer(token: str) -> HTTPAuthorizationCredentials:
	return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_pending_password_change_blocks_protected_api(conn):
	token = _add_user(conn, 1, must_change=True)
	with pytest.raises(HTTPException) as exc:
		auth_api.get_current_user(_request("/api/wireguard/interfaces"), _bearer(token), conn)
	assert exc.value.status_code == 428
	with pytest.raises(HTTPException) as exc:
		auth_api.get_current_user(_request("/api/me"), _bearer(token), conn)
	assert exc.value.status_code == 428


@pytest.mark.parametrize("path", ["/api/users/me/complete-required-change", "/api/logout", "/ui/change-password"])
def test_pending_password_change_allows_change_and_logout_paths(conn, path):
	token = _add_user(conn, 1, must_change=True)
	user = auth_api.get_current_user(_request(path), _bearer(token), conn)
	assert user["id"] == 1


def test_pending_password_change_blocks_cookie_session(conn):
	token = _add_user(conn, 1, must_change=True)
	with pytest.raises(HTTPException) as exc:
		auth_api.get_current_user(_request("/api/dns/status", cookie=token), None, conn)
	assert exc.value.status_code == 428


def test_regular_user_is_unaffected(conn):
	token = _add_user(conn, 1, must_change=False)
	user = auth_api.get_current_user(_request("/api/wireguard/interfaces"), _bearer(token), conn)
	assert user["id"] == 1


def test_ui_guard_redirects_to_change_password(conn):
	_add_user(conn, 1, must_change=True)
	user = get_user_by_id(conn, 1)
	with pytest.raises(RedirectTo) as exc:
		require_user_or_redirect(_request("/ui/dashboard"), user)
	assert exc.value.url == "/ui/change-password"
	# The change page itself must stay reachable.
	assert require_user_or_redirect(_request("/ui/change-password"), user)["id"] == 1


def test_ui_guard_passes_regular_user(conn):
	_add_user(conn, 1, must_change=False)
	user = get_user_by_id(conn, 1)
	assert require_user_or_redirect(_request("/ui/dashboard"), user)["id"] == 1


@pytest.mark.parametrize("path", ["/", "/login", "/login/", "/ui/dashboard", "/api/me"])
def test_cookie_auth_allowed_paths(path):
	assert auth_api._allow_cookie_auth_for_path(path) is True


@pytest.mark.parametrize("path", ["/loginx", "/login/extra", "/static/app.js", "/health", "/other"])
def test_cookie_auth_rejected_paths(path):
	assert auth_api._allow_cookie_auth_for_path(path) is False


def test_optional_user_detects_session_on_login_page(conn):
	token = _add_user(conn, 1, must_change=False)
	user = auth_api.get_current_user_optional(_request("/login", cookie=token), None, conn)
	assert user is not None and user["id"] == 1


def test_totp_step_matches_current_code_only():
	secret = pyotp.random_base32()
	totp = pyotp.TOTP(secret)
	step = verify_otp_step(secret, totp.now())
	assert step == int(time.time()) // totp.interval
	assert verify_otp_step(secret, "000000" if totp.now() != "000000" else "111111") is None
	assert verify_otp_step(secret, "abc") is None


def test_consume_otp_step_rejects_replay_and_older_steps(conn):
	_add_user(conn, 1, must_change=False)
	assert consume_otp_step(conn, 1, 100) is True
	assert consume_otp_step(conn, 1, 100) is False
	assert consume_otp_step(conn, 1, 99) is False
	assert consume_otp_step(conn, 1, 101) is True


def test_otp_step_is_reset_on_new_secret_and_disable(conn):
	_add_user(conn, 1, must_change=False)
	assert consume_otp_step(conn, 1, 500) is True
	assert set_user_otp_secret(conn, 1, pyotp.random_base32())
	assert consume_otp_step(conn, 1, 500) is True
	assert disable_user_otp(conn, 1)
	assert consume_otp_step(conn, 1, 500) is True


def test_migration_adds_otp_last_used_step_to_existing_database():
	rt._ensure_sqlite_adapters()
	old = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	old.row_factory = sqlite3.Row
	try:
		init_schema(old)
		old.execute("ALTER TABLE users DROP COLUMN otp_last_used_step")
		old.commit()
		init_schema(old)
		cols = {row["name"] for row in old.execute("PRAGMA table_info(users)")}
		assert "otp_last_used_step" in cols
	finally:
		old.close()


def test_confirm_otp_second_confirm_with_stale_row_is_rejected(conn):
	token = _add_user(conn, 1, must_change=False)
	assert set_user_otp_secret(conn, 1, pyotp.random_base32())
	assert confirm_user_otp(conn, 1, "codes-first") is True

	# A parallel confirm that already passed the pending check must lose cleanly.
	assert confirm_user_otp(conn, 1, "codes-second") is False
	assert get_user_by_id(conn, 1)["otp_recovery_codes"] == "codes-first"
	assert conn.execute("SELECT COUNT(*) FROM auth_tokens WHERE user_id = 1").fetchone()[0] == 1
	assert token


def test_confirm_endpoint_with_stale_user_row_returns_409_and_keeps_state(conn, monkeypatch):
	token = _add_user(conn, 1, must_change=False)
	secret = pyotp.random_base32()
	assert set_user_otp_secret(conn, 1, secret)
	stale_user = get_user_by_id(conn, 1)
	monkeypatch.setattr(auth_api, "decrypt_otp_secret", lambda _value: secret)
	# The winning request already enabled OTP after this request loaded its row.
	assert confirm_user_otp(conn, 1, "codes-first") is True

	request = Request({"type": "http", "method": "POST", "path": "/api/auth/me/otp/confirm", "headers": [], "query_string": b"", "client": ("127.0.0.1", 1)})
	payload = auth_api.OTPConfirmRequest(code=pyotp.TOTP(secret).now())
	with pytest.raises(HTTPException) as exc:
		auth_api.confirm_my_otp_setup.__wrapped__(request, Response(), payload, conn, stale_user)

	assert exc.value.status_code == 409
	assert get_user_by_id(conn, 1)["otp_recovery_codes"] == "codes-first"
	assert conn.execute("SELECT COUNT(*) FROM auth_tokens WHERE user_id = 1").fetchone()[0] == 1
	assert token
