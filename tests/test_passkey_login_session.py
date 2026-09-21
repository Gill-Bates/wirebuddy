#!/usr/bin/env python3
#
# tests/test_passkey_login_session.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Passkey login must issue its session exactly like the password login.

WebAuthn verification and challenge bookkeeping are stubbed; everything from
the sign-count update onwards runs against a real schema.
"""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.api import auth, passkeys
from app.api.passkeys import PasskeyLoginFinishRequest
from app.db.sqlite_users import create_user
from app.utils.time import utcnow

_CREDENTIAL_ID = "cred-1"


@pytest.fixture()
def passkey_user(conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> int:
	user_id = create_user(conn, "alice", "Correct-Horse-Battery-9", is_admin=False)
	conn.execute("UPDATE users SET passkey_enabled = 1 WHERE id = ?", (user_id,))
	conn.execute(
		"INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, 0, ?)",
		(user_id, _CREDENTIAL_ID, b"pk", utcnow()),
	)
	conn.commit()

	monkeypatch.setattr(passkeys, "_get_client_ip", lambda request: "198.51.100.7")
	monkeypatch.setattr(passkeys, "_get_rp_id", lambda request: "vpn.example.com")
	monkeypatch.setattr(passkeys, "_get_origin", lambda request: "https://vpn.example.com")
	monkeypatch.setattr(passkeys, "_parse_client_data", lambda credential: {"challenge": "c"})
	monkeypatch.setattr(passkeys, "consume_authentication_challenge", lambda conn, challenge: SimpleNamespace(user_id=None))
	monkeypatch.setattr(passkeys, "verify_authentication", lambda **kwargs: SimpleNamespace(new_sign_count=5))
	return user_id


def _login(conn: sqlite3.Connection) -> Response:
	request = Request({"type": "http", "method": "POST", "path": "/api/passkeys/login/finish", "headers": []})
	response = Response()
	payload = PasskeyLoginFinishRequest(credential={"id": _CREDENTIAL_ID})
	passkeys.passkey_login_finish.__wrapped__(request, response, payload, conn)
	return response


def _state(conn: sqlite3.Connection) -> tuple[int, int]:
	tokens = conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0]
	sign_count = conn.execute("SELECT sign_count FROM passkeys WHERE credential_id = ?", (_CREDENTIAL_ID,)).fetchone()[0]
	return tokens, sign_count


def test_plaintext_passkey_login_is_rejected_when_https_is_required(conn, passkey_user, monkeypatch):
	monkeypatch.setattr(auth, "_is_https", lambda request: False)
	monkeypatch.setattr(auth, "get_gui_https_enabled", lambda conn: True)

	with pytest.raises(HTTPException) as excinfo:
		_login(conn)

	assert excinfo.value.status_code == 400
	# Rolled back as a unit: no session, and the authenticator counter is untouched.
	assert _state(conn) == (0, 0)


def test_https_passkey_login_sets_the_same_cookie_as_password_login(conn, passkey_user, monkeypatch):
	monkeypatch.setattr(auth, "_is_https", lambda request: True)

	cookie = _login(conn).headers["set-cookie"]

	assert cookie.startswith("auth_token=")
	assert "HttpOnly" in cookie
	assert "Secure" in cookie
	assert "SameSite=lax" in cookie
	assert _state(conn) == (1, 5)
