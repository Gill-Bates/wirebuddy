#!/usr/bin/env python3
#
# tests/test_session_revocation.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Changing an authentication factor or account status must invalidate sessions.

A token issued before MFA was enabled, before a passkey was reset, or before an
account was disabled must not keep working afterwards. Each test asserts the
auth_tokens rows directly, because that table is what get_user_by_token reads.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from datetime import timedelta
from types import SimpleNamespace

import pyotp
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.api import auth as auth_api
from app.api import passkeys as passkeys_api
from app.db.sqlite_auth import create_auth_token
from app.db.sqlite_schema import init_schema
from app.db.sqlite_users import create_user, set_user_otp_secret, update_user
from app.models.users import OTPConfirmRequest
from app.tasks import maintenance
from app.utils.crypto import MAX_PASSWORD_BYTES
from app.utils.time import utcnow

_CREDENTIAL_ID = "cred-session-1"


def _issue_token(conn: sqlite3.Connection, user_id: int, token: str) -> None:
	now = utcnow()
	create_auth_token(conn, user_id, token, now + timedelta(hours=1), now + timedelta(hours=8))


def _token_count(conn: sqlite3.Connection) -> int:
	return conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0]


def _request(path: str) -> Request:
	return Request({"type": "http", "method": "POST", "path": path, "headers": [], "query_string": b""})


# ---------------------------------------------------------------------------
# Enabling MFA
# ---------------------------------------------------------------------------


def test_self_otp_confirm_revokes_pre_mfa_sessions_and_reissues_one(conn, monkeypatch):
	user_id = create_user(conn, "alice", "Correct-Horse-Battery-9")
	secret = pyotp.random_base32()
	assert set_user_otp_secret(conn, user_id, secret)
	_issue_token(conn, user_id, "stolen-" + "x" * 32)
	_issue_token(conn, user_id, "other-" + "y" * 32)
	assert _token_count(conn) == 2

	user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
	monkeypatch.setattr(auth_api, "_get_client_ip", lambda request: "198.51.100.7")
	monkeypatch.setattr(auth_api, "_is_https", lambda request: False)

	response = Response()
	auth_api.confirm_my_otp_setup.__wrapped__(
		_request("/api/me/otp/confirm"),
		response,
		OTPConfirmRequest(code=pyotp.TOTP(secret).now()),
		conn,
		user,
	)

	# Both pre-MFA tokens are gone; the caller keeps exactly one fresh session so
	# it can still download its recovery codes.
	assert _token_count(conn) == 1
	assert response.headers["set-cookie"].startswith("auth_token=")
	assert conn.execute("SELECT otp_enabled FROM users WHERE id = ?", (user_id,)).fetchone()[0] == 1


def test_self_otp_confirm_keeps_sessions_when_the_code_is_wrong(conn, monkeypatch):
	user_id = create_user(conn, "bob", "Correct-Horse-Battery-9")
	secret = pyotp.random_base32()
	assert set_user_otp_secret(conn, user_id, secret)
	_issue_token(conn, user_id, "live-" + "z" * 32)

	user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
	monkeypatch.setattr(auth_api, "_get_client_ip", lambda request: "198.51.100.7")
	wrong_code = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"

	with pytest.raises(HTTPException) as excinfo:
		auth_api.confirm_my_otp_setup.__wrapped__(
			_request("/api/me/otp/confirm"),
			Response(),
			OTPConfirmRequest(code=wrong_code),
			conn,
			user,
		)
	assert excinfo.value.status_code == 401

	# A failed activation must not log the user out either.
	assert _token_count(conn) == 1
	assert conn.execute("SELECT otp_enabled FROM users WHERE id = ?", (user_id,)).fetchone()[0] == 0


# ---------------------------------------------------------------------------
# Passkey reset / disable
# ---------------------------------------------------------------------------


def _passkey_user(conn: sqlite3.Connection, username: str) -> int:
	user_id = create_user(conn, username, "Correct-Horse-Battery-9")
	conn.execute("UPDATE users SET passkey_enabled = 1 WHERE id = ?", (user_id,))
	conn.execute(
		"INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, 0, ?)",
		(user_id, f"{_CREDENTIAL_ID}-{username}", b"pk", utcnow()),
	)
	conn.commit()
	_issue_token(conn, user_id, f"passkey-session-{username}-" + "q" * 32)
	return user_id


def test_admin_passkey_reset_revokes_target_sessions(conn):
	user_id = _passkey_user(conn, "carol")
	admin = {"username": "root"}

	passkeys_api.reset_user_passkeys.__wrapped__(_request("/api/passkeys/reset"), user_id, admin, conn)

	assert _token_count(conn) == 0
	assert conn.execute("SELECT COUNT(*) FROM passkeys WHERE user_id = ?", (user_id,)).fetchone()[0] == 0


def test_admin_passkey_disable_revokes_target_sessions(conn):
	user_id = _passkey_user(conn, "dave")
	admin = {"username": "root"}

	passkeys_api.disable_user_passkey.__wrapped__(_request("/api/passkeys/disable"), user_id, admin, conn)

	assert _token_count(conn) == 0


def test_deleting_the_last_own_passkey_revokes_sessions(conn):
	user_id = _passkey_user(conn, "erin")
	user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
	passkey_id = conn.execute("SELECT id FROM passkeys WHERE user_id = ?", (user_id,)).fetchone()[0]

	passkeys_api.delete_passkey_endpoint(passkey_id, user, conn)

	assert _token_count(conn) == 0
	assert conn.execute("SELECT passkey_enabled FROM users WHERE id = ?", (user_id,)).fetchone()[0] == 0


def test_deleting_one_of_two_passkeys_keeps_the_session(conn):
	user_id = _passkey_user(conn, "frank")
	conn.execute(
		"INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, 0, ?)",
		(user_id, "cred-frank-2", b"pk2", utcnow()),
	)
	conn.commit()
	user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
	passkey_id = conn.execute("SELECT id FROM passkeys WHERE credential_id = 'cred-frank-2'").fetchone()[0]

	passkeys_api.delete_passkey_endpoint(passkey_id, user, conn)

	# Another passkey still backs this account, so the session stays valid.
	assert _token_count(conn) == 1


# ---------------------------------------------------------------------------
# Account deactivation
# ---------------------------------------------------------------------------


def test_deactivating_a_user_revokes_tokens_so_reactivation_cannot_revive_them(conn):
	user_id = create_user(conn, "grace", "Correct-Horse-Battery-9")
	_issue_token(conn, user_id, "pre-disable-" + "w" * 32)

	update_user(conn, user_id, is_active=False)
	assert _token_count(conn) == 0

	# Re-enabling must not hand the old token back.
	update_user(conn, user_id, is_active=True)
	assert _token_count(conn) == 0


def test_unrelated_update_keeps_sessions(conn):
	user_id = create_user(conn, "heidi", "Correct-Horse-Battery-9")
	_issue_token(conn, user_id, "kept-" + "v" * 32)

	update_user(conn, user_id, is_admin=True)

	assert _token_count(conn) == 1


# ---------------------------------------------------------------------------
# Expired WebAuthn challenges
# ---------------------------------------------------------------------------


def _challenge_db(tmp_path, monkeypatch) -> tuple[str, sqlite3.Connection]:
	db_path = tmp_path / "wirebuddy.db"
	file_conn = sqlite3.connect(db_path)
	file_conn.row_factory = sqlite3.Row
	init_schema(file_conn)
	monkeypatch.setattr(maintenance, "get_config", lambda: SimpleNamespace(db_path=str(db_path)))
	return str(db_path), file_conn


def test_expired_passkey_challenges_are_purged_and_valid_ones_kept(tmp_path, monkeypatch):
	_, file_conn = _challenge_db(tmp_path, monkeypatch)
	now = time.time()
	file_conn.executemany(
		"INSERT INTO passkey_challenges (challenge, ceremony_type, user_id, username, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		[
			("expired-1", "authentication", None, None, now - 10, now - 130),
			("expired-2", "registration", 1, "alice", now - 1, now - 121),
			("still-valid", "authentication", None, None, now + 60, now),
		],
	)
	file_conn.commit()
	file_conn.close()

	asyncio.run(maintenance.cleanup_expired_passkey_challenges())

	check = sqlite3.connect(tmp_path / "wirebuddy.db")
	remaining = [row[0] for row in check.execute("SELECT challenge FROM passkey_challenges").fetchall()]
	check.close()
	assert remaining == ["still-valid"]


def test_passkey_challenge_cleanup_handles_an_empty_table(tmp_path, monkeypatch):
	_, file_conn = _challenge_db(tmp_path, monkeypatch)
	file_conn.close()

	asyncio.run(maintenance.cleanup_expired_passkey_challenges())


# ---------------------------------------------------------------------------
# Password length bound
# ---------------------------------------------------------------------------


def test_a_long_passphrase_is_accepted():
	from app.models.users import _validate_password_strength

	passphrase = "Correct-Horse-Battery-Staple-9 " * 4  # 124 bytes, over the old 72-byte cap
	assert _validate_password_strength(passphrase) == passphrase


def test_an_oversized_password_is_still_rejected():
	from app.models.users import _validate_password_strength

	with pytest.raises(ValueError, match="at most"):
		_validate_password_strength("Aa1!" + "x" * MAX_PASSWORD_BYTES)


@pytest.mark.parametrize(
	("model_name", "field"),
	[
		("LoginRequest", "password"),
		("UserCreate", "password"),
		("PasswordChangeRequest", "new_password"),
		("AdminPasswordResetRequest", "new_password"),
		("RequiredPasswordChangeRequest", "new_password"),
	],
)
def test_a_257_character_password_is_rejected_by_the_models(model_name, field):
	from pydantic import ValidationError

	from app.models import users

	data = {"username": "alice", "current_password": "Aa1!old-pass", field: "Aa1!" + "x" * 253}
	with pytest.raises(ValidationError):
		getattr(users, model_name)(**data)
