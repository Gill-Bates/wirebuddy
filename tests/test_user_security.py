#!/usr/bin/env python3
#
# tests/test_user_security.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for user-management security invariants."""

from __future__ import annotations

import sqlite3

import pyotp
import pytest
from fastapi import HTTPException

from app.api import users as users_api
from app.api.users import _require_self, disable_user_otp_setup, enable_user_otp
from app.db.sqlite_users import (
	LastAdminError,
	consume_otp_step,
	delete_user,
	get_all_users,
	update_user_recovery_codes_if_current,
)
from app.models.users import OTPDisableRequest
from app.utils.otp import verify_otp_step
from app.utils.time import utcnow


def _insert_user(
	conn: sqlite3.Connection,
	*,
	user_id: int,
	username: str,
	is_admin: bool = False,
	otp_secret: str | None = None,
	otp_recovery_codes: str | None = None,
) -> None:
	conn.execute(
		"""
		INSERT INTO users (
			id,
			username,
			password_hash,
			is_admin,
			is_active,
			otp_secret,
			otp_recovery_codes,
			created_at
		)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?)
		""",
		(
			user_id,
			username,
			f"hash-{username}",
			int(is_admin),
			otp_secret,
			otp_recovery_codes,
			utcnow(),
		),
	)
	conn.commit()


def test_get_all_users_omits_stored_secrets(conn):
	_insert_user(
		conn,
		user_id=1,
		username="admin",
		is_admin=True,
		otp_secret="encrypted-secret",
		otp_recovery_codes='["hashed-code"]',
	)

	row = get_all_users(conn)[0]
	keys = set(row.keys())

	assert "password_hash" not in keys
	assert "otp_recovery_codes" not in keys
	assert row["otp_secret"] == 1


def test_recovery_code_update_requires_current_value(conn):
	_insert_user(
		conn,
		user_id=1,
		username="admin",
		is_admin=True,
		otp_recovery_codes='["old"]',
	)

	assert update_user_recovery_codes_if_current(
		conn,
		1,
		previous_codes='["old"]',
		new_codes='["new"]',
	)
	assert not update_user_recovery_codes_if_current(
		conn,
		1,
		previous_codes='["old"]',
		new_codes='["stale-write"]',
	)
	stored = conn.execute("SELECT otp_recovery_codes FROM users WHERE id = 1").fetchone()
	assert stored["otp_recovery_codes"] == '["new"]'


def test_delete_user_rejects_last_admin_in_db_layer(conn):
	_insert_user(conn, user_id=1, username="admin", is_admin=True)

	with pytest.raises(LastAdminError):
		delete_user(conn, 1)


def test_otp_setup_confirm_requires_self():
	with pytest.raises(HTTPException) as exc:
		_require_self(2, {"id": 1})

	assert exc.value.status_code == 403


def test_otp_enable_rejects_already_enabled_account(conn):
	"""Re-running OTP setup must not silently clear an active OTP enrolment."""
	_insert_user(
		conn,
		user_id=1,
		username="admin",
		is_admin=True,
		otp_secret="encrypted-secret",
		otp_recovery_codes='["hashed-code"]',
	)
	conn.execute("UPDATE users SET otp_enabled = 1 WHERE id = 1")
	conn.commit()
	current_user = conn.execute("SELECT * FROM users WHERE id = 1").fetchone()

	with pytest.raises(HTTPException) as excinfo:
		enable_user_otp.__wrapped__(
			request=None,
			user_id=1,
			conn=conn,
			current_user=current_user,
		)

	assert excinfo.value.status_code == 409
	row = conn.execute("SELECT otp_enabled, otp_secret, otp_recovery_codes FROM users WHERE id = 1").fetchone()
	assert row["otp_enabled"] == 1
	assert row["otp_secret"] == "encrypted-secret"
	assert row["otp_recovery_codes"] == '["hashed-code"]'


def _enrol_otp_user(conn: sqlite3.Connection, secret: str) -> sqlite3.Row:
	_insert_user(
		conn,
		user_id=1,
		username="admin",
		is_admin=True,
		otp_secret="encrypted-secret",
		otp_recovery_codes='["hashed-code"]',
	)
	conn.execute("UPDATE users SET otp_enabled = 1 WHERE id = 1")
	conn.commit()
	return conn.execute("SELECT * FROM users WHERE id = 1").fetchone()


def _disable(conn: sqlite3.Connection, current_user: sqlite3.Row, code: str):
	return disable_user_otp_setup.__wrapped__(
		request=None,
		user_id=1,
		payload=OTPDisableRequest(code=code),
		conn=conn,
		current_user=current_user,
	)


def test_self_otp_disable_rejects_replayed_code(conn, monkeypatch):
	"""Turning off the second factor must not accept an already-used TOTP code.

	The code used for the login that created this session is consumed; replaying
	it inside the same 30-second window must not disable MFA.
	"""
	secret = pyotp.random_base32()
	current_user = _enrol_otp_user(conn, secret)
	monkeypatch.setattr(users_api, "decrypt_otp_secret", lambda _enc: secret)

	code = pyotp.TOTP(secret).now()
	step = verify_otp_step(secret, code)
	assert step is not None
	assert consume_otp_step(conn, 1, step) is True

	with pytest.raises(HTTPException) as excinfo:
		_disable(conn, current_user, code)

	assert excinfo.value.status_code == 401
	assert conn.execute("SELECT otp_enabled FROM users WHERE id = 1").fetchone()["otp_enabled"] == 1


def test_self_otp_disable_accepts_fresh_code_once(conn, monkeypatch):
	"""A code that has not been used still disables MFA, and only once."""
	secret = pyotp.random_base32()
	current_user = _enrol_otp_user(conn, secret)
	monkeypatch.setattr(users_api, "decrypt_otp_secret", lambda _enc: secret)

	code = pyotp.TOTP(secret).now()
	_disable(conn, current_user, code)

	assert conn.execute("SELECT otp_enabled FROM users WHERE id = 1").fetchone()["otp_enabled"] == 0
