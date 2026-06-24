#!/usr/bin/env python3
#
# tests/test_user_security.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for user-management security invariants."""

from __future__ import annotations

import sqlite3

import pytest
from fastapi import HTTPException

from app.api.users import _require_self
from app.db import sqlite_runtime as rt
from app.db.sqlite_schema import init_schema
from app.db.sqlite_users import (
	LastAdminError,
	delete_user,
	get_all_users,
	update_user_recovery_codes_if_current,
)
from app.utils.time import utcnow


@pytest.fixture()
def conn():
	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	try:
		yield connection
	finally:
		connection.close()


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
