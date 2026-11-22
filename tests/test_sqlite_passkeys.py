#!/usr/bin/env python3
#
# tests/test_sqlite_passkeys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Passkey storage: only a credential-ID conflict is reported as "already registered"."""

from __future__ import annotations

import sqlite3

import pytest

from app.db.sqlite_passkeys import consume_challenge, create_passkey, store_challenge
from app.db.sqlite_users import create_user


def _passkey(conn: sqlite3.Connection, user_id: int, credential_id: str) -> int:
	return create_passkey(conn, user_id, credential_id, b"pk", 0)


def test_duplicate_credential_id_is_reported_as_already_registered(conn):
	uid = create_user(conn, "alice", "S3cret-passw0rd!x")
	_passkey(conn, uid, "cred-1")
	with pytest.raises(ValueError, match="already registered"):
		_passkey(conn, uid, "cred-1")


def test_other_integrity_errors_are_not_reported_as_duplicates(conn):
	conn.execute("PRAGMA foreign_keys = ON")
	with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
		_passkey(conn, 9999, "cred-2")


@pytest.mark.parametrize("ceremony", ["registration", "authentication"])
def test_challenge_roundtrip_for_valid_ceremony_types(conn, ceremony):
	uid = create_user(conn, "bob", "S3cret-passw0rd!x")
	store_challenge(conn, "chal-" + ceremony, ceremony, uid, "bob")
	assert consume_challenge(conn, "chal-" + ceremony, ceremony) == (uid, "bob")


def test_invalid_ceremony_type_is_rejected_on_store_and_consume(conn):
	with pytest.raises(ValueError, match="Invalid ceremony_type"):
		store_challenge(conn, "c", "other", None, None)
	with pytest.raises(ValueError, match="Invalid ceremony_type"):
		consume_challenge(conn, "c", "other")
