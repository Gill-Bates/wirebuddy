#!/usr/bin/env python3
#
# tests/test_ci_seed_admin.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Contract of tools/ci-seed-admin.py: seed only a fresh database, refuse any existing user."""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest

from app.db.sqlite_runtime import close_connection, connect
from app.db.sqlite_schema import init_schema
from app.db.sqlite_users import create_user

_SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "ci-seed-admin.py"


@pytest.fixture()
def seed(monkeypatch, tmp_path):
	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "k" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))
	monkeypatch.setenv("SEED_PW", "correct-horse-battery-staple-1")
	monkeypatch.setattr(sys, "argv", ["ci-seed-admin.py", "--password-env", "SEED_PW"])
	spec = importlib.util.spec_from_file_location("ci_seed_admin", _SCRIPT)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def _db_path() -> Path:
	from app.utils.config import load_config

	return load_config().db_path


def _prepare(*, active: bool, admin: bool) -> Path:
	db_path = _db_path()
	conn = connect(db_path)
	try:
		init_schema(conn)
		uid = create_user(conn, "existing", "another-long-password-1", is_admin=admin)
		if not active:
			conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (uid,))
			conn.commit()
	finally:
		close_connection(conn)
	return db_path


def _users(db_path: Path) -> list[tuple]:
	with closing(sqlite3.connect(db_path)) as conn:
		return conn.execute("SELECT is_admin, is_active, must_change_password FROM users").fetchall()


def test_fresh_database_gets_active_admin(seed):
	assert seed.main() == 0
	assert _users(_db_path()) == [(1, 1, 0)]


@pytest.mark.parametrize(("active", "admin"), [(True, False), (False, True)], ids=["normal-user", "disabled-admin"])
def test_any_existing_user_aborts_before_writing(seed, active, admin):
	db_path = _prepare(active=active, admin=admin)
	assert seed.main() == 1
	assert len(_users(db_path)) == 1
