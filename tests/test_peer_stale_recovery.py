#!/usr/bin/env python3
#
# tests/test_peer_stale_recovery.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""peer_stale_months: alternate-DB recovery and the 'no key means default' semantics."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.db import sqlite_settings as settings_mod
from app.db.sqlite_schema import insert_default_settings
from app.db.sqlite_settings import (
	DEFAULT_PEER_STALE_MONTHS,
	get_peer_stale_months,
	get_setting,
	recover_missing_global_settings,
	set_setting,
)

_KEY = "peer_stale_months"


@pytest.fixture()
def alt_db(tmp_path, monkeypatch):
	"""Factory for an alternate wirebuddy.db inside an allowed recovery base."""
	monkeypatch.setattr(settings_mod, "_RECOVERY_ALLOWED_BASES", (tmp_path,))

	def make(value: str | None) -> Path:
		path = tmp_path / "alt" / "wirebuddy.db"
		path.parent.mkdir(exist_ok=True)
		path.unlink(missing_ok=True)
		src = sqlite3.connect(str(path))
		try:
			src.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
			if value is not None:
				src.execute("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, 'x')", (_KEY, value))
			src.commit()
		finally:
			src.close()
		return path

	return make


def test_recovery_adopts_valid_value(conn, alt_db):
	assert recover_missing_global_settings(conn, [alt_db("18")]) == 1
	assert get_setting(conn, _KEY) == "18"
	assert get_peer_stale_months(conn) == 18


@pytest.mark.parametrize("bad", ["0", "121", "abc", "", "-3", "1.5", "²"])
def test_recovery_rejects_invalid_value(conn, alt_db, bad):
	assert recover_missing_global_settings(conn, [alt_db(bad)]) == 0
	assert get_setting(conn, _KEY) is None
	assert get_peer_stale_months(conn) == DEFAULT_PEER_STALE_MONTHS


def test_recovery_does_not_overwrite_local_value(conn, alt_db):
	set_setting(conn, _KEY, "3")
	recover_missing_global_settings(conn, [alt_db("18")])
	assert get_setting(conn, _KEY) == "3"


def test_recovery_without_source_key_creates_nothing(conn, alt_db):
	recover_missing_global_settings(conn, [alt_db(None)])
	assert get_setting(conn, _KEY) is None


def test_defaults_do_not_persist_threshold(conn):
	insert_default_settings(conn)
	assert get_setting(conn, _KEY) is None
	assert get_peer_stale_months(conn) == 6
