#!/usr/bin/env python3
#
# tests/test_backup_fk_check.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Foreign-key validation for backup validate + restore (P3.3).

A backup can be structurally valid (passes PRAGMA integrity_check) yet contain
orphaned references, because FK enforcement is intentionally off during import
(circular nodes<->peers reference). These tests lock the explicit
PRAGMA foreign_key_check that both the validator and the restore run.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api import backup

# Schema with a plain (non-circular) FK so an orphan is easy to construct.
_SCHEMA = "CREATE TABLE parent (id INTEGER PRIMARY KEY);\nCREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));\n"
_VALID_DATA = 'INSERT INTO "parent" ("id") VALUES (1);\nINSERT INTO "child" ("id", "parent_id") VALUES (1, 1);\n'
_ORPHAN_DATA = 'INSERT INTO "child" ("id", "parent_id") VALUES (1, 999);\n'


def test_validate_data_sql_accepts_satisfied_fks() -> None:
	backup._validate_data_sql(_SCHEMA, _VALID_DATA)


def test_validate_data_sql_rejects_orphaned_reference() -> None:
	with pytest.raises(HTTPException) as exc:
		backup._validate_data_sql(_SCHEMA, _ORPHAN_DATA)
	assert exc.value.status_code == 400


def _restore(tmp_path: Path, data_sql: str) -> list[str]:
	data_dir = tmp_path / "data"
	data_dir.mkdir()
	live_db = data_dir / "wirebuddy.db"
	# Seed a live DB so the restore has something to roll back to.
	seed = sqlite3.connect(str(live_db))
	try:
		seed.executescript(_SCHEMA)
		seed.commit()
	finally:
		seed.close()

	extracted = tmp_path / "extracted" / "data"
	extracted.mkdir(parents=True)
	(extracted / "schema.sql").write_text(_SCHEMA, encoding="utf-8")
	(extracted / "data.sql").write_text(data_sql, encoding="utf-8")
	return backup._apply_restored_backup(data_dir, live_db, extracted, _SCHEMA, data_sql)


def test_restore_accepts_satisfied_fks(tmp_path: Path) -> None:
	restored = _restore(tmp_path, _VALID_DATA)
	assert "wirebuddy.db" in restored


def test_restore_rejects_orphaned_reference_and_rolls_back(tmp_path: Path) -> None:
	with pytest.raises(Exception):  # noqa: B017 - _apply_restored_backup re-raises after rollback
		_restore(tmp_path, _ORPHAN_DATA)

	# The pre-restore database is restored from rollback, so no orphan row lands.
	live_db = tmp_path / "data" / "wirebuddy.db"
	conn = sqlite3.connect(str(live_db))
	try:
		assert conn.execute("SELECT COUNT(*) FROM child").fetchone()[0] == 0
	finally:
		conn.close()
