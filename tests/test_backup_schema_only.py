#!/usr/bin/env python3
#
# tests/test_backup_schema_only.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the schema-and-data (format v2) backup archive.

These tests exercise the pure functions in ``app.api.backup`` without booting
the FastAPI app: schema export, data export, archive creation, tar validation,
manifest handling, TSDB range filtering and the configuration restore.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api import backup


SECRET_KEY = "test-secret-key-0123456789"


def _make_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
            CREATE UNIQUE INDEX idx_users_username ON users(username);
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE VIEW user_count AS SELECT COUNT(*) AS n FROM users;
            INSERT INTO users (username) VALUES ('admin');
            INSERT INTO settings (key, value) VALUES ('secret', 'do-not-export-via-schema');
            """
        )
        conn.commit()
    finally:
        conn.close()


def _open_members(archive: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile():
                stream = tar.extractfile(member)
                assert stream is not None
                out[member.name] = stream.read()
    return out


def _opts(include_tsdb: bool = False, rng: str = "30d") -> backup.BackupCreateOptions:
    return backup.BackupCreateOptions(include_tsdb_metrics=include_tsdb, tsdb_range=rng)


# ─── Schema export ───────────────────────────────────────────────────────────


def test_schema_export_has_ddl_and_no_rows(tmp_path: Path) -> None:
    db = tmp_path / "wirebuddy.db"
    _make_db(db)
    schema = backup._export_sqlite_schema(db)

    assert "CREATE TABLE users" in schema
    assert "CREATE UNIQUE INDEX idx_users_username" in schema
    assert "CREATE VIEW user_count" in schema
    # No row data must appear in the DDL export.
    assert "INSERT" not in schema.upper()
    assert "admin" not in schema
    assert "do-not-export-via-schema" not in schema
    assert "sqlite_" not in schema


# ─── Data export ─────────────────────────────────────────────────────────────


def test_data_export_includes_known_tables_and_rows(tmp_path: Path) -> None:
    db = tmp_path / "wirebuddy.db"
    _make_db(db)
    data_sql = backup._export_sqlite_data(db)

    # The tables that exist in _make_db are users and settings.
    assert "INSERT INTO" in data_sql
    assert "admin" in data_sql
    assert "do-not-export-via-schema" in data_sql
    # Schema DDL must not appear in the data export.
    assert "CREATE TABLE" not in data_sql.upper()


def test_data_export_skips_missing_tables(tmp_path: Path) -> None:
    db = tmp_path / "wirebuddy.db"
    _make_db(db)
    data_sql = backup._export_sqlite_data(db)
    # Tables from _BACKUP_DATA_TABLES that don't exist in _make_db schema
    # (e.g. interfaces, peers, nodes) must not appear.
    assert "interfaces" not in data_sql
    assert "peers" not in data_sql


# ─── Archive creation ─────────────────────────────────────────────────────────


def test_archive_without_tsdb_contains_manifest_schema_and_data(tmp_path: Path) -> None:
    db = tmp_path / "wirebuddy.db"
    _make_db(db)
    archive, filename, size = backup._create_backup_archive(tmp_path, db, SECRET_KEY, _opts())

    try:
        members = _open_members(archive)
        assert set(members) == {"backup.json", "data/schema.sql", "data/data.sql"}
        manifest = json.loads(members["backup.json"])
        assert manifest["format_version"] == 2
        assert manifest["database"] == "schema_and_data"
        assert manifest["include_tsdb_metrics"] is False
        assert manifest["tsdb_range"] is None
        assert filename.startswith("wirebuddy_backup_") and filename.endswith(".tar.gz")
        assert size == archive.stat().st_size
        # data.sql must contain the INSERT for the admin user
        data_sql = members["data/data.sql"].decode()
        assert "admin" in data_sql
        assert "INSERT INTO" in data_sql
    finally:
        archive.unlink(missing_ok=True)


def test_archive_with_tsdb_filters_by_range(tmp_path: Path) -> None:
    db = tmp_path / "wirebuddy.db"
    _make_db(db)

    tsdb = tmp_path / "tsdb" / "network"
    tsdb.mkdir(parents=True)
    now = datetime.now(UTC)
    recent = (now - timedelta(days=3)).isoformat()
    old = (now - timedelta(days=200)).isoformat()
    series = tsdb / "iface_eth0.jsonl"
    series.write_text(
        json.dumps({"ts": old, "value": {"total": 1}}) + "\n"
        + json.dumps({"ts": recent, "value": {"total": 2}}) + "\n",
        encoding="utf-8",
    )
    rotated = tsdb / "iface_eth0.jsonl.000001.gz"
    rotated.write_bytes(gzip.compress((json.dumps({"ts": old, "value": {"total": 0}}) + "\n").encode()))

    archive, _filename, _size = backup._create_backup_archive(tmp_path, db, SECRET_KEY, _opts(True, "30d"))
    try:
        members = _open_members(archive)
        assert "data/data.sql" in members
        assert "data/tsdb/network/iface_eth0.jsonl" in members
        assert "data/tsdb/network/iface_eth0.jsonl.000001.gz" not in members
        lines = members["data/tsdb/network/iface_eth0.jsonl"].decode().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["value"]["total"] == 2
    finally:
        archive.unlink(missing_ok=True)


# ─── Tar validation ───────────────────────────────────────────────────────────


def test_tar_validation_rejects_legacy_members(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.tar.gz"
    with tarfile.open(legacy, mode="w:gz") as tar:
        for name in ("data/wirebuddy.db", "data/certs/cert.pem", "data/dns/unbound.conf"):
            import io
            data = b"x"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    with tarfile.open(legacy, mode="r:gz") as tar:
        with pytest.raises(HTTPException) as exc:
            backup._validate_tar_members(tar)
    assert exc.value.status_code == 400


# ─── Schema SQL validation ────────────────────────────────────────────────────


def test_validate_schema_sql_accepts_and_rejects() -> None:
    backup._validate_schema_sql("CREATE TABLE t (id INTEGER PRIMARY KEY);")
    with pytest.raises(HTTPException):
        backup._validate_schema_sql("this is not valid sql;")
    with pytest.raises(HTTPException):
        backup._validate_schema_sql("   ")


def test_validate_schema_sql_rejects_row_data() -> None:
    with pytest.raises(HTTPException):
        backup._validate_schema_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);\n"
            "INSERT INTO users (username) VALUES ('admin');\n"
        )
    for malicious in (
        "DROP TABLE users;",
        "ATTACH DATABASE 'x.db' AS x;",
        "PRAGMA journal_mode=WAL;",
        "DELETE FROM users;",
    ):
        with pytest.raises(HTTPException):
            backup._validate_schema_sql(malicious)


def test_validate_schema_sql_accepts_trigger_with_dml_body() -> None:
    backup._validate_schema_sql(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER);\n"
        "CREATE TRIGGER bump AFTER INSERT ON t BEGIN\n"
        "  UPDATE t SET n = n + 1 WHERE id = NEW.id;\n"
        "END;\n"
    )


# ─── Data SQL validation ──────────────────────────────────────────────────────


def test_validate_data_sql_accepts_inserts_and_empty() -> None:
    schema = "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);"
    # Valid INSERT
    backup._validate_data_sql(schema, "INSERT INTO \"t\" (\"id\", \"v\") VALUES (1, 'hello');")
    # Empty data is valid (fresh install with no rows)
    backup._validate_data_sql(schema, "")
    backup._validate_data_sql(schema, "   \n  ")


def test_validate_data_sql_rejects_non_insert() -> None:
    schema = "CREATE TABLE t (id INTEGER PRIMARY KEY);"
    for bad in (
        "DROP TABLE t;",
        "CREATE TABLE evil (x TEXT);",
        "UPDATE t SET id = 99;",
        "DELETE FROM t;",
        "ATTACH DATABASE 'x.db' AS x;",
        "PRAGMA journal_mode=DELETE;",
    ):
        with pytest.raises(HTTPException):
            backup._validate_data_sql(schema, bad)


def test_validate_data_sql_rejects_mismatched_table() -> None:
    schema = "CREATE TABLE t (id INTEGER PRIMARY KEY);"
    with pytest.raises(HTTPException):
        backup._validate_data_sql(
            schema,
            "INSERT INTO \"nonexistent\" (\"id\") VALUES (1);",
        )


# ─── Manifest validation ──────────────────────────────────────────────────────


def test_manifest_rejects_missing_and_unsupported(tmp_path: Path) -> None:
    root = tmp_path / "extract"
    (root / "data").mkdir(parents=True)

    with pytest.raises(HTTPException):
        backup._read_backup_manifest(root)  # no manifest

    # format_version=1 (legacy)
    (root / "backup.json").write_text(json.dumps({"format_version": 1}), encoding="utf-8")
    with pytest.raises(HTTPException):
        backup._read_backup_manifest(root)

    # format_version=2 but database="schema_only" (old sub-format)
    (root / "backup.json").write_text(
        json.dumps({
            "format_version": 2,
            "created_at": "2026-06-15T00:00:00+00:00",
            "database": "schema_only",
            "include_tsdb_metrics": False,
        }),
        encoding="utf-8",
    )
    with pytest.raises(HTTPException):
        backup._read_backup_manifest(root)


# ─── Structure validation ─────────────────────────────────────────────────────


def test_extracted_structure_rejects_tsdb_when_manifest_disables_it(tmp_path: Path) -> None:
    extracted = tmp_path / "data"
    (extracted / backup._BACKUP_TSDB_DIRNAME).mkdir(parents=True)
    (extracted / "schema.sql").write_text("CREATE TABLE t (id INTEGER);", encoding="utf-8")
    (extracted / "data.sql").write_text("", encoding="utf-8")

    manifest_off = backup.BackupManifest(
        format_version=2, created_at="2026-06-15T00:00:00+00:00",
        database="schema_and_data", include_tsdb_metrics=False, tsdb_range=None,
    )
    with pytest.raises(HTTPException):
        backup._validate_extracted_backup_structure(extracted, manifest_off)

    manifest_on = backup.BackupManifest(
        format_version=2, created_at="2026-06-15T00:00:00+00:00",
        database="schema_and_data", include_tsdb_metrics=True, tsdb_range="30d",
    )
    backup._validate_extracted_backup_structure(extracted, manifest_on)  # ok


def test_extracted_structure_rejects_missing_data_sql(tmp_path: Path) -> None:
    extracted = tmp_path / "data"
    extracted.mkdir(parents=True)
    (extracted / "schema.sql").write_text("CREATE TABLE t (id INTEGER);", encoding="utf-8")
    # data.sql intentionally absent

    manifest = backup.BackupManifest(
        format_version=2, created_at="2026-06-15T00:00:00+00:00",
        database="schema_and_data", include_tsdb_metrics=False, tsdb_range=None,
    )
    with pytest.raises(HTTPException):
        backup._validate_extracted_backup_structure(extracted, manifest)


# ─── Full restore ─────────────────────────────────────────────────────────────


def test_restore_preserves_configuration_data(tmp_path: Path) -> None:
    """Restore must recreate the schema AND reinsert configuration rows."""
    src_db = tmp_path / "src.db"
    _make_db(src_db)
    schema_sql = backup._export_sqlite_schema(src_db)
    data_sql = backup._export_sqlite_data(src_db)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    live_db = data_dir / "wirebuddy.db"
    _make_db(live_db)  # existing install with different rows

    # Stale WAL/SHM sidecars must be cleared by a successful restore.
    (data_dir / "wirebuddy.db-wal").write_bytes(b"stale-wal")
    (data_dir / "wirebuddy.db-shm").write_bytes(b"stale-shm")

    extracted = tmp_path / "extracted" / "data"
    extracted.mkdir(parents=True)
    (extracted / "schema.sql").write_text(schema_sql, encoding="utf-8")
    (extracted / "data.sql").write_text(data_sql, encoding="utf-8")

    restored = backup._apply_restored_backup(data_dir, live_db, extracted, schema_sql, data_sql)
    assert "wirebuddy.db" in restored

    assert not (data_dir / "wirebuddy.db-wal").exists()
    assert not (data_dir / "wirebuddy.db-shm").exists()

    conn = sqlite3.connect(str(live_db))
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert {"users", "settings"} <= tables
        # Configuration data is restored.
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert conn.execute("SELECT username FROM users").fetchone()[0] == "admin"
        assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1
    finally:
        conn.close()


# ─── Scheduler integration ────────────────────────────────────────────────────


def test_scheduled_backup_uses_persisted_options(tmp_path: Path) -> None:
    """Integration: the scheduler reads include_tsdb/range from settings and the
    produced archive's manifest and members reflect them."""
    from app.db.sqlite_schema import init_schema
    from app.db.sqlite_settings import set_setting

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "wirebuddy.db"

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        init_schema(conn)
        set_setting(conn, backup.SETTING_BACKUP_INCLUDE_TSDB, "1")
        set_setting(conn, backup.SETTING_BACKUP_TSDB_RANGE, "90d")
    finally:
        conn.close()

    series_dir = data_dir / "tsdb" / "network"
    series_dir.mkdir(parents=True)
    (series_dir / "iface_eth0.jsonl").write_text(
        json.dumps({"ts": datetime.now(UTC).isoformat(), "value": {"total": 1}}) + "\n",
        encoding="utf-8",
    )

    result = backup.run_scheduled_backup(data_dir, db_path, SECRET_KEY)
    assert "filename" in result, result

    archive = data_dir / "backup" / result["filename"]
    members = _open_members(archive)
    manifest = json.loads(members["backup.json"])
    assert manifest["database"] == "schema_and_data"
    assert manifest["include_tsdb_metrics"] is True
    assert manifest["tsdb_range"] == "90d"
    assert "data/data.sql" in members
    assert any(name.startswith("data/tsdb/") for name in members)
