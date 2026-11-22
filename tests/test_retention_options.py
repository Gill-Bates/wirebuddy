#!/usr/bin/env python3
#
# tests/test_retention_options.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Retention option sets: TSDB rejects keep-nothing, DNS/speedtest keep it (P3.3).

The TSDB storage layer coerces any retention below 1 day up to 1
(MIN_RETENTION_DAYS), so offering 0 at the setting is dishonest: it would
silently become 1. TSDB must therefore not list 0, while DNS-log and speedtest
retention legitimately support 0 (keep-nothing) and keep it.
"""

from __future__ import annotations

from app.db.sqlite_settings import (
	DNS_LOG_RETENTION_OPTIONS,
	SPEEDTEST_RETENTION_OPTIONS,
	TSDB_RETENTION_OPTIONS,
)


def test_tsdb_retention_excludes_keep_nothing():
	assert 0 not in TSDB_RETENTION_OPTIONS
	# The published long ranges stay available.
	assert TSDB_RETENTION_OPTIONS == (7, 30, 90, 180, 365)


def test_dns_and_speedtest_retention_keep_zero():
	assert 0 in DNS_LOG_RETENTION_OPTIONS
	assert 0 in SPEEDTEST_RETENTION_OPTIONS


# --- Scheduled TSDB cleanup keeps speedtest history (finding 26) ---------------


def _prepare_cleanup(tmp_path, monkeypatch):
	"""Return (db_path, tsdb_dir) with a schema DB and the config pointing at it."""
	from types import SimpleNamespace

	from app.db.sqlite_runtime import close_connection, connect
	from app.db.sqlite_schema import init_schema
	from app.tasks import maintenance

	db_path = tmp_path / "wirebuddy.db"
	tsdb_dir = tmp_path / "tsdb"
	tsdb_dir.mkdir()
	conn = connect(db_path)
	try:
		init_schema(conn)
	finally:
		close_connection(conn)
	monkeypatch.setattr(maintenance, "get_config", lambda: SimpleNamespace(db_path=db_path, tsdb_dir=tsdb_dir))
	return db_path, tsdb_dir


def _seed_old_points(tsdb_dir):
	from datetime import timedelta

	from app.db import tsdb
	from app.utils.time import utcnow

	old = utcnow() - timedelta(days=30)
	for key in ("__speedtest__", "__geo_traffic__"):
		tsdb.append_point(tsdb_dir, peer_key=key, metric="m", value=1, retention_days=365, at=old, sync=True)
	return old


def _count(tsdb_dir, key):
	from app.db import tsdb

	return len(tsdb.query(tsdb_dir, peer_key=key, metric="m", limit=100))


def test_retention_cleanup_keeps_speedtest_history_at_7_days_general_retention(tmp_path, monkeypatch):
	import asyncio

	from app.tasks import maintenance

	_db_path, tsdb_dir = _prepare_cleanup(tmp_path, monkeypatch)
	_seed_old_points(tsdb_dir)
	assert _count(tsdb_dir, "__speedtest__") == 1

	# Defaults: general TSDB 7 days, speedtest 365 days.
	asyncio.run(maintenance.tsdb_retention_cleanup())

	assert _count(tsdb_dir, "__speedtest__") == 1
	assert _count(tsdb_dir, "__geo_traffic__") == 0


def test_retention_cleanup_deletes_nothing_when_retention_read_fails(tmp_path, monkeypatch):
	import asyncio

	import pytest

	from app.tasks import db_inputs, maintenance

	_db_path, tsdb_dir = _prepare_cleanup(tmp_path, monkeypatch)
	_seed_old_points(tsdb_dir)

	def _boom(_conn):
		raise RuntimeError("read failed")

	monkeypatch.setattr(db_inputs, "get_tsdb_retention_days", _boom)
	with pytest.raises(RuntimeError, match="read failed"):
		asyncio.run(maintenance.tsdb_retention_cleanup())

	assert _count(tsdb_dir, "__speedtest__") == 1
	assert _count(tsdb_dir, "__geo_traffic__") == 1
