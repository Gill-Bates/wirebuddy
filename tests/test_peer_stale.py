#!/usr/bin/env python3
#
# tests/test_peer_stale.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Stale peer marker: calendar-month cutoff, persisted threshold, derived-only state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api import wireguard_settings as ws
from app.api.auth import require_admin
from app.db.sqlite_peers import update_peers_last_seen_batch
from app.db.sqlite_settings import DEFAULT_PEER_STALE_MONTHS, get_peer_stale_months, get_setting, set_setting
from app.utils.time import is_peer_stale, subtract_months

_ROOT = Path(__file__).resolve().parent.parent


def _dt(*args: int) -> datetime:
	return datetime(*args, tzinfo=UTC)


def _epoch(*args: int) -> int:
	return int(_dt(*args).timestamp())


def test_factory_default_is_six(threadsafe_conn):
	assert DEFAULT_PEER_STALE_MONTHS == 6
	assert get_peer_stale_months(threadsafe_conn) == 6


def test_threshold_persisted_and_read(threadsafe_conn):
	set_setting(threadsafe_conn, "peer_stale_months", "3")
	assert get_setting(threadsafe_conn, "peer_stale_months") == "3"
	assert get_peer_stale_months(threadsafe_conn) == 3


@pytest.mark.parametrize("raw", ["0", "-1", "121", "abc", ""])
def test_invalid_stored_value_falls_back_to_default(threadsafe_conn, raw):
	set_setting(threadsafe_conn, "peer_stale_months", raw)
	assert get_peer_stale_months(threadsafe_conn) == 6


def test_no_last_seen_is_not_stale():
	now = _dt(2026, 10, 27, 10)
	assert not is_peer_stale(None, 6, now)
	assert not is_peer_stale(0, 6, now)


def test_younger_exact_and_older():
	now = _dt(2026, 10, 27, 10)
	assert not is_peer_stale(_epoch(2026, 4, 27, 10, 0, 1), 6, now)
	assert is_peer_stale(_epoch(2026, 4, 27, 10), 6, now)
	assert is_peer_stale(_epoch(2026, 1, 1), 6, now)


def test_custom_threshold():
	now = _dt(2026, 10, 27, 10)
	seen = _epoch(2026, 7, 27, 10)
	assert is_peer_stale(seen, 3, now)
	assert not is_peer_stale(seen, 4, now)


def test_year_boundary():
	assert subtract_months(_dt(2026, 2, 15, 8), 6) == _dt(2025, 8, 15, 8)
	assert subtract_months(_dt(2026, 1, 15), 1) == _dt(2025, 12, 15)
	assert subtract_months(_dt(2026, 1, 15), 13) == _dt(2024, 12, 15)


@pytest.mark.parametrize(
	("now", "months", "expected"),
	[
		(_dt(2026, 8, 31), 6, _dt(2026, 2, 28)),
		(_dt(2024, 8, 31), 6, _dt(2024, 2, 29)),
		(_dt(2026, 7, 31), 1, _dt(2026, 6, 30)),
		(_dt(2026, 3, 31), 1, _dt(2026, 2, 28)),
	],
)
def test_month_length_clamping(now, months, expected):
	assert subtract_months(now, months) == expected


def test_naive_datetime_rejected():
	with pytest.raises(ValueError):
		subtract_months(datetime(2026, 1, 1), 1)  # noqa: DTZ001 - naive input is the case under test


def test_new_activity_clears_stale():
	now = _dt(2026, 10, 27, 10)
	old = _epoch(2026, 1, 1)
	assert is_peer_stale(old, 6, now)
	assert not is_peer_stale(int(now.timestamp()), 6, now)


def test_last_seen_update_clears_stale_in_db(threadsafe_conn):
	cols = {r["name"] for r in threadsafe_conn.execute("PRAGMA table_info(peers)")}
	assert "last_handshake_at" in cols
	threadsafe_conn.execute("PRAGMA foreign_keys = OFF")
	threadsafe_conn.execute(
		"INSERT INTO peers (name, public_key, private_key, allowed_ips, interface, created_at, updated_at, last_handshake_at) "
		"VALUES ('p', 'PUB', 'PRIV', '10.0.0.2/32', 'wg0', 'x', 'x', ?)",
		(_epoch(2026, 1, 1),),
	)
	threadsafe_conn.commit()
	now = _dt(2026, 10, 27, 10)
	row = threadsafe_conn.execute("SELECT last_handshake_at FROM peers WHERE public_key='PUB'").fetchone()
	assert is_peer_stale(row["last_handshake_at"], 6, now)
	update_peers_last_seen_batch(threadsafe_conn, [("1.2.3.4", int(now.timestamp()), "PUB")])
	row = threadsafe_conn.execute("SELECT last_handshake_at FROM peers WHERE public_key='PUB'").fetchone()
	assert not is_peer_stale(row["last_handshake_at"], 6, now)


def test_no_stale_state_in_schema(threadsafe_conn):
	for table in ("peers", "settings"):
		cols = {r["name"] for r in threadsafe_conn.execute(f"PRAGMA table_info({table})")}
		assert not {c for c in cols if "stale" in c.lower()}
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM settings WHERE key LIKE '%stale%'").fetchone()[0] == 0


def test_only_one_stale_settings_key():
	assert [k for k in ws.WG_SETTING_KEYS if "stale" in k] == ["peer_stale_months"]


@pytest.mark.parametrize("value", [0, -1, 121, "abc", "5", True, 5.5])
def test_payload_rejects_invalid(value):
	with pytest.raises(ValidationError):
		ws.WgSettingsPayload(peer_stale_months=value)


@pytest.mark.parametrize("value", [1, 6, 120])
def test_payload_accepts_bounds(value):
	assert ws.WgSettingsPayload(peer_stale_months=value).peer_stale_months == value


def test_non_admin_rejected():
	with pytest.raises(HTTPException) as exc:
		require_admin({"is_admin": 0})
	assert exc.value.status_code == 403


def test_admin_update_persists_and_clear_restores_default(threadsafe_conn):
	admin = {"is_admin": 1}
	asyncio.run(ws.update_wg_settings(ws.WgSettingsPayload(peer_stale_months=9), admin, threadsafe_conn))
	assert get_peer_stale_months(threadsafe_conn) == 9
	asyncio.run(ws.update_wg_settings(ws.WgSettingsPayload(peer_stale_months=None), admin, threadsafe_conn))
	assert get_peer_stale_months(threadsafe_conn) == 6


def test_ui_references_server_flag_only():
	peers_html = (_ROOT / "app/templates/peers.html").read_text(encoding="utf-8")
	peers_js = (_ROOT / "app/static/js/peers.js").read_text(encoding="utf-8")
	assert "is_stale" in peers_html and "peer-stale-badge" in peers_html
	assert "is_stale" in peers_js
