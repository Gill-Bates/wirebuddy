#!/usr/bin/env python3
#
# tests/test_speedtest_api.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#


"""Manual speedtest runs through the API honour the run guard's cooldown (HTTP 429)."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import speedtest as speedtest_api

_OK_RESULT = {
	"status": "ok",
	"server": "Test",
	"server_url": None,
	"country_code": None,
	"download_mbit": 100.0,
	"upload_mbit": 50.0,
	"rtt_ms": 10.0,
	"jitter_ms": 1.0,
}


def _run_manual(monkeypatch, tmp_path, result):
	async def fake_run_speedtest(**_kwargs):
		return dict(result)

	async def fake_persist(*_args, **_kwargs):
		return None

	async def fake_store(*_args, **_kwargs):
		return True

	monkeypatch.setattr(speedtest_api, "run_speedtest", fake_run_speedtest)
	monkeypatch.setattr(speedtest_api, "_persist_speedtest_state", fake_persist)
	monkeypatch.setattr(speedtest_api, "_store_speedtest_result", fake_store)
	cfg = SimpleNamespace(db_path=tmp_path / "wb.db", tsdb_dir=tmp_path)

	async def scenario():
		lease = await speedtest_api._acquire_speedtest_lease(tmp_path)
		session = speedtest_api._SpeedtestStreamSession(stream_id="s", created_at=datetime.now(UTC))
		await speedtest_api._run_speedtest_stream_session(session, cfg, lease)
		try:
			follow_up = await speedtest_api._acquire_speedtest_lease(tmp_path)
		except HTTPException as exc:
			return session, exc.status_code
		await follow_up.arelease()
		return session, None

	return asyncio.run(scenario())


def test_successful_manual_run_starts_cooldown(monkeypatch, tmp_path):
	session, follow_up_status = _run_manual(monkeypatch, tmp_path, _OK_RESULT)
	assert session.result_payload is not None
	assert session.result_payload["status"] == "ok"
	assert follow_up_status == 429


def test_failed_manual_run_leaves_no_cooldown(monkeypatch, tmp_path):
	session, follow_up_status = _run_manual(monkeypatch, tmp_path, {"status": "error", "reason": "librespeed-cli not found"})
	assert session.result_payload is not None
	assert session.result_payload["status"] == "error"
	assert follow_up_status is None


# ─── nightly window scheduling (02:00-04:00 UTC) ─────────────────────────────
_PROCESS_ZONES = ["UTC", "Europe/Berlin", "America/New_York", "Pacific/Auckland"]


@pytest.fixture
def utc_window(monkeypatch):
	"""The window module without jitter; yields a setter for the process ``TZ``."""
	import time

	from app.utils import speedtest_window

	monkeypatch.setattr(speedtest_window.random, "uniform", lambda _a, _b: 0.0)

	def _set_zone(name: str) -> None:
		monkeypatch.setenv("TZ", name)
		time.tzset()

	yield _set_zone
	monkeypatch.undo()
	time.tzset()


@pytest.mark.parametrize("zone", _PROCESS_ZONES)
@pytest.mark.parametrize("start", [(2026, 3, 24), (2026, 3, 5), (2026, 10, 20), (2026, 10, 29)])
def test_daily_speedtest_stays_in_the_utc_night_window(zone, start, utc_window):
	"""Every slot is inside 02:00-04:00 UTC on 10 consecutive UTC days, across EU and US DST changes."""
	from app.tasks import scheduled

	utc_window(zone)
	now = datetime(*start, 2, 5, tzinfo=UTC).timestamp()
	days = []
	for _ in range(10):
		now += scheduled.seconds_until_next_speedtest(now)
		slot = datetime.fromtimestamp(now, UTC)
		days.append(slot.date().toordinal())
		assert 2 <= slot.hour < 4
		assert scheduled._seconds_until_night_window(now_ts=now) == 0.0
	assert days == list(range(days[0], days[0] + 10))


@pytest.mark.parametrize("zone", _PROCESS_ZONES)
def test_speedtest_outside_the_window_waits_for_the_next_window_start(zone, utc_window):
	from app.tasks import scheduled

	utc_window(zone)
	# 10:00 UTC is outside the window: the next slot is the next 02:00 UTC start, not +24 h.
	now = datetime(2026, 6, 15, 10, 0, tzinfo=UTC).timestamp()
	assert scheduled._seconds_until_night_window(now_ts=now) == 16 * 3600.0
	# Inside the window the just-finished run counts for today.
	inside = datetime(2026, 6, 15, 2, 30, tzinfo=UTC).timestamp()
	assert scheduled._seconds_until_night_window(now_ts=inside) == 0.0
	# Late in the window (< min_runtime left): defer to tomorrow.
	late = datetime(2026, 6, 15, 3, 58, tzinfo=UTC).timestamp()
	assert scheduled._seconds_until_night_window(now_ts=late) == 22 * 3600.0 + 2 * 60.0


@pytest.mark.parametrize("zone", _PROCESS_ZONES)
def test_next_day_window_is_the_next_utc_day(zone, utc_window):
	from app.utils.speedtest_window import seconds_until_next_day_window

	utc_window(zone)
	now = datetime(2026, 11, 1, 2, 30, tzinfo=UTC).timestamp()
	assert seconds_until_next_day_window(now_ts=now) == 23.5 * 3600.0


def test_node_last_run_state_is_utc(monkeypatch, tmp_path):
	"""The node daemon stores and compares UTC calendar days, whatever the process zone."""
	import time

	from app.node import daemon

	monkeypatch.setattr(daemon, "DATA_DIR", tmp_path)
	monkeypatch.setenv("TZ", "Pacific/Auckland")
	time.tzset()
	try:
		ts = datetime(2026, 6, 15, 23, 30, tzinfo=UTC).timestamp()  # already 16 June in Auckland
		daemon._write_last_speedtest_run(ts)
		stored = (tmp_path / daemon._SPEEDTEST_LAST_RUN_FILE).read_text(encoding="utf-8").strip()
		assert stored == "2026-06-15"
		assert daemon._read_last_speedtest_run().isoformat() == "2026-06-15"
	finally:
		monkeypatch.undo()
		time.tzset()


def test_node_legacy_last_run_file_does_not_trigger_a_second_run(monkeypatch, tmp_path):
	"""A file written by an older version (local day) written today counts as ran today."""
	import os

	from app.node import daemon

	monkeypatch.setattr(daemon, "DATA_DIR", tmp_path)
	path = tmp_path / daemon._SPEEDTEST_LAST_RUN_FILE
	today = datetime(2026, 6, 15, tzinfo=UTC).date()
	# Legacy: local (UTC+13) day 2026-06-16 written at 2026-06-15 12:00 UTC.
	path.write_text("2026-06-16", encoding="utf-8")
	written = datetime(2026, 6, 15, 12, 0, tzinfo=UTC).timestamp()
	os.utime(path, (written, written))
	assert daemon._ran_speedtest_today(daemon._read_last_speedtest_run(), today) is True
	# A file from the day before does not count.
	earlier = datetime(2026, 6, 14, 3, 0, tzinfo=UTC).timestamp()
	path.write_text("2026-06-14", encoding="utf-8")
	os.utime(path, (earlier, earlier))
	assert daemon._ran_speedtest_today(daemon._read_last_speedtest_run(), today) is False
	# No file: has not run.
	path.unlink()
	assert daemon._ran_speedtest_today(None, today) is False
