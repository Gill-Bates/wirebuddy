#!/usr/bin/env python3
#
# tests/test_scheduled_tasks.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Contracts of the scheduled GeoIP update and the scheduled speedtest around the shared packages."""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import gillbates_speedtest
import pytest

from app.tasks import scheduled
from app.utils import geoip


class _FakeLease:
	def __init__(self) -> None:
		self.success = False

	async def __aenter__(self):
		return self

	async def __aexit__(self, *_exc):
		return False

	def mark_success(self) -> None:
		self.success = True


class _Result(dict):
	confirmed = True


def _ctx(tmp_path):
	return SimpleNamespace(cfg=SimpleNamespace(tsdb_dir=tmp_path, db_path=tmp_path / "wb.db"))


@pytest.fixture(autouse=True)
def _reset_geoip_retry(monkeypatch):
	monkeypatch.setattr(scheduled, "_geoip_retry_pending", False)


# ---------------------------------------------------------------------------
# GeoIP update
# ---------------------------------------------------------------------------
def _run_geoip_update(monkeypatch, usable, confirmed, caplog):
	monkeypatch.setattr(geoip, "refresh_geoip_databases", lambda force=False: (usable, confirmed))
	opened = []
	monkeypatch.setattr(geoip, "eager_init", lambda: opened.append(True))
	with caplog.at_level(logging.INFO, logger=scheduled._log.name):
		asyncio.run(scheduled.update_geoip(SimpleNamespace()))
	return opened


def test_unchanged_valid_pair_is_not_an_error_and_keeps_the_weekly_interval(monkeypatch, caplog):
	opened = _run_geoip_update(monkeypatch, {"city": True, "asn": True}, True, caplog)
	assert opened == [True]
	assert [r.levelno for r in caplog.records] == [logging.INFO]
	assert scheduled.geoip_next_delay(604800.0) == 604800.0


def test_missing_database_is_warned_and_retried_early(monkeypatch, caplog):
	opened = _run_geoip_update(monkeypatch, {"city": False, "asn": False}, False, caplog)
	assert opened == []
	assert any(r.levelno == logging.WARNING and "incomplete" in r.getMessage() for r in caplog.records)
	assert scheduled.geoip_next_delay(604800.0) == scheduled._GEOIP_RETRY_SECONDS


def test_unconfirmed_but_usable_pair_warns_without_early_retry(monkeypatch, caplog):
	_run_geoip_update(monkeypatch, {"city": True, "asn": True}, False, caplog)
	assert any(r.levelno == logging.WARNING for r in caplog.records)
	assert scheduled.geoip_next_delay(604800.0) == 604800.0


def test_retry_flag_clears_after_a_complete_update(monkeypatch, caplog):
	_run_geoip_update(monkeypatch, {"city": True, "asn": False}, False, caplog)
	assert scheduled.geoip_next_delay(604800.0) == scheduled._GEOIP_RETRY_SECONDS
	_run_geoip_update(monkeypatch, {"city": True, "asn": True}, True, caplog)
	assert scheduled.geoip_next_delay(604800.0) == 604800.0


def test_geoip_exception_is_logged_and_retried_early(monkeypatch, caplog):
	def boom(force=False):
		raise OSError("disk")

	monkeypatch.setattr(geoip, "refresh_geoip_databases", boom)
	with caplog.at_level(logging.ERROR, logger=scheduled._log.name):
		asyncio.run(scheduled.update_geoip(SimpleNamespace()))
	assert any(r.levelno == logging.ERROR for r in caplog.records)
	assert scheduled.geoip_next_delay(604800.0) == scheduled._GEOIP_RETRY_SECONDS


def test_refresh_reports_usable_and_confirmed(monkeypatch):
	class _Db:
		def ensure(self, *, force=False):
			return _Result({"city": True, "asn": True})

	monkeypatch.setattr(geoip, "_get_db", _Db)
	assert geoip.refresh_geoip_databases() == ({"city": True, "asn": True}, True)


# ---------------------------------------------------------------------------
# Scheduled speedtest
# ---------------------------------------------------------------------------
def _patch_speedtest(monkeypatch, *, lease=None, acquire_error=None, run=None, append_error=None):
	lease = lease or _FakeLease()
	points: list[dict] = []
	persisted: list[bool] = []

	async def acquire(*_args, **_kwargs):
		if acquire_error is not None:
			raise acquire_error
		return lease

	async def default_run(**_kwargs):
		return {"status": "ok", "download_mbit": 10.0, "upload_mbit": 5.0}

	def append_point(*_args, value, **_kwargs):
		if append_error is not None:
			raise append_error
		points.append(value)

	monkeypatch.setattr(gillbates_speedtest, "acquire_speedtest_run_lease_async", acquire)
	monkeypatch.setattr(gillbates_speedtest, "run_speedtest", run or default_run)
	monkeypatch.setattr(scheduled.tsdb, "append_point", append_point)
	monkeypatch.setattr(scheduled, "_persist_last_run_to_db", lambda _db: persisted.append(True))
	return lease, points, persisted


def test_scheduled_speedtest_success_persists_point_and_marks_lease(monkeypatch, tmp_path):
	lease, points, persisted = _patch_speedtest(monkeypatch)
	asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
	assert lease.success
	assert [p["status"] for p in points] == ["ok"]
	assert persisted == [True]


def test_scheduled_speedtest_busy_lease_is_skipped_quietly(monkeypatch, tmp_path, caplog):
	_patch_speedtest(monkeypatch, acquire_error=gillbates_speedtest.SpeedtestBusyError("busy"))
	with caplog.at_level(logging.INFO, logger=scheduled._log.name):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
	assert [r.levelno for r in caplog.records] == [logging.INFO]


@pytest.mark.parametrize("error", [RuntimeError("lease"), OSError("disk")])
def test_scheduled_speedtest_errors_before_the_run_are_logged_not_raised(monkeypatch, tmp_path, caplog, error):
	_patch_speedtest(monkeypatch, acquire_error=error)
	with caplog.at_level(logging.ERROR, logger=scheduled._log.name):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
	assert any(r.levelno == logging.ERROR and r.exc_info for r in caplog.records)


def test_scheduled_speedtest_error_after_the_run_is_logged_not_raised(monkeypatch, tmp_path, caplog):
	_patch_speedtest(monkeypatch, append_error=OSError("tsdb full"))
	with caplog.at_level(logging.ERROR, logger=scheduled._log.name):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
	assert any(r.levelno == logging.ERROR and r.exc_info for r in caplog.records)


def test_scheduled_speedtest_failed_run_is_logged_and_persisted(monkeypatch, tmp_path, caplog):
	async def failing_run(**_kwargs):
		raise ValueError("bad output")

	lease, points, persisted = _patch_speedtest(monkeypatch, run=failing_run)
	with caplog.at_level(logging.WARNING, logger=scheduled._log.name):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
	assert not lease.success
	assert points == [{"status": "error", "reason": "bad output"}]
	assert persisted == [True]
	assert any("run failed" in r.getMessage() for r in caplog.records)


def test_scheduled_speedtest_does_not_swallow_cancellation(monkeypatch, tmp_path):
	async def cancelled_run(**_kwargs):
		raise asyncio.CancelledError

	_patch_speedtest(monkeypatch, run=cancelled_run)
	with pytest.raises(asyncio.CancelledError):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))


def test_scheduled_speedtest_does_not_swallow_cancellation_before_the_run(monkeypatch, tmp_path):
	_patch_speedtest(monkeypatch, acquire_error=asyncio.CancelledError())
	with pytest.raises(asyncio.CancelledError):
		asyncio.run(scheduled._execute_scheduled_speedtest_run(_ctx(tmp_path)))
