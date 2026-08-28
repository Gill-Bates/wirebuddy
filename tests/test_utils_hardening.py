#!/usr/bin/env python3
#
# tests/test_utils_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for assorted utility-layer correctness fixes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from app.utils import version as version_mod
from app.utils.scheduler import Scheduler
from app.utils.tsdb_helpers import build_latest_by_node
from app.utils.vault import decrypt, encrypt, is_encrypted


@dataclass
class _Point:
    """Stand-in for a tsdb MetricPoint."""
    ts: datetime
    value: Any


# ─── build_latest_by_node ────────────────────────────────────────────────────


def test_point_timestamp_wins_over_node_reported_ts():
    """Nodes report their own 'ts' in the value; their clock is not authoritative."""
    recorded = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    points = [_Point(ts=recorded, value={"node_id": "n1", "ts": "1999-01-01T00:00:00+00:00"})]

    assert build_latest_by_node(points)["n1"]["ts"] == recorded.isoformat()


def test_latest_point_per_node_wins():
    older = datetime(2026, 6, 15, 10, 0, tzinfo=timezone.utc)
    newer = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    points = [
        _Point(ts=older, value={"node_id": "n1", "download_mbit": 10}),
        _Point(ts=newer, value={"node_id": "n1", "download_mbit": 90}),
    ]

    latest = build_latest_by_node(points)
    assert latest["n1"]["download_mbit"] == 90
    assert latest["n1"]["ts"] == newer.isoformat()


def test_master_points_key_on_none_and_junk_is_skipped():
    ts = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    points = [
        _Point(ts=ts, value={"download_mbit": 50}),
        _Point(ts=ts, value="not-a-dict"),
        _Point(ts=None, value={"node_id": "n2"}),
    ]

    latest = build_latest_by_node(points)
    assert set(latest) == {None}
    assert latest[None]["download_mbit"] == 50


# ─── vault payload parsing ───────────────────────────────────────────────────


_PEPPER = "x" * 40


def test_roundtrip_encrypt_decrypt():
    assert decrypt(encrypt("s3cret", _PEPPER), _PEPPER) == "s3cret"


def test_non_ascii_token_is_reported_as_a_corrupt_payload():
    """Must not surface as a bare UnicodeEncodeError from the .encode() call."""
    payload = f"vault:2:{'ab' * 16}:tökén"
    with pytest.raises(ValueError, match="Corrupt vault payload"):
        decrypt(payload, _PEPPER)
    assert is_encrypted(payload) is False


def test_wrong_pepper_is_rejected():
    stored = encrypt("s3cret", _PEPPER)
    with pytest.raises(ValueError, match="Cannot decrypt secret"):
        decrypt(stored, "y" * 40)


# ─── version comparison and update cache ─────────────────────────────────────


@pytest.mark.parametrize(
    "current,latest,expected",
    [
        ("1.6.0", "1.7.0", True),
        ("1.6.0", "1.6.0", False),
        ("1.7.0", "1.6.0", False),
        ("1.2", "1.2.0", False),  # same release, differently written
        ("1.2.0", "1.2", False),
        ("dev", "9.9.9", False),
    ],
)
def test_version_comparison(current, latest, expected):
    assert version_mod._is_newer_version(current, latest) is expected


def test_update_check_cache_is_not_mutable_by_callers(monkeypatch):
    """A caller editing the returned dict must not poison later cache hits."""
    monkeypatch.setattr(version_mod, "_UPDATE_CHECK_CACHE", None)
    monkeypatch.setattr(version_mod, "_UPDATE_CHECK_TIME", 0.0)
    monkeypatch.setattr(version_mod, "get_version", lambda: "dev")

    first = version_mod.check_for_updates()
    first["latest_version"] = "9.9.9-tampered"

    assert version_mod.check_for_updates()["latest_version"] != "9.9.9-tampered"


# ─── scheduler job validation ────────────────────────────────────────────────


async def _noop() -> None:
    return None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.5, -1.0])
def test_rejects_invalid_interval(bad):
    with pytest.raises(ValueError, match="interval_seconds"):
        Scheduler().add("job", bad, _noop)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0])
def test_rejects_invalid_initial_delay(bad):
    with pytest.raises(ValueError, match="initial_delay"):
        Scheduler().add("job", 60.0, _noop, initial_delay=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -1.0])
def test_rejects_invalid_timeout(bad):
    with pytest.raises(ValueError, match="timeout"):
        Scheduler().add("job", 60.0, _noop, timeout=bad)


def test_accepts_a_valid_job():
    scheduler = Scheduler()
    scheduler.add("job", 60.0, _noop, initial_delay=5.0, timeout=30.0, jitter_pct=0.1)
    assert [s["name"] for s in scheduler.get_status()] == ["job"]


def test_timeout_none_means_no_limit():
    scheduler = Scheduler()
    scheduler.add("job", 60.0, _noop, timeout=None)
    assert scheduler.get_status()[0]["name"] == "job"
