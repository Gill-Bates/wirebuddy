#!/usr/bin/env python3
#
# tests/test_time.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the timezone-aware time utilities.

Locks the documented contract for reading wire/DB timestamps, in particular the
naive-handling policy after consolidating the two former ``_parse_db_timestamp``
helpers (sqlite_auth / sqlite_nodes) onto ``parse_db_timestamp``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

from app.utils.time import ensure_utc, parse_db_timestamp, parse_utc

# ─── parse_utc ───────────────────────────────────────────────────────────────


def test_parse_utc_accepts_z_suffix():
    dt = parse_utc("2026-06-15T12:00:00.000000Z")
    assert dt == datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def test_parse_utc_accepts_offset_and_normalizes_to_utc():
    dt = parse_utc("2026-06-15T12:00:00+02:00")
    assert dt == datetime(2026, 6, 15, 10, 0, 0, tzinfo=UTC)
    assert dt.tzinfo == UTC


def test_parse_utc_preserves_microseconds():
    dt = parse_utc("2026-06-15T12:00:00.123456Z")
    assert dt.microsecond == 123456


def test_parse_utc_rejects_naive_string():
    assert parse_utc("2026-06-15T12:00:00") is None


@pytest.mark.parametrize("value", ["", "not-a-date", "2026-13-99T99:99:99Z"])
def test_parse_utc_rejects_invalid(value):
    assert parse_utc(value) is None


# ─── parse_db_timestamp ──────────────────────────────────────────────────────


def test_parse_db_timestamp_none():
    assert parse_db_timestamp(None) is None


def test_parse_db_timestamp_aware_string():
    dt = parse_db_timestamp("2026-06-15T12:00:00.000000Z")
    assert dt == datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def test_parse_db_timestamp_naive_string_is_rejected():
    # Policy: naive strings should never be stored (_adapt_datetime forbids it),
    # so reading one fails closed. This is the converged behavior shared by the
    # auth and nodes call sites.
    assert parse_db_timestamp("2026-06-15T12:00:00") is None


def test_parse_db_timestamp_aware_datetime_passthrough():
    aware = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)
    assert parse_db_timestamp(aware) == aware


def test_parse_db_timestamp_naive_datetime_tolerated_as_utc():
    naive = datetime(2026, 6, 15, 12, 0, 0)  # noqa: DTZ001 - naive input is the case under test
    assert parse_db_timestamp(naive) == datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def test_parse_db_timestamp_normalizes_aware_to_utc():
    # A non-UTC aware datetime is converted to UTC so callers get a consistent
    # representation regardless of whether SQLite returned a str or a datetime.
    plus_two = timezone(timedelta(hours=2))
    value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=plus_two)
    parsed = parse_db_timestamp(value)
    assert parsed == datetime(2026, 6, 15, 10, 0, 0, tzinfo=UTC)
    assert parsed.tzinfo == UTC


class _NullOffsetTz(tzinfo):
    """A tzinfo that is set but reports no concrete offset (not truly aware)."""

    def utcoffset(self, dt):
        return None

    def tzname(self, dt):
        return "X"

    def dst(self, dt):
        return None


def test_parse_db_timestamp_semi_aware_tzinfo_is_treated_as_naive():
    # tzinfo present but utcoffset() is None -> _is_aware is False, so it is
    # tolerated as UTC rather than blowing up later in astimezone().
    value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=_NullOffsetTz())
    assert parse_db_timestamp(value) == datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def test_ensure_utc_rejects_semi_aware_tzinfo():
    value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=_NullOffsetTz())
    with pytest.raises(ValueError):
        ensure_utc(value)


@pytest.mark.parametrize("value", [12345, 3.14, object(), b"2026-06-15T12:00:00Z"])
def test_parse_db_timestamp_unsupported_types(value):
    assert parse_db_timestamp(value) is None


def test_ensure_utc_rejects_naive():
    with pytest.raises(ValueError):
        ensure_utc(datetime(2026, 6, 15, 12, 0, 0))  # noqa: DTZ001 - naive input is the case under test

def test_parse_db_timestamp_naive_policy_depends_on_representation_by_design():
    """The naive-handling split is deliberate, not an accidental inconsistency.

    A naive ``str`` is rejected because ``_adapt_datetime`` never writes one -
    seeing one means corruption or a foreign write, so failing closed is the
    safe choice. A naive ``datetime`` only ever originates from this process'
    own sqlite3 converter reading back a value *this code* wrote as UTC, so
    tolerating it as UTC does not weaken the guarantee. Same wall-clock value,
    different representation, different trust boundary - this test pins that
    gap so it is not "fixed" into a uniform naive-rejection policy later.
    """
    same_instant = datetime(2026, 6, 15, 12, 0, 0)  # noqa: DTZ001 - naive input is the case under test
    assert parse_db_timestamp(same_instant.isoformat()) is None
    assert parse_db_timestamp(same_instant) == same_instant.replace(tzinfo=UTC)
