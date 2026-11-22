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
from pathlib import Path

import pytest

from app.utils.time import ensure_utc, parse_db_timestamp, parse_utc, to_utc_iso

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


# ─── to_utc_iso (server -> browser wire format) ──────────────────────────────


@pytest.mark.parametrize(
	("value", "expected"),
	[
		(datetime(2026, 6, 15, 12, 0, 0, 123456, tzinfo=UTC), "2026-06-15T12:00:00.123Z"),
		(datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone(timedelta(hours=2))), "2026-06-15T10:00:00.000Z"),
		# Naive datetime and naive-less ISO string with offset both resolve to UTC.
		(datetime(2026, 6, 15, 12, 0, 0), "2026-06-15T12:00:00.000Z"),  # noqa: DTZ001 - naive input is the case under test
		("2026-06-15T12:00:00+02:00", "2026-06-15T10:00:00.000Z"),
		(None, ""),
		("garbage", ""),
	],
)
def test_to_utc_iso(value, expected):
	assert to_utc_iso(value) == expected


def test_templates_do_not_format_datetimes_server_side():
	"""Display formatting belongs to the browser (WBFormat); templates only emit UTC."""
	templates = Path(__file__).resolve().parent.parent / "app" / "templates"
	offenders = [
		f"{path.relative_to(templates)}:{number}"
		for path in templates.rglob("*.html")
		for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
		if ".strftime(" in line
	]
	assert offenders == []


def test_utc_iso_filter_is_registered():
	from app.api.frontend_shared import _jinja_templates

	template = _jinja_templates.env.from_string("{{ value|utc_iso }}")
	assert template.render(value=datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)) == "2026-06-15T12:00:00.000Z"


def test_users_template_uses_utc_iso_filter():
	template = Path(__file__).resolve().parent.parent / "app" / "templates" / "users.html"
	assert "|utc_iso" in template.read_text(encoding="utf-8")


# ─── UTC-only guard ──────────────────────────────────────────────────────────
_APP = Path(__file__).resolve().parent.parent / "app"
_LOCAL_TIME_CALLS = {"localtime", "mktime", "tzset", "ctime", "asctime", "utcfromtimestamp"}


def _local_time_offenders() -> list[str]:
	"""Find calls that read or depend on the process time zone, in addition to Ruff DTZ."""
	import ast

	found: list[str] = []
	for path in sorted(_APP.rglob("*.py")):
		tree = ast.parse(path.read_text(encoding="utf-8"))
		rel = path.relative_to(_APP)
		for node in ast.walk(tree):
			where = f"{rel}:{getattr(node, 'lineno', 0)}"
			if isinstance(node, ast.Call):
				func = node.func
				name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
				keywords = {kw.arg for kw in node.keywords}
				if name in _LOCAL_TIME_CALLS:
					found.append(f"{where} {name}()")
				elif name == "utcnow" and isinstance(func, ast.Attribute) and getattr(func.value, "id", "") in {"datetime", "dt"}:
					found.append(f"{where} datetime.utcnow() is naive")
				elif name in {"now", "today"} and not node.args and "tz" not in keywords:
					found.append(f"{where} {name}() without time zone")
				elif name == "fromtimestamp" and len(node.args) < 2 and "tz" not in keywords:
					found.append(f"{where} fromtimestamp() without time zone")
				elif name == "astimezone" and not node.args and not keywords:
					found.append(f"{where} astimezone() to the local zone")
				elif name in {"getenv", "get"} and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "TZ":
					found.append(f"{where} reads TZ")
			elif isinstance(node, ast.Constant) and isinstance(node.value, str):
				text = node.value
				if "/etc/localtime" in text or "/etc/timezone" in text or ("CURRENT_TIMESTAMP" in text and "CREATE TABLE" not in text):
					found.append(f"{where} {text[:40]!r}")
			elif isinstance(node, ast.ImportFrom | ast.Import):
				modules = [node.module] if isinstance(node, ast.ImportFrom) else [alias.name for alias in node.names]
				if any(m and m.split(".")[0] == "zoneinfo" for m in modules):
					found.append(f"{where} imports zoneinfo")
	return found


def test_app_code_never_depends_on_the_process_time_zone():
	assert _local_time_offenders() == []


def test_guard_detects_local_time_constructs(tmp_path, monkeypatch):
	import sys

	module = sys.modules[__name__]

	bad = tmp_path / "bad.py"
	bad.write_text(
		"import time, os\nfrom datetime import datetime\n"
		"a = datetime.now()\nb = datetime.fromtimestamp(1)\nc = time.localtime()\nd = os.getenv('TZ')\ne = b.astimezone()\n"
		"f = datetime.now(tz=None)\n",
		encoding="utf-8",
	)
	monkeypatch.setattr(module, "_APP", tmp_path)
	found = module._local_time_offenders()
	assert len(found) == 5
	good = tmp_path / "bad.py"
	good.write_text("from datetime import UTC, datetime\na = datetime.now(UTC)\nb = datetime.fromtimestamp(1, UTC)\n", encoding="utf-8")
	assert module._local_time_offenders() == []


def test_schema_version_updated_at_is_written_as_utc(tmp_path):
	import sqlite3

	from app.db.sqlite_runtime import connect
	from app.utils.migration import _ensure_schema_version_table, _set_schema_version

	conn = connect(tmp_path / "t.db")
	try:
		_ensure_schema_version_table(conn)
		_set_schema_version(conn, 3)
		raw = sqlite3.connect(tmp_path / "t.db").execute("SELECT updated_at FROM schema_version").fetchone()[0]
		assert raw.endswith("Z")
		assert parse_utc(raw) is not None
	finally:
		conn.close()


@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "America/New_York", "Pacific/Auckland"])
def test_disable_until_midnight_is_utc_midnight(zone, monkeypatch):
	import time

	from app.api.dns import _next_utc_midnight_epoch

	monkeypatch.setenv("TZ", zone)
	time.tzset()
	try:
		now = int(datetime(2026, 3, 29, 22, 15, 7, tzinfo=UTC).timestamp())
		assert _next_utc_midnight_epoch(now) == int(datetime(2026, 3, 30, tzinfo=UTC).timestamp())
		# Less than 60 s before midnight: pushed to now + 60.
		near = int(datetime(2026, 3, 29, 23, 59, 30, tzinfo=UTC).timestamp())
		assert _next_utc_midnight_epoch(near) == near + 60
		# Exactly at midnight: the following midnight.
		at_midnight = int(datetime(2026, 11, 1, tzinfo=UTC).timestamp())
		assert _next_utc_midnight_epoch(at_midnight) == at_midnight + 86400
	finally:
		monkeypatch.undo()
		time.tzset()


def test_api_user_model_refuses_naive_and_serialises_utc_with_offset():
	"""API instants are never ambiguous: a naive value cannot be built, an aware one keeps its offset."""
	from pydantic import ValidationError

	from app.models.users import UserPublic

	base = {"id": 1, "username": "u", "is_admin": False, "is_active": True, "otp_enabled": False}
	with pytest.raises(ValidationError):
		UserPublic(**base, created_at=datetime(2026, 5, 1, 12, 0, 0))  # noqa: DTZ001 - naive input is the case under test
	dumped = UserPublic(**base, created_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)).model_dump(mode="json")
	assert dumped["created_at"] == "2026-05-01T12:00:00Z"
