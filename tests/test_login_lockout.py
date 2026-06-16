#!/usr/bin/env python3
#
# tests/test_login_lockout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for login-attempt throttling, incl. the username-wide policy.

The username-wide throttle slows distributed password guessing against a known
account across rotating IPs, while a high threshold + short cap keep it a brief
throttle rather than a durable, DoS-able account lockout.
"""

from __future__ import annotations

import sqlite3

import pytest

from app.db import sqlite_runtime as rt
from app.db.sqlite_auth import (
	_USERNAME_LOCKOUT_POLICY,
	clear_login_attempts,
	is_ip_locked,
	record_failed_login,
)
from app.db.sqlite_schema import init_schema

_FRESH_IP = "203.0.113.99"  # never used to record a failure


@pytest.fixture()
def conn():
	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	try:
		yield connection
	finally:
		connection.close()


def _fail_from_distinct_ips(conn: sqlite3.Connection, username: str, count: int) -> None:
	for i in range(count):
		record_failed_login(conn, f"10.0.0.{i}", username)


def test_distributed_failures_trip_username_throttle_on_fresh_ip(conn):
	# Each IP stays under its own ip/userip thresholds, but the shared username
	# counter reaches its threshold and locks even a previously-unseen IP.
	_fail_from_distinct_ips(conn, "admin", _USERNAME_LOCKOUT_POLICY.min_failures)

	locked, remaining = is_ip_locked(conn, _FRESH_IP, "admin")
	assert locked
	assert 0 < remaining <= _USERNAME_LOCKOUT_POLICY.max_seconds


def test_below_threshold_does_not_lock(conn):
	_fail_from_distinct_ips(conn, "admin", _USERNAME_LOCKOUT_POLICY.min_failures - 1)
	assert is_ip_locked(conn, _FRESH_IP, "admin")[0] is False


def test_username_throttle_is_bounded_by_cap(conn):
	# Even with many more failures, the lockout never exceeds the short cap,
	# so a legitimate admin is never durably locked out.
	_fail_from_distinct_ips(conn, "admin", _USERNAME_LOCKOUT_POLICY.min_failures + 25)
	locked, remaining = is_ip_locked(conn, _FRESH_IP, "admin")
	assert locked
	assert remaining <= _USERNAME_LOCKOUT_POLICY.max_seconds


def test_successful_login_clears_username_throttle(conn):
	_fail_from_distinct_ips(conn, "admin", _USERNAME_LOCKOUT_POLICY.min_failures)
	assert is_ip_locked(conn, _FRESH_IP, "admin")[0] is True

	# A successful login from any one IP clears all keys for that username.
	clear_login_attempts(conn, "10.0.0.0", "admin")
	assert is_ip_locked(conn, _FRESH_IP, "admin")[0] is False


def test_other_username_is_unaffected(conn):
	_fail_from_distinct_ips(conn, "admin", _USERNAME_LOCKOUT_POLICY.min_failures + 5)
	# A different account is not throttled by attacks on "admin".
	assert is_ip_locked(conn, _FRESH_IP, "bob")[0] is False
