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

from app.db.sqlite_auth import (
	_USERNAME_LOCKOUT_POLICY,
	clear_login_attempts,
	is_ip_locked,
	record_failed_login,
)

_FRESH_IP = "203.0.113.99"  # never used to record a failure


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


# ─── policy bounds (independent of the configured values) ────────────────────
#
# The tests above derive everything from `_USERNAME_LOCKOUT_POLICY`, so they
# stay green even if the policy itself regresses to something unsafe (e.g.
# min_failures=1, which would turn the throttle into a single-guess lockout,
# or a max_seconds so large it becomes a durable, DoS-able account lockout).
# These bounds are deliberately independent of the live config.


def test_username_policy_threshold_is_not_trivially_low():
	# A one- or two-attempt threshold would let an attacker lock out the admin
	# account (or trip the throttle for everyone) with a couple of guesses.
	assert _USERNAME_LOCKOUT_POLICY.min_failures >= 10


def test_username_policy_cap_stays_a_brief_throttle():
	# The whole point of a separate, short cap (vs. the per-IP policy's 24h) is
	# that a legitimate admin is never durably locked out. One hour is already
	# generous; regressing towards the 24h IP cap would defeat that guarantee.
	assert 0 < _USERNAME_LOCKOUT_POLICY.max_seconds <= 3600
