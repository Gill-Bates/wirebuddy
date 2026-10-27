#!/usr/bin/env python3
#
# tests/test_unbound_binaries.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Unbound binaries are resolved to absolute paths, never launched via PATH (P2.4).

is_unbound_installed() must resolve unbound and unbound-checkconf to absolute
paths from a fixed allowlist and store them; detection fails closed when no
trusted binary exists, so the resolver is never started by a bare name through
a manipulated PATH.
"""

from __future__ import annotations

from app.dns import unbound_process as up


def _reset_cache() -> None:
	up._unbound_installed = None
	up._unbound_bin = None
	up._unbound_checkconf_bin = None


def test_detection_stores_resolved_absolute_paths(monkeypatch):
	_reset_cache()

	def fake_first(candidates):
		first = str(next(iter(candidates)))
		return first if "unbound" in first else None

	monkeypatch.setattr(up, "first_executable", fake_first)

	assert up.is_unbound_installed(refresh=True) is True
	# Absolute paths from the allowlist are stored for the start/checkconf path.
	assert up._unbound_bin == str(up._UNBOUND_BIN_CANDIDATES[0])
	assert up._unbound_checkconf_bin == str(up._UNBOUND_CHECKCONF_BIN_CANDIDATES[0])
	assert up._unbound_bin.startswith("/")
	assert up._unbound_checkconf_bin.startswith("/")


def test_detection_fails_closed_without_trusted_binary(monkeypatch):
	_reset_cache()
	monkeypatch.setattr(up, "first_executable", lambda _candidates: None)

	assert up.is_unbound_installed(refresh=True) is False
	assert up._unbound_bin is None
	assert up._unbound_checkconf_bin is None


def test_detection_fails_closed_when_checkconf_missing(monkeypatch):
	_reset_cache()

	def only_unbound(candidates):
		first = str(next(iter(candidates)))
		# Resolve the resolver but not unbound-checkconf.
		return first if first.endswith("/unbound") else None

	monkeypatch.setattr(up, "first_executable", only_unbound)

	assert up.is_unbound_installed(refresh=True) is False


def test_candidate_lists_are_absolute():
	for candidates in (up._UNBOUND_BIN_CANDIDATES, up._UNBOUND_CHECKCONF_BIN_CANDIDATES, up._PGREP_BIN_CANDIDATES, up._SS_BIN_CANDIDATES):
		assert candidates
		assert all(c.is_absolute() for c in candidates)
