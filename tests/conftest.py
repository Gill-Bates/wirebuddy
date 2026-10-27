#!/usr/bin/env python3
#
# tests/conftest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Shared fixtures for the backend test suite."""

from __future__ import annotations

import sqlite3

import pytest

from app.db import sqlite_runtime as rt
from app.db.sqlite_schema import init_schema


def _open_schema_db(*, check_same_thread: bool) -> sqlite3.Connection:
	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=check_same_thread)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	return connection


@pytest.fixture()
def conn():
	"""A fresh in-memory database with the full application schema."""
	connection = _open_schema_db(check_same_thread=True)
	try:
		yield connection
	finally:
		connection.close()


@pytest.fixture()
def threadsafe_conn():
	"""Like ``conn`` but usable across threadpool hops, as production connections are.

	Handlers that offload SQLite work via ``asyncio.to_thread``/``run_in_threadpool``
	need ``check_same_thread=False``; the plain ``conn`` is single-thread only.
	"""
	connection = _open_schema_db(check_same_thread=False)
	try:
		yield connection
	finally:
		connection.close()
