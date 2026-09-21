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


@pytest.fixture()
def conn():
	"""A fresh in-memory database with the full application schema."""
	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	try:
		yield connection
	finally:
		connection.close()
