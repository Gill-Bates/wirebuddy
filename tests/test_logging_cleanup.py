#!/usr/bin/env python3
#
# tests/test_logging_cleanup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Characterize logging normalization in app.utils.logging_setup."""

import logging

import pytest

from app.utils import logging_setup


@pytest.mark.parametrize(
	("message", "expected"),
	[
		("executing built-in method commit of sqlite3.Connection", "committing SQLite transaction"),
		("operation built-in method fetchall of sqlite3.Cursor completed", "SQLite rows fetched"),
		("executing future_operation", "running SQLite background operation"),
		("operation future_operation completed", "SQLite background operation completed"),
		("returning exception database locked", "SQLite background operation failed: database locked"),
		("unrecognized message", "unrecognized message"),
		("", ""),
	],
)
def test_humanization_preserves_known_unknown_and_error_messages(message, expected):
	assert logging_setup._humanize_aiosqlite_message(message) == expected


def test_aiosqlite_filter_rewrites_only_aiosqlite_once():
	flt = logging_setup._AiosqliteFilter()
	record = logging.LogRecord("aiosqlite", logging.DEBUG, __file__, 1, "executing %s", ("future_operation",), None)
	assert flt.filter(record)
	assert record.getMessage() == "running SQLite background operation"
	assert record.levelname == "DEBUG"
	assert flt.filter(record)
	assert record.getMessage() == "running SQLite background operation"


def test_setup_logging_attaches_filters_once():
	logging_setup.setup_logging("INFO")
	logging_setup.setup_logging("INFO")
	filters = [f for f in logging.getLogger("aiosqlite").filters if isinstance(f, logging_setup._AiosqliteFilter)]
	assert len(filters) == 1


def test_uvicorn_log_config_routes_through_root_handler():
	import logging.config

	from app.server import _UVICORN_LOG_CONFIG, UvicornMessageFilter

	logging_setup.setup_logging("INFO")
	logging.config.dictConfig(_UVICORN_LOG_CONFIG)
	for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
		assert logging.getLogger(name).handlers == []
		assert logging.getLogger(name).propagate
	assert any(isinstance(f, UvicornMessageFilter) for f in logging.getLogger("uvicorn.error").filters)


def _access_record(path: str) -> logging.LogRecord:
	return logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "GET %s HTTP/1.1" 200', ("127.0.0.1", path), None)


@pytest.mark.parametrize(("level", "kept"), [("INFO", False), ("DEBUG", True)])
def test_static_access_lines_are_hidden_at_info_and_kept_at_debug(level, kept):
	logging_setup.setup_logging(level)
	try:
		access = logging.getLogger("uvicorn.access")
		static = _access_record("/static/css/app.css")
		assert bool(access.filter(static)) is kept
		if kept:
			assert static.levelno == logging.DEBUG
			assert static.levelname == "DEBUG"
		page = _access_record("/api/peers")
		assert access.filter(page)
		assert page.levelno == logging.INFO
	finally:
		logging_setup.setup_logging("INFO")
