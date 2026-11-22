#!/usr/bin/env python3
#
# app/utils/logging_setup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application logging binding over the shared ``gillbates-logging`` package.

The package owns the line format, stream routing and colour. This module adds
the WireBuddy-specific parts: humanized aiosqlite debug messages, the uvicorn
logger wiring and the static-file access-log downgrade.
"""

from __future__ import annotations

import logging

from gillbates_logging import LineLog

__all__ = ["setup_logging"]

LOG = LineLog("wirebuddy")

_PREPARED_RECORD_ATTR = "_wirebuddy_prepared"
_QUIET_LOGGERS = ("aiosqlite", "hpack", "watchfiles", "python_multipart", "python_multipart.multipart")


def _humanize_aiosqlite_message(message: str) -> str:
	"""Rewrite low-signal aiosqlite debug messages into readable text."""

	def _describe_operation(operation: str) -> tuple[str, str]:
		known_operations = (
			("built-in method close of sqlite3.Connection", "closing SQLite connection", "SQLite connection closed"),
			("built-in method close of sqlite3.Cursor", "closing SQLite cursor", "SQLite cursor closed"),
			("built-in method commit of sqlite3.Connection", "committing SQLite transaction", "SQLite transaction committed"),
			("built-in method rollback of sqlite3.Connection", "rolling back SQLite transaction", "SQLite transaction rolled back"),
			("built-in method execute of sqlite3.Connection", "executing SQLite statement", "SQLite statement executed"),
			("built-in method execute of sqlite3.Cursor", "executing SQLite cursor statement", "SQLite cursor statement executed"),
			("built-in method fetchone of sqlite3.Cursor", "fetching one SQLite row", "SQLite row fetched"),
			("built-in method fetchall of sqlite3.Cursor", "fetching SQLite rows", "SQLite rows fetched"),
			("built-in method close of sqlite3.Blob", "closing SQLite blob handle", "SQLite blob handle closed"),
			("Connection.stop.<locals>.close_and_stop", "stopping SQLite worker thread", "SQLite worker thread stopped"),
			("connect.<locals>.connector", "opening SQLite connection", "SQLite connection opened"),
			("built-in method cursor of sqlite3.Connection", "creating SQLite cursor", "SQLite cursor created"),
		)
		for needle, active_text, done_text in known_operations:
			if needle in operation:
				return active_text, done_text
		return "running SQLite background operation", "SQLite background operation completed"

	if message.startswith("executing "):
		active_text, _ = _describe_operation(message[len("executing ") :])
		return active_text
	if message.startswith("operation ") and message.endswith(" completed"):
		_, done_text = _describe_operation(message[len("operation ") : -len(" completed")])
		return done_text
	if message.startswith("returning exception "):
		return f"SQLite background operation failed: {message[len('returning exception ') :]}"
	return message


class _AiosqliteFilter(logging.Filter):
	"""Rewrite low-signal aiosqlite debug messages in place, once per record."""

	def filter(self, record: logging.LogRecord) -> bool:
		if not getattr(record, _PREPARED_RECORD_ATTR, False):
			setattr(record, _PREPARED_RECORD_ATTR, True)
			record.msg = _humanize_aiosqlite_message(record.getMessage())
			record.args = ()
		return True


class _StaticFileAccessFilter(logging.Filter):
	"""Drop uvicorn access-log records for /static/ paths unless DEBUG is enabled."""

	def filter(self, record: logging.LogRecord) -> bool:
		if "/static/" in record.getMessage():
			if not logging.getLogger("uvicorn.access").isEnabledFor(logging.DEBUG):
				return False
			record.levelno = logging.DEBUG
			record.levelname = "DEBUG"
		return True


def setup_logging(log_level: str) -> None:
	"""Configure unified logging for the entire application (idempotent)."""
	level_name = str(log_level or "INFO").strip().upper()
	valid = isinstance(getattr(logging, level_name, None), int)
	LOG.setup(level_name if valid else "INFO")
	level = getattr(logging, level_name) if valid else logging.INFO
	if not valid:
		logging.getLogger(__name__).warning("Invalid log level %r, falling back to INFO", log_level)
	# Uvicorn loggers use the root handler and level.
	for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
		logger = logging.getLogger(name)
		logger.handlers.clear()
		logger.setLevel(level)
		logger.propagate = True
	access = logging.getLogger("uvicorn.access")
	if not any(isinstance(f, _StaticFileAccessFilter) for f in access.filters):
		access.addFilter(_StaticFileAccessFilter())
	aiosqlite_logger = logging.getLogger("aiosqlite")
	if not any(isinstance(f, _AiosqliteFilter) for f in aiosqlite_logger.filters):
		aiosqlite_logger.addFilter(_AiosqliteFilter())
	for name in _QUIET_LOGGERS:
		logging.getLogger(name).setLevel(logging.WARNING)
