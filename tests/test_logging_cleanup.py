#!/usr/bin/env python3
#
# tests/test_logging_cleanup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#
# SPDX-License-Identifier: MIT
#

"""Characterize logging normalization in app.main."""

import logging

import pytest

from app import main


@pytest.mark.parametrize(("message", "expected"), [
	("executing built-in method commit of sqlite3.Connection", "committing SQLite transaction"),
	("operation built-in method fetchall of sqlite3.Cursor completed", "SQLite rows fetched"),
	("executing future_operation", "running SQLite background operation"),
	("operation future_operation completed", "SQLite background operation completed"),
	("returning exception database locked", "SQLite background operation failed: database locked"),
	("unrecognized message", "unrecognized message"),
	("", ""),
])
def test_humanization_preserves_known_unknown_and_error_messages(message, expected):
	assert main._humanize_aiosqlite_message(message) == expected


@pytest.mark.parametrize("clone", [False, True])
@pytest.mark.parametrize("name", ["app", "aiosqlite"])
def test_main_record_preparation_preserves_clone_and_idempotence(name, clone):
	record = logging.LogRecord(name, logging.INFO, __file__, 1, "executing %s", ("future_operation",), None)
	prepared = main._prepare_log_record(record, clone=clone)
	assert (prepared is not record) == (clone or name == "aiosqlite")
	assert main._prepare_log_record(prepared, clone=clone) is prepared
	assert record.msg == "executing %s"
	assert record.args == ("future_operation",)
	assert prepared.getMessage() == (
		"running SQLite background operation" if name == "aiosqlite" else "executing future_operation"
	)


@pytest.mark.parametrize("formatter_class", [main._HumanizedFormatter, main._ColoredFormatter])
@pytest.mark.parametrize("name", ["app", "aiosqlite"])
def test_main_formatters_leave_source_message_and_level_unchanged(formatter_class, name):
	record = logging.LogRecord(name, logging.INFO, __file__, 1, "returning exception %s", ("locked",), None)
	formatter = formatter_class("%(levelname)s | %(message)s")
	output = formatter.format(record)
	assert "INFO" in output
	assert ("SQLite background operation failed: locked" if name == "aiosqlite" else "returning exception locked") in output
	assert record.levelname == "INFO"
	assert record.msg == "returning exception %s"
	assert record.args == ("locked",)
