#!/usr/bin/env python3
#
# app/runtime/logging.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Unified logging configuration for the application.

Provides:
- Colored TTY output with level-based coloring
- Humanized third-party log messages (aiosqlite)
- Consistent formatting across all loggers
"""

from __future__ import annotations

import logging
import sys

# ANSI color codes for log levels (if TTY)
_LOG_COLORS = {
    "DEBUG": "\033[36m",    # Cyan
    "INFO": "\033[32m",     # Green
    "WARNING": "\033[33m",  # Yellow
    "ERROR": "\033[31m",    # Red
    "CRITICAL": "\033[35m", # Magenta
}
_RESET = "\033[0m"


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
        active_text, _ = _describe_operation(message[len("executing "):])
        return active_text
    if message.startswith("operation ") and message.endswith(" completed"):
        _, done_text = _describe_operation(message[len("operation "):-len(" completed")])
        return done_text
    if message.startswith("returning exception "):
        return f"SQLite background operation failed: {message[len('returning exception '):]}"
    return message


def _prepare_log_record(record: logging.LogRecord) -> logging.LogRecord:
    """Clone and normalize a log record before formatting."""
    # Only copy records from loggers that need modification to reduce overhead
    # (issue #16: modifying the shared LogRecord object is not thread-safe).
    if record.name == "aiosqlite":
        record = logging.makeLogRecord(record.__dict__)
        record.msg = _humanize_aiosqlite_message(record.getMessage())
        record.args = ()
    return record


class HumanizedFormatter(logging.Formatter):
    """Formatter that normalizes noisy third-party log messages."""

    def _prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        return _prepare_log_record(record)

    def format(self, record: logging.LogRecord) -> str:
        record = self._prepare(record)
        return super().format(record)


class ColoredFormatter(HumanizedFormatter):
    """Custom formatter that adds color to log levels in TTY."""

    def format(self, record: logging.LogRecord) -> str:
        record = self._prepare(record)
        if record.levelname in _LOG_COLORS:
            record = logging.makeLogRecord(record.__dict__)
            record.levelname = f"{_LOG_COLORS[record.levelname]}{record.levelname:<8}{_RESET}"
        else:
            record = logging.makeLogRecord(record.__dict__)
            record.levelname = f"{record.levelname:<8}"
        return super().format(record)


def setup_logging(log_level: str) -> None:
    """Configure unified logging for the entire application.

    Args:
        log_level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    valid_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    normalized_level = log_level.strip().upper()
    if normalized_level not in valid_levels:
        raise ValueError(f"Invalid log level: {log_level!r}")

    level = valid_levels[normalized_level]
    is_tty = sys.stdout.isatty()

    # Choose formatter based on TTY detection
    if is_tty:
        formatter = ColoredFormatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = HumanizedFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # force=True removes any pre-existing handlers (e.g. from uvicorn)
    # so every logger inherits the same format.
    logging.basicConfig(
        level=level,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    # Apply the formatter to the root logger's handler
    for handler in logging.root.handlers:
        handler.setFormatter(formatter)

    # Make sure uvicorn loggers use the root handler & level
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.setLevel(level)
        logger.propagate = True

    # Quiet down noisy third-party libraries
    for name in ("aiosqlite", "httpcore", "httpx", "hpack", "watchfiles", "python_multipart", "python_multipart.multipart"):
        logger = logging.getLogger(name)
        if name == "aiosqlite" and level <= logging.DEBUG:
            logger.setLevel(level)
        else:
            logger.setLevel(logging.WARNING)
