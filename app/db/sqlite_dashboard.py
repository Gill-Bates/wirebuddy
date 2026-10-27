#!/usr/bin/env python3
#
# app/db/sqlite_dashboard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Per-user dashboard layout storage (one row per placed widget).

The layout lives in its own ``dashboard_layouts`` table instead of a JSON blob in ``settings``: the
bounds are enforced by CHECK constraints, a user's rows disappear with the user (ON DELETE CASCADE)
and a replace is one IMMEDIATE transaction. The public shape stays ``{"version": 1, "widgets": [...]}``.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

# Vertical bound in rows; mirrors _DASHBOARD_MAX_Y in app/api/dashboard_layout.py and the CHECK in
# the dashboard_layouts DDL (sqlite_schema.py), which has to carry the literal.
DASHBOARD_MAX_Y = 1000
LAYOUT_VERSION = 1

# Legacy storage: a JSON blob per user in the settings table, migrated once by the schema step.
_LEGACY_KEY_PREFIX = "dashboard_layout:user:"


def _widget_valid(widget: Any) -> bool:
	"""Return True when *widget* satisfies the same bounds as the table CHECK constraints."""
	if not isinstance(widget, dict):
		return False
	wid = widget.get("id")
	if not isinstance(wid, str) or not 1 <= len(wid) <= 64:
		return False
	values = [widget.get(key) for key in ("x", "y", "w", "h")]
	if any(isinstance(v, bool) or not isinstance(v, int) for v in values):
		return False
	x, y, w, h = values
	return 0 <= x <= 11 and 1 <= w <= 12 and x + w <= 12 and y >= 0 and 1 <= h <= 100 and y + h <= DASHBOARD_MAX_Y


def get_dashboard_layout(conn: sqlite3.Connection, user_id: int) -> dict[str, Any] | None:
	"""Return the stored layout for a user, or None when the user has none."""
	rows = conn.execute(
		"SELECT widget_id, x, y, w, h, visible, layout_version FROM dashboard_layouts WHERE user_id = ? ORDER BY position",
		(user_id,),
	).fetchall()
	if not rows:
		return None
	widgets = [{"id": r["widget_id"], "x": r["x"], "y": r["y"], "w": r["w"], "h": r["h"], "visible": bool(r["visible"])} for r in rows]
	return {"version": int(rows[0]["layout_version"]), "widgets": widgets}


def _insert_rows(conn: sqlite3.Connection, user_id: int, layout: dict[str, Any]) -> None:
	conn.executemany(
		"INSERT INTO dashboard_layouts (user_id, widget_id, position, x, y, w, h, visible, layout_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		[
			(user_id, wd["id"], pos, wd["x"], wd["y"], wd["w"], wd["h"], 1 if wd.get("visible", True) else 0, LAYOUT_VERSION)
			for pos, wd in enumerate(layout["widgets"])
		],
	)


def set_dashboard_layout(conn: sqlite3.Connection, user_id: int, layout: dict[str, Any]) -> None:
	"""Replace the user's layout atomically (delete + insert in one IMMEDIATE transaction).

	An empty widget list stores nothing, which reads back as "no stored layout" (the client then uses
	its default). Raises ValueError for a layout the table would reject.
	"""
	widgets = layout.get("widgets")
	if layout.get("version") != LAYOUT_VERSION or not isinstance(widgets, list) or not all(_widget_valid(w) for w in widgets):
		raise ValueError("Invalid dashboard layout")
	if len({w["id"] for w in widgets}) != len(widgets):
		raise ValueError("Duplicate widget id")
	with transaction(conn, immediate=True):
		conn.execute("DELETE FROM dashboard_layouts WHERE user_id = ?", (user_id,))
		_insert_rows(conn, user_id, layout)


def delete_dashboard_layout(conn: sqlite3.Connection, user_id: int) -> bool:
	"""Delete the user's layout. Returns True if any row was removed."""
	with transaction(conn, immediate=True):
		return conn.execute("DELETE FROM dashboard_layouts WHERE user_id = ?", (user_id,)).rowcount > 0


def migrate_dashboard_layouts_from_settings(conn: sqlite3.Connection) -> int:
	"""Move legacy ``dashboard_layout:user:<id>`` settings rows into the table (idempotent).

	Runs inside the caller's schema transaction. Valid blobs of existing users are inserted (never
	over an existing table layout); invalid, orphaned or unparsable ones are logged and dropped with
	the rest, so the migration neither repeats nor can fail startup. Returns the number migrated.
	"""
	legacy = conn.execute("SELECT key, value FROM settings WHERE key LIKE ?", (_LEGACY_KEY_PREFIX + "%",)).fetchall()
	migrated = 0
	for row in legacy:
		key = row["key"]
		suffix = key[len(_LEGACY_KEY_PREFIX) :]
		try:
			user_id = int(suffix)
			blob = json.loads(row["value"])
			widgets = blob.get("widgets") if isinstance(blob, dict) else None
			valid = (
				blob.get("version") == LAYOUT_VERSION
				and isinstance(widgets, list)
				and all(_widget_valid(w) for w in widgets)
				and len({w["id"] for w in widgets}) == len(widgets)
			)
		except (ValueError, TypeError, AttributeError):
			valid = False
			user_id = -1
		if not valid:
			_log.warning("Dropping invalid legacy dashboard layout %s", key)
		elif conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
			_log.warning("Dropping legacy dashboard layout of unknown user: %s", key)
		elif conn.execute("SELECT 1 FROM dashboard_layouts WHERE user_id = ? LIMIT 1", (user_id,)).fetchone() is None:
			_insert_rows(conn, user_id, blob)
			migrated += 1
		conn.execute("DELETE FROM settings WHERE key = ?", (key,))
	if legacy:
		_log.info("Dashboard layout migration: %d of %d legacy row(s) moved to dashboard_layouts", migrated, len(legacy))
	return migrated
