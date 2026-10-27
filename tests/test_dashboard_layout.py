#!/usr/bin/env python3
#
# tests/test_dashboard_layout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Dashboard layout: Pydantic contract, cross-field validation, the dashboard_layouts table helpers and endpoints.

The endpoint handlers are driven directly with the shared in-memory ``conn`` fixture and a stub
user row (the design permits this substitution when a full TestClient session is impractical in the
harness). A separate ``TestClient`` check proves an unauthenticated mutation is rejected, so the
auth-required acceptance criterion is still exercised end-to-end.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.dashboard_layout import (
	_DASHBOARD_MAX_Y,
	_DASHBOARD_WIDGETS,
	DashboardLayout,
	DashboardWidgetLayout,
	_validate_dashboard_layout,
	delete_layout,
	get_layout,
	put_layout,
)
from app.db import sqlite_dashboard as dash
from app.db import sqlite_runtime as rt
from app.db.sqlite_schema import init_schema


def _stub_user(user_id: int):
	return {"id": user_id}


def _all_ids_once() -> list[DashboardWidgetLayout]:
	return [DashboardWidgetLayout(id=wid, x=0, y=index, w=1, h=1) for index, wid in enumerate(sorted(_DASHBOARD_WIDGETS))]


# ---------------------------------------------------------------------------
# Pydantic model bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
	"field,value",
	[
		("x", -1),
		("x", 12),
		("y", -1),
		("y", 1001),
		("w", 0),
		("w", 13),
		("h", 0),
		("h", 101),
	],
)
def test_widget_field_bounds_rejected(field, value):
	kwargs = {"id": "kpi-nodes", "x": 0, "y": 0, "w": 1, "h": 1}
	kwargs[field] = value
	with pytest.raises(ValidationError):
		DashboardWidgetLayout(**kwargs)


def test_widget_rejects_extra_field():
	with pytest.raises(ValidationError):
		DashboardWidgetLayout(id="kpi-nodes", x=0, y=0, w=1, h=1, html="<b>no</b>")


@pytest.mark.parametrize("version", [0, 2, -1])
def test_layout_version_pinned_to_one(version):
	with pytest.raises(ValidationError):
		DashboardLayout(version=version, widgets=[])


def test_layout_rejects_more_than_32_widgets():
	widgets = [DashboardWidgetLayout(id="kpi-nodes", x=0, y=i, w=1, h=1) for i in range(33)]
	with pytest.raises(ValidationError):
		DashboardLayout(version=1, widgets=widgets)


def test_layout_rejects_extra_field():
	with pytest.raises(ValidationError):
		DashboardLayout(version=1, widgets=[], extra="x")


# ---------------------------------------------------------------------------
# Cross-field validation
# ---------------------------------------------------------------------------


def test_validation_accepts_all_ids_once():
	_validate_dashboard_layout(DashboardLayout(version=1, widgets=_all_ids_once()))


def test_validation_rejects_unknown_id():
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="nope", x=0, y=0, w=1, h=1)])
	with pytest.raises(HTTPException) as exc:
		_validate_dashboard_layout(body)
	assert exc.value.status_code == 422


def test_validation_rejects_duplicate_id():
	body = DashboardLayout(
		version=1,
		widgets=[
			DashboardWidgetLayout(id="kpi-nodes", x=0, y=0, w=1, h=1),
			DashboardWidgetLayout(id="kpi-nodes", x=0, y=2, w=1, h=1),
		],
	)
	with pytest.raises(HTTPException) as exc:
		_validate_dashboard_layout(body)
	assert exc.value.status_code == 422


def test_validation_rejects_horizontal_overflow():
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="kpi-nodes", x=10, y=0, w=3, h=1)])
	with pytest.raises(HTTPException) as exc:
		_validate_dashboard_layout(body)
	assert exc.value.status_code == 422


def test_validation_rejects_vertical_overflow():
	# y + h must not exceed _DASHBOARD_MAX_Y; y=1000 is in range but y+h=1001 crosses the bound.
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="kpi-nodes", x=0, y=_DASHBOARD_MAX_Y, w=1, h=1)])
	with pytest.raises(HTTPException) as exc:
		_validate_dashboard_layout(body)
	assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# sqlite_dashboard helpers (dashboard_layouts table)
# ---------------------------------------------------------------------------

_ONE = {"id": "kpi-nodes", "x": 0, "y": 0, "w": 3, "h": 2, "visible": True}
_MAP = {"id": "peer-map", "x": 0, "y": 7, "w": 8, "h": 8, "visible": False}


def _add_user(conn, user_id: int) -> None:
	conn.execute(
		"INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, 'x', '2026-01-01 00:00:00')",
		(user_id, f"user{user_id}"),
	)
	conn.commit()


def _layout(*widgets) -> dict:
	return {"version": 1, "widgets": list(widgets)}


def test_helper_round_trip_keeps_order_and_visibility(conn):
	_add_user(conn, 1)
	layout = _layout(_MAP, _ONE)
	dash.set_dashboard_layout(conn, 1, layout)
	assert dash.get_dashboard_layout(conn, 1) == layout


def test_helper_per_user_isolation(conn):
	_add_user(conn, 1)
	_add_user(conn, 2)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	assert dash.get_dashboard_layout(conn, 2) is None
	dash.set_dashboard_layout(conn, 2, _layout(_MAP))
	dash.delete_dashboard_layout(conn, 2)
	assert dash.get_dashboard_layout(conn, 1) == _layout(_ONE)


def test_helper_get_absent_is_none(conn):
	assert dash.get_dashboard_layout(conn, 99) is None


def test_helper_empty_widget_list_reads_back_as_no_layout(conn):
	_add_user(conn, 1)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	dash.set_dashboard_layout(conn, 1, _layout())
	assert dash.get_dashboard_layout(conn, 1) is None


def test_helper_delete_clears(conn):
	_add_user(conn, 1)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	assert dash.delete_dashboard_layout(conn, 1) is True
	assert dash.delete_dashboard_layout(conn, 1) is False
	assert dash.get_dashboard_layout(conn, 1) is None


def test_replace_is_atomic_on_failure(conn):
	# The second widget violates the table CHECK, so the whole replace must roll back to the old rows.
	_add_user(conn, 1)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	bad = _layout(_MAP, {**_ONE, "id": "kpi-traffic"})
	real_valid = dash._widget_valid
	dash._widget_valid = lambda _w: True  # bypass the Python pre-check to reach the DB constraint
	try:
		bad["widgets"][1]["x"] = 11  # x + w = 14 > 12
		with pytest.raises(Exception, match="CHECK"):
			dash.set_dashboard_layout(conn, 1, bad)
	finally:
		dash._widget_valid = real_valid
	assert dash.get_dashboard_layout(conn, 1) == _layout(_ONE)


@pytest.mark.parametrize(
	"widget",
	[{**_ONE, "x": 12}, {**_ONE, "w": 13}, {**_ONE, "x": 10, "w": 3}, {**_ONE, "h": 101}, {**_ONE, "y": 999, "h": 2}, {**_ONE, "id": ""}],
)
def test_table_rejects_out_of_bounds_rows(conn, widget):
	_add_user(conn, 1)
	with pytest.raises(Exception, match="CHECK"):
		conn.execute(
			"INSERT INTO dashboard_layouts (user_id, widget_id, position, x, y, w, h) VALUES (1, ?, 0, ?, ?, ?, ?)",
			(widget["id"], widget["x"], widget["y"], widget["w"], widget["h"]),
		)


def test_user_delete_cascades_only_that_users_layout(conn):
	conn.execute("PRAGMA foreign_keys=ON")  # production connections enable it in sqlite_runtime
	_add_user(conn, 1)
	_add_user(conn, 2)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	dash.set_dashboard_layout(conn, 2, _layout(_MAP))
	conn.execute("DELETE FROM users WHERE id = 1")
	conn.commit()
	assert dash.get_dashboard_layout(conn, 1) is None
	assert dash.get_dashboard_layout(conn, 2) == _layout(_MAP)


def _legacy(conn, user_id, value) -> None:
	conn.execute("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, '2026-01-01 00:00:00')", (f"dashboard_layout:user:{user_id}", value))


def test_migration_moves_valid_drops_invalid_and_orphans(conn, caplog):
	import json

	_add_user(conn, 1)
	_add_user(conn, 2)
	_legacy(conn, 1, json.dumps(_layout(_MAP, _ONE)))
	_legacy(conn, 2, "{not json")
	_legacy(conn, 77, json.dumps(_layout(_ONE)))  # orphaned: no such user
	_legacy(conn, "abc", json.dumps(_layout(_ONE)))  # non-numeric suffix
	conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('unrelated', 'keep', '2026-01-01 00:00:00')")
	with caplog.at_level("WARNING"):
		assert dash.migrate_dashboard_layouts_from_settings(conn) == 1
	assert dash.get_dashboard_layout(conn, 1) == _layout(_MAP, _ONE)
	assert dash.get_dashboard_layout(conn, 2) is None
	assert conn.execute("SELECT COUNT(*) FROM settings WHERE key LIKE 'dashboard_layout:user:%'").fetchone()[0] == 0
	assert conn.execute("SELECT value FROM settings WHERE key = 'unrelated'").fetchone()[0] == "keep"
	assert "unknown user" in caplog.text and "invalid legacy" in caplog.text
	# Idempotent: a second run finds nothing to do.
	assert dash.migrate_dashboard_layouts_from_settings(conn) == 0


def test_migration_does_not_overwrite_existing_table_layout(conn):
	import json

	_add_user(conn, 1)
	dash.set_dashboard_layout(conn, 1, _layout(_ONE))
	_legacy(conn, 1, json.dumps(_layout(_MAP)))
	assert dash.migrate_dashboard_layouts_from_settings(conn) == 0
	assert dash.get_dashboard_layout(conn, 1) == _layout(_ONE)


def test_init_schema_migrates_legacy_rows_on_existing_database(conn):
	import json

	_add_user(conn, 1)
	_legacy(conn, 1, json.dumps(_layout(_ONE)))
	conn.execute("DROP TABLE dashboard_layouts")  # a database from before the table existed
	conn.commit()
	init_schema(conn)
	assert dash.get_dashboard_layout(conn, 1) == _layout(_ONE)


def test_backup_round_trip_restores_layouts(conn, tmp_path):
	import sqlite3

	from app.api import backup

	_add_user(conn, 1)
	dash.set_dashboard_layout(conn, 1, _layout(_MAP, _ONE))
	db = tmp_path / "wirebuddy.db"
	disk = sqlite3.connect(db)
	conn.backup(disk)
	disk.close()
	schema_sql = backup._export_sqlite_schema(db)
	data_sql = backup._export_sqlite_data(db)
	assert "dashboard_layouts" in schema_sql and 'INSERT INTO "dashboard_layouts"' in data_sql
	restored = sqlite3.connect(":memory:")
	restored.row_factory = sqlite3.Row
	restored.executescript(schema_sql)
	restored.executescript(data_sql)
	assert dash.get_dashboard_layout(restored, 1) == _layout(_MAP, _ONE)


def test_restoring_an_old_backup_with_settings_keys_migrates_on_init(tmp_path):
	import json
	import sqlite3

	from app.api import backup

	old = tmp_path / "old.db"
	raw = sqlite3.connect(old)
	raw.executescript(
		"CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at timestamp NOT NULL);"
		"CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);"
		"INSERT INTO users VALUES (1, 'a', 'x', '2026-01-01 00:00:00');"
	)
	raw.execute("INSERT INTO settings VALUES ('dashboard_layout:user:1', ?)", (json.dumps(_layout(_ONE)),))
	raw.commit()
	raw.close()
	schema_sql, data_sql = backup._export_sqlite_schema(old), backup._export_sqlite_data(old)
	fresh = tmp_path / "restored.db"
	target = sqlite3.connect(fresh)
	target.executescript(schema_sql)
	target.executescript(data_sql)
	target.commit()
	target.close()
	rt._ensure_sqlite_adapters()
	reopened = sqlite3.connect(fresh, detect_types=sqlite3.PARSE_DECLTYPES)
	reopened.row_factory = sqlite3.Row
	init_schema(reopened)
	assert dash.get_dashboard_layout(reopened, 1) == _layout(_ONE)
	reopened.close()


# ---------------------------------------------------------------------------
# Endpoint handlers (driven directly with the conn fixture + stub user)
# ---------------------------------------------------------------------------


def test_endpoint_get_without_layout_returns_null(threadsafe_conn):
	result = asyncio.run(get_layout(conn=threadsafe_conn, user=_stub_user(1)))
	assert result["data"] == {"layout": None}


def test_endpoint_put_round_trips_through_get(threadsafe_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	put_result = asyncio.run(put_layout(body=body, conn=threadsafe_conn, user=_stub_user(1)))
	assert put_result["data"]["layout"] == body.model_dump()
	get_result = asyncio.run(get_layout(conn=threadsafe_conn, user=_stub_user(1)))
	assert get_result["data"]["layout"] == body.model_dump()


def test_endpoint_put_invalid_does_not_persist(threadsafe_conn):
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="nope", x=0, y=0, w=1, h=1)])
	with pytest.raises(HTTPException) as exc:
		asyncio.run(put_layout(body=body, conn=threadsafe_conn, user=_stub_user(1)))
	assert exc.value.status_code == 422
	assert dash.get_dashboard_layout(threadsafe_conn, 1) is None


def test_endpoint_delete_clears(threadsafe_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	asyncio.run(put_layout(body=body, conn=threadsafe_conn, user=_stub_user(1)))
	del_result = asyncio.run(delete_layout(conn=threadsafe_conn, user=_stub_user(1)))
	assert del_result["data"] == {"layout": None}
	assert asyncio.run(get_layout(conn=threadsafe_conn, user=_stub_user(1)))["data"]["layout"] is None


def test_endpoint_per_user_isolation(threadsafe_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	asyncio.run(put_layout(body=body, conn=threadsafe_conn, user=_stub_user(1)))
	# User 2 never wrote a layout: their GET is still null.
	assert asyncio.run(get_layout(conn=threadsafe_conn, user=_stub_user(2)))["data"]["layout"] is None


def test_endpoint_put_oversize_payload_is_400(threadsafe_conn, monkeypatch):
	# A storage-layer ValueError must map to HTTP 400 (not 500/422).
	def _boom(*_args):
		raise ValueError("too large")

	monkeypatch.setattr("app.api.dashboard_layout.set_dashboard_layout", _boom)
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	with pytest.raises(HTTPException) as exc:
		asyncio.run(put_layout(body=body, conn=threadsafe_conn, user=_stub_user(1)))
	assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Auth required on mutation (end-to-end via TestClient)
# ---------------------------------------------------------------------------


def test_mutation_requires_auth(monkeypatch, tmp_path):
	from fastapi.testclient import TestClient

	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))  # keep the real data/ untouched
	app = main.create_app()
	client = TestClient(app, raise_server_exceptions=False)
	response = client.put("/api/dashboard/layout", json={"version": 1, "widgets": []})
	# No session and no bearer token: the mutation is rejected before any body validation. A cookie-less
	# request carries no CSRF session, so CSRF lets it through to get_current_user, which raises 401.
	assert response.status_code == 401


def _seed_bearer_session(app) -> str:
	"""Create a user in the app's own DB and mint a bearer token for it.

	Bearer tokens are exempt from the CSRF double-submit check, so a request carrying one reaches the
	route through the real middleware stack and FastAPI's request-body validation runs. The token is
	written to ``app.state.db_path`` — the same database ``get_conn`` opens per request.
	"""
	import secrets

	from app.db.sqlite_auth import create_auth_token
	from app.db.sqlite_runtime import close_connection, connect
	from app.db.sqlite_schema import init_schema
	from app.db.sqlite_users import create_user
	from app.utils.time import utcnow

	token = secrets.token_urlsafe(32)
	conn = connect(app.state.db_path)
	try:
		init_schema(conn)  # create_app does not build the schema; the lifespan would, but we seed directly
		user_id = create_user(conn, "layout-tester", "pw-not-used-for-bearer-auth")
		assert user_id is not None
		now = utcnow()
		create_auth_token(conn, user_id, token, now + timedelta(hours=1), now + timedelta(hours=1))
	finally:
		close_connection(conn)
	return token


def test_authenticated_put_out_of_range_body_is_422(monkeypatch, tmp_path):
	"""An authenticated PUT with an out-of-range field is rejected by FastAPI as 422 over real HTTP.

	This exercises the request-body validation path (Pydantic bounds enforced by FastAPI), which the
	direct-handler tests above cannot reach because they construct the model themselves.
	"""
	from fastapi.testclient import TestClient

	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))  # isolated DB so the seeded user never collides
	app = main.create_app()
	client = TestClient(app, raise_server_exceptions=False)
	token = _seed_bearer_session(app)
	# x = 99 is outside the 0..11 field bound: FastAPI returns 422 before the handler runs.
	response = client.put(
		"/api/dashboard/layout",
		json={"version": 1, "widgets": [{"id": "kpi-nodes", "x": 99, "y": 0, "w": 1, "h": 1}]},
		headers={"Authorization": f"Bearer {token}"},
	)
	assert response.status_code == 422


def _seed_bearer_user(app, username: str) -> str:
	"""Create one more user in the app's own DB and mint a bearer token for it.

	Unlike ``_seed_bearer_session`` this does not re-init the schema (the first caller already did),
	so several users can be seeded into the same database for an isolation check.
	"""
	import secrets

	from app.db.sqlite_auth import create_auth_token
	from app.db.sqlite_runtime import close_connection, connect
	from app.db.sqlite_users import create_user
	from app.utils.time import utcnow

	token = secrets.token_urlsafe(32)
	conn = connect(app.state.db_path)
	try:
		user_id = create_user(conn, username, "pw-not-used-for-bearer-auth")
		assert user_id is not None
		now = utcnow()
		create_auth_token(conn, user_id, token, now + timedelta(hours=1), now + timedelta(hours=1))
	finally:
		close_connection(conn)
	return token


def test_two_session_layout_isolation_over_http(monkeypatch, tmp_path):
	"""User A's PUT layout is invisible to user B over the real HTTP route (acceptance criterion 8).

	The handler-level isolation test above drives the coroutines directly; this one proves the route
	itself resolves the settings key from the *session's* user and never leaks A's row to B.
	"""
	from fastapi.testclient import TestClient

	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))
	app = main.create_app()
	client = TestClient(app, raise_server_exceptions=False)
	token_a = _seed_bearer_session(app)  # inits the schema + seeds user A
	token_b = _seed_bearer_user(app, "layout-tester-b")

	layout = {"version": 1, "widgets": [{"id": "kpi-nodes", "x": 0, "y": 0, "w": 2, "h": 2, "visible": True}]}
	put_a = client.put("/api/dashboard/layout", json=layout, headers={"Authorization": f"Bearer {token_a}"})
	assert put_a.status_code == 200

	get_a = client.get("/api/dashboard/layout", headers={"Authorization": f"Bearer {token_a}"})
	assert get_a.status_code == 200
	assert get_a.json()["data"]["layout"] == layout

	# User B never wrote a layout: their GET over the same route is still null.
	get_b = client.get("/api/dashboard/layout", headers={"Authorization": f"Bearer {token_b}"})
	assert get_b.status_code == 200
	assert get_b.json()["data"]["layout"] is None


def test_cookie_authenticated_put_without_csrf_token_is_403(monkeypatch, tmp_path):
	"""A cookie-authenticated mutation without an X-CSRF-Token is rejected by the CSRF middleware (403).

	Acceptance criterion 7: a browser-style request (session cookie + same-origin) that omits the CSRF
	token must never reach the handler. The bearer tests above cover the token-exempt path; this one
	exercises the cookie-authenticated path through the real middleware stack.
	"""
	from fastapi.testclient import TestClient

	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path))
	app = main.create_app()
	client = TestClient(app, raise_server_exceptions=False)
	token = _seed_bearer_session(app)

	# Present the token as the session cookie (not a bearer header) so the request is cookie-authenticated.
	# With a matching same-origin header but no X-CSRF-Token / csrf_token cookie, the double-submit check
	# fails before the handler runs. base_url is http://testserver, so Origin must match it.
	client.cookies.set("auth_token", token)
	response = client.put(
		"/api/dashboard/layout",
		json={"version": 1, "widgets": []},
		headers={"Origin": "http://testserver"},
	)
	assert response.status_code == 403
