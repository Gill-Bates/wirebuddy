#!/usr/bin/env python3
#
# tests/test_dashboard_layout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#
# SPDX-License-Identifier: MIT
#

"""Dashboard layout: Pydantic contract, cross-field validation, settings helpers and endpoints.

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
from app.db import sqlite_runtime as rt
from app.db import sqlite_settings as settings
from app.db.sqlite_schema import init_schema


@pytest.fixture()
def mt_conn():
	"""A schema-loaded SQLite connection usable across threads.

	The endpoint handlers run their SQLite work via ``asyncio.to_thread`` (as in production, where
	``get_conn`` opens the connection with ``check_same_thread=False``). The shared ``conn`` fixture
	is thread-checked, so these handler tests use their own cross-thread connection instead.
	"""
	import sqlite3

	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	try:
		yield connection
	finally:
		connection.close()


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
# sqlite_settings helpers
# ---------------------------------------------------------------------------


def test_helper_round_trip(conn):
	layout = {"version": 1, "widgets": [{"id": "kpi-nodes", "x": 0, "y": 0, "w": 3, "h": 2, "visible": True}]}
	settings.set_dashboard_layout(conn, 1, layout)
	assert settings.get_dashboard_layout(conn, 1) == layout


def test_helper_per_user_isolation(conn):
	settings.set_dashboard_layout(conn, 1, {"version": 1, "widgets": []})
	assert settings.get_dashboard_layout(conn, 2) is None
	settings.set_dashboard_layout(conn, 2, {"version": 1, "widgets": [{"id": "peer-map", "x": 0, "y": 0, "w": 6, "h": 8, "visible": True}]})
	assert settings.get_dashboard_layout(conn, 1) == {"version": 1, "widgets": []}


def test_helper_get_absent_is_none(conn):
	assert settings.get_dashboard_layout(conn, 99) is None


def test_helper_get_corrupt_is_none(conn):
	# A non-JSON value stored under the key must read back as None, not raise.
	settings.set_setting(conn, settings._dashboard_layout_key(5), "{not json")
	assert settings.get_dashboard_layout(conn, 5) is None


def test_helper_delete_clears(conn):
	settings.set_dashboard_layout(conn, 1, {"version": 1, "widgets": []})
	assert settings.delete_dashboard_layout(conn, 1) is True
	assert settings.get_dashboard_layout(conn, 1) is None


# ---------------------------------------------------------------------------
# Endpoint handlers (driven directly with the conn fixture + stub user)
# ---------------------------------------------------------------------------


def test_endpoint_get_without_layout_returns_null(mt_conn):
	result = asyncio.run(get_layout(conn=mt_conn, user=_stub_user(1)))
	assert result["data"] == {"layout": None}


def test_endpoint_put_round_trips_through_get(mt_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	put_result = asyncio.run(put_layout(body=body, conn=mt_conn, user=_stub_user(1)))
	assert put_result["data"]["layout"] == body.model_dump()
	get_result = asyncio.run(get_layout(conn=mt_conn, user=_stub_user(1)))
	assert get_result["data"]["layout"] == body.model_dump()


def test_endpoint_put_invalid_does_not_persist(mt_conn):
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="nope", x=0, y=0, w=1, h=1)])
	with pytest.raises(HTTPException) as exc:
		asyncio.run(put_layout(body=body, conn=mt_conn, user=_stub_user(1)))
	assert exc.value.status_code == 422
	assert settings.get_dashboard_layout(mt_conn, 1) is None


def test_endpoint_delete_clears(mt_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	asyncio.run(put_layout(body=body, conn=mt_conn, user=_stub_user(1)))
	del_result = asyncio.run(delete_layout(conn=mt_conn, user=_stub_user(1)))
	assert del_result["data"] == {"layout": None}
	assert asyncio.run(get_layout(conn=mt_conn, user=_stub_user(1)))["data"]["layout"] is None


def test_endpoint_per_user_isolation(mt_conn):
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	asyncio.run(put_layout(body=body, conn=mt_conn, user=_stub_user(1)))
	# User 2 never wrote a layout: their GET is still null.
	assert asyncio.run(get_layout(conn=mt_conn, user=_stub_user(2)))["data"]["layout"] is None


def test_endpoint_put_oversize_payload_is_400(mt_conn, monkeypatch):
	# Force the serialized-size cap to trip so the handler maps ValueError -> HTTP 400 (not 500/422).
	monkeypatch.setattr(settings, "_MAX_JSON_SETTING_LENGTH", 1)
	body = DashboardLayout(version=1, widgets=_all_ids_once())
	with pytest.raises(HTTPException) as exc:
		asyncio.run(put_layout(body=body, conn=mt_conn, user=_stub_user(1)))
	assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Auth required on mutation (end-to-end via TestClient)
# ---------------------------------------------------------------------------


def test_mutation_requires_auth(monkeypatch):
	from fastapi.testclient import TestClient

	from app import main

	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 48)
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
