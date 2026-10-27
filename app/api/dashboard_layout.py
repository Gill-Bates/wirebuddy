#!/usr/bin/env python3
#
# app/api/dashboard_layout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Per-user dashboard layout endpoints (GridStack).

The dashboard layout is personal UI config, not server configuration: every endpoint resolves the
row owner from the authenticated user's immutable id (never from input), so a user can only read,
write or delete their own layout. Reads are available to any logged-in user; mutations are the same
auth level (get_current_user) and are CSRF-protected centrally by CSRFMiddleware under /api/.
"""

from __future__ import annotations

import asyncio
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..db.sqlite_dashboard import (
	DASHBOARD_MAX_Y,
	delete_dashboard_layout,
	get_dashboard_layout,
	set_dashboard_layout,
)
from ..utils.deps import get_conn
from .auth import get_current_user
from .response import OkResponse, ok_response

# Server-side allowlist of widget ids the browser may place on the dashboard (a hand-written literal,
# no import-time file IO). Kept in sync with the JS registry in app/static/js/dashboard_widgets.js by
# tests/test_dashboard_widget_registry.py.
_DASHBOARD_WIDGETS = frozenset(
	{
		"kpi-nodes",
		"kpi-connections",
		"kpi-traffic",
		"kpi-bandwidth",
		"network-gauges",
		"speedtest-chart",
		"peer-map",
		"recent-peers",
	}
)
# The dashboard grid's vertical bound in rows, mirroring MAX_Y in app/static/js/dashboard_grid.js. A
# widget must fit within it (y + h <= limit): a layout that cannot be resolved below this bound is
# rejected here, exactly as the client's overlap resolver refuses to push a box past it.
_DASHBOARD_MAX_Y = DASHBOARD_MAX_Y


class DashboardWidgetLayout(BaseModel):
	"""One placed widget. extra="forbid" rejects any DOM/HTML or unknown field."""

	model_config = ConfigDict(extra="forbid")

	id: str = Field(min_length=1, max_length=64)
	x: int = Field(ge=0, le=11)
	# le mirrors _DASHBOARD_MAX_Y (and MAX_Y in dashboard_grid.js); referencing the constant keeps the
	# per-field cap and the cross-field y + h <= _DASHBOARD_MAX_Y check from drifting apart.
	y: int = Field(ge=0, le=_DASHBOARD_MAX_Y)
	w: int = Field(ge=1, le=12)
	h: int = Field(ge=1, le=100)
	visible: bool = True


class DashboardLayout(BaseModel):
	"""The stored layout contract. version is pinned to 1; widgets is capped at 32."""

	model_config = ConfigDict(extra="forbid")

	version: int = Field(ge=1, le=1)
	widgets: list[DashboardWidgetLayout] = Field(max_length=32)


def _validate_dashboard_layout(body: DashboardLayout) -> None:
	"""Reject unknown/duplicate ids and tiles crossing the grid bounds (422).

	Runs after Pydantic's per-field bounds have already passed.
	"""
	ids = [widget.id for widget in body.widgets]
	unknown = sorted(set(ids) - _DASHBOARD_WIDGETS)
	if unknown:
		raise HTTPException(422, f"Unknown widget id(s): {', '.join(unknown)}")
	if len(set(ids)) != len(ids):
		raise HTTPException(422, "Duplicate widget id")
	for widget in body.widgets:
		if widget.x + widget.w > 12:
			raise HTTPException(422, f"Widget {widget.id} extends past the 12-column grid")
		if widget.y + widget.h > _DASHBOARD_MAX_Y:
			raise HTTPException(422, f"Widget {widget.id} extends past the {_DASHBOARD_MAX_Y}-row vertical bound")


router = APIRouter(tags=["dashboard"])


@router.get("/layout", response_model=OkResponse[dict[str, object]])
async def get_layout(
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(get_current_user),
):
	"""Return the current user's stored layout, or {"layout": null} when none is stored."""
	stored = await asyncio.to_thread(get_dashboard_layout, conn, int(user["id"]))
	return ok_response(data={"layout": stored})


@router.put("/layout", response_model=OkResponse[dict[str, object]])
async def put_layout(
	body: DashboardLayout,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(get_current_user),
):
	"""Validate and persist the current user's layout, then return it."""
	_validate_dashboard_layout(body)
	layout = body.model_dump()
	try:
		await asyncio.to_thread(set_dashboard_layout, conn, int(user["id"]), layout)
	except ValueError as exc:
		# A request-size problem, not a schema problem (unreachable given the 32-widget cap and the
		# per-field integer bounds, but it must never surface as a 500).
		raise HTTPException(400, "Layout payload too large") from exc
	return ok_response(data={"layout": layout})


@router.delete("/layout", response_model=OkResponse[dict[str, object]])
async def delete_layout(
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(get_current_user),
):
	"""Delete the current user's stored layout (idempotent)."""
	await asyncio.to_thread(delete_dashboard_layout, conn, int(user["id"]))
	return ok_response(data={"layout": None})
