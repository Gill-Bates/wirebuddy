#!/usr/bin/env python3
#
# app/api/response.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Common API response helpers."""

from __future__ import annotations

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class OkResponse(BaseModel, Generic[T]):
	"""Typed success envelope for FastAPI response_model declarations."""

	status: Literal["ok"] = "ok"
	message: str | None = None
	data: T | None = None


class ErrorResponse(BaseModel):
	"""Standardized error envelope for API error responses."""

	status: Literal["error"] = "error"
	message: str
	detail: str | None = None


def ok_response(
	*,
	message: str | None = None,
	data: Any = None,
) -> dict[str, Any]:
	"""Build a typed success envelope.

	Returns a plain mapping so legacy handlers annotated as ``dict[...]`` and
	typed ``response_model=OkResponse[T]`` routes can both serialize cleanly.
	Prefer constructing ``OkResponse[T]`` directly when the concrete payload type
	is known at the call site.
	"""
	return OkResponse[Any](message=message, data=data).model_dump()

