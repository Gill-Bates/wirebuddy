#!/usr/bin/env python3
#
# app/utils/request_id.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Request ID middleware for tracing."""

from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class RequestIDMiddleware(BaseHTTPMiddleware):
	"""Add a unique request ID to each request for tracing/debugging."""

	async def dispatch(self, request: Request, call_next: Callable) -> Response:
		request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
		
		request.state.request_id = request_id
		
		response = await call_next(request)
		
		response.headers["X-Request-ID"] = request_id
		
		return response
