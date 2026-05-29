#!/usr/bin/env python3
#
# app/utils/request_id.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Request ID middleware for tracing."""

from __future__ import annotations

import re
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class RequestIDMiddleware(BaseHTTPMiddleware):
	"""Add a unique request ID to each request for tracing/debugging."""

	async def dispatch(self, request: Request, call_next: Callable) -> Response:
		raw_request_id = request.headers.get("X-Request-ID", "")
		request_id = raw_request_id if _REQUEST_ID_RE.fullmatch(raw_request_id) else str(uuid.uuid4())
		
		request.state.request_id = request_id
		
		response = await call_next(request)
		
		response.headers["X-Request-ID"] = request_id
		
		return response
