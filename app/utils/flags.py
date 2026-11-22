#!/usr/bin/env python3
#
# app/utils/flags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#


"""Country flags served from the SVGs bundled in gillbates-country-flags."""

from __future__ import annotations

from gillbates_country_flags import bundled_flag_path

# Directory URL of the route app.main serves; it sits below /static/, which stays
# reachable without a session and is already exempt from the bootstrap gate.
FLAG_BASE_URL = "/static/flags"


def local_flag_svg(code: str) -> bytes | None:
	"""Return the bundled SVG bytes for ``code``, or ``None`` unless it is a valid bundled code."""
	path = bundled_flag_path(code)
	if path is None:
		return None
	try:
		return path.read_bytes()
	except OSError:
		return None
