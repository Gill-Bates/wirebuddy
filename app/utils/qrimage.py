#!/usr/bin/env python3
#
# app/utils/qrimage.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""QR code image generation with optional logo and peer name label.

Requires the ``qrcode`` and ``Pillow`` packages.  If they are not
installed, importing this module will fail with ``ImportError`` —
callers should catch that at the import site.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Optional

import qrcode
from PIL import Image, ImageDraw, ImageFont

_log = logging.getLogger(__name__)

# Asset paths resolved relative to the app package
_APP_DIR = Path(__file__).resolve().parent.parent  # …/app
_LOGO_PATH = _APP_DIR / "static" / "img" / "wirebuddy_1c.png"
_FONT_PATH = _APP_DIR / "static" / "vendor" / "fonts" / "RobotoFlex.woff2"

# Layout tunables
_LOGO_SCALE = 0.6  # Logo width relative to QR code width
_MAX_LABEL_LEN = 32  # Truncate peer names beyond this to avoid canvas overflow


def generate_qr_png(config_text: str, peer_name: str) -> bytes:
	"""Render a QR code PNG with an optional logo and peer name label.

	Layout (top to bottom):
		1. QR code
		2. WireBuddy logo (if ``wirebuddy_1c.png`` exists)
		3. Peer name label (centred)

	Args:
		config_text: The WireGuard configuration text to encode.
		peer_name: Human-readable peer name rendered below the QR code.

	Returns:
		PNG image bytes.
	"""
	# Sanitise inputs
	peer_name = peer_name or "Peer"
	if len(peer_name) > _MAX_LABEL_LEN:
		peer_name = peer_name[:_MAX_LABEL_LEN - 1] + "…"

	# version=1 is a minimum hint; fit=True auto-upgrades for larger payloads
	qr = qrcode.QRCode(version=1, box_size=10, border=4)
	qr.add_data(config_text)
	qr.make(fit=True)

	qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
	qr_w, qr_h = qr_img.size

	# --- load logo (optional – graceful fallback) ---
	logo_img: Optional[Image.Image] = None
	if _LOGO_PATH.is_file():
		try:
			with Image.open(_LOGO_PATH) as raw:
				logo_img = raw.convert("RGBA")
			# Scale logo, preserve aspect ratio
			target_w = int(qr_w * _LOGO_SCALE)
			scale = target_w / logo_img.width
			target_h = int(logo_img.height * scale)
			logo_img = logo_img.resize((target_w, target_h), Image.LANCZOS)
		except (OSError, ValueError, SyntaxError):
			_log.warning("Could not load logo from %s", _LOGO_PATH)
			logo_img = None

	# --- load font (optional – graceful fallback) ---
	font_size = max(20, qr_w // 18)
	try:
		font = ImageFont.truetype(str(_FONT_PATH), font_size)
	except (OSError, ValueError):
		try:
			font = ImageFont.load_default(size=font_size)
		except TypeError:
			# Pillow < 10.0 does not accept a size argument
			font = ImageFont.load_default()

	# --- measure text ---
	text_bbox = font.getbbox(peer_name)
	text_w = text_bbox[2] - text_bbox[0]
	text_h = text_bbox[3] - text_bbox[1]

	# --- compose final image ---
	padding = 16
	logo_section_h = (logo_img.height + padding) if logo_img else 0
	text_section_h = text_h + padding

	canvas_w = qr_w
	canvas_h = qr_h + logo_section_h + text_section_h + padding * 2
	canvas = Image.new("RGBA", (canvas_w, canvas_h), "white")

	# Paste QR code at top
	canvas.paste(qr_img, (0, 0))

	y_cursor = qr_h + padding

	# Paste logo centred below QR
	if logo_img:
		logo_x = (canvas_w - logo_img.width) // 2
		canvas.paste(logo_img, (logo_x, y_cursor), logo_img)
		y_cursor += logo_img.height + padding

	# Draw peer name centred below logo
	draw = ImageDraw.Draw(canvas)
	text_x = (canvas_w - text_w) // 2
	draw.text((text_x, y_cursor), peer_name, fill="black", font=font)

	# Convert to RGB (PNG doesn't need alpha, keeps file small)
	canvas = canvas.convert("RGB")

	buffer = io.BytesIO()
	canvas.save(buffer, format="PNG", optimize=True)
	return buffer.getvalue()
