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
_BADGE_PAD_X = 22
_BADGE_PAD_Y = 10
_BADGE_SECTION_SPACING = 18


def _load_font(size: int, variation_name: Optional[str] = None) -> ImageFont.ImageFont:
	"""Load the bundled font with an optional variation, with Pillow fallbacks."""
	try:
		font = ImageFont.truetype(str(_FONT_PATH), size)
		if variation_name and hasattr(font, "set_variation_by_name"):
			font.set_variation_by_name(variation_name)
		return font
	except (AttributeError, OSError, ValueError):
		try:
			return ImageFont.load_default(size=size)
		except TypeError:
			# Pillow < 10.0 does not accept a size argument
			return ImageFont.load_default()


def _draw_node_badge(
	draw: ImageDraw.Draw,
	font: ImageFont.FreeTypeFont,
	node_name: str,
	canvas_w: int,
	y: int,
) -> int:
	"""Draw a rounded node badge (pill shape) centred at the given y position.

	Returns the total height consumed (badge + padding).
	"""
	badge_text = node_name
	text_bbox = font.getbbox(badge_text)
	text_w = text_bbox[2] - text_bbox[0]
	text_h = text_bbox[3] - text_bbox[1]

	pad_x = _BADGE_PAD_X
	pad_y = _BADGE_PAD_Y
	badge_w = text_w + pad_x * 2
	badge_h = text_h + pad_y * 2
	radius = badge_h // 4

	x0 = (canvas_w - badge_w) // 2
	y0 = y
	x1 = x0 + badge_w
	y1 = y0 + badge_h

	# Badge background
	draw.rounded_rectangle(
		[x0, y0, x1, y1],
		radius=radius,
		fill="#000000",
	)

	# Center text using anchor-based alignment for more consistent vertical centering.
	cx = (x0 + x1) // 2
	cy = (y0 + y1) // 2
	draw.text(
		(cx, cy),
		badge_text,
		fill="white",
		font=font,
		anchor="mm",
	)

	return badge_h


def generate_qr_png(
	config_text: str,
	peer_name: str,
	node_name: Optional[str] = None,
) -> bytes:
	"""Render a QR code PNG with an optional logo, peer name, and node badge.

	Layout (top to bottom):
		1. QR code
		2. WireBuddy logo (if ``wirebuddy_1c.png`` exists)
		3. Node badge (if peer is assigned to a remote node)
		4. Peer name label (centred)

	Args:
		config_text: The WireGuard configuration text to encode.
		peer_name: Human-readable peer name rendered below the QR code.
		node_name: Optional node display name. When set, a coloured badge
			is rendered to indicate which node this config targets.

	Returns:
		PNG image bytes.
	"""
	# Sanitise inputs
	peer_name = peer_name or "Peer"
	if len(peer_name) > _MAX_LABEL_LEN:
		peer_name = peer_name[:_MAX_LABEL_LEN - 1] + "…"
	if node_name and len(node_name) > _MAX_LABEL_LEN:
		node_name = node_name[:_MAX_LABEL_LEN - 1] + "…"

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
	font = _load_font(font_size)

	badge_font_size = max(16, font_size * 3 // 4)
	badge_font = _load_font(badge_font_size, variation_name="Bold")

	# --- measure text ---
	text_bbox = font.getbbox(peer_name)
	text_w = text_bbox[2] - text_bbox[0]
	text_h = text_bbox[3] - text_bbox[1]

	# Pre-measure badge height
	badge_section_h = 0
	if node_name:
		badge_text = node_name
		b_bbox = badge_font.getbbox(badge_text)
		b_text_h = b_bbox[3] - b_bbox[1]
		badge_section_h = b_text_h + (_BADGE_PAD_Y * 2) + _BADGE_SECTION_SPACING

	# --- compose final image ---
	padding = 16
	logo_section_h = (logo_img.height + padding) if logo_img else 0
	text_section_h = text_h + padding

	canvas_w = qr_w
	canvas_h = qr_h + logo_section_h + badge_section_h + text_section_h + padding * 2
	canvas = Image.new("RGBA", (canvas_w, canvas_h), "white")

	# Paste QR code at top
	canvas.paste(qr_img, (0, 0))

	y_cursor = qr_h + padding

	# Paste logo centred below QR
	if logo_img:
		logo_x = (canvas_w - logo_img.width) // 2
		canvas.paste(logo_img, (logo_x, y_cursor), logo_img)
		y_cursor += logo_img.height + padding

	draw = ImageDraw.Draw(canvas)

	# Draw node badge below logo (if applicable)
	if node_name:
		badge_h = _draw_node_badge(draw, badge_font, node_name, canvas_w, y_cursor)
		y_cursor += badge_h + _BADGE_SECTION_SPACING

	# Draw peer name centred below badge/logo
	text_x = (canvas_w - text_w) // 2
	draw.text((text_x, y_cursor), peer_name, fill="black", font=font)

	# Convert to RGB (PNG doesn't need alpha, keeps file small)
	canvas = canvas.convert("RGB")

	buffer = io.BytesIO()
	canvas.save(buffer, format="PNG", optimize=True)
	return buffer.getvalue()
