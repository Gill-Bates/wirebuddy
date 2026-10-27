#!/usr/bin/env python3
#
# tests/test_settings_stale_slider.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Static wiring checks: the peer stale threshold is a range slider that sends real months."""

from __future__ import annotations

import re
from pathlib import Path

from app.db.sqlite_settings import PEER_STALE_MONTHS_MAX, PEER_STALE_MONTHS_MIN

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = (ROOT / "app/templates/settings/_tab_wireguard.html").read_text(encoding="utf-8")
SETTINGS_JS = (ROOT / "app/static/js/settings.js").read_text(encoding="utf-8")
SETTINGS_CSS = (ROOT / "app/static/css/pages/settings.css").read_text(encoding="utf-8")


def _stale_input_tag() -> str:
	match = re.search(r"<input\b[^>]*\bid=\"wg-peer-stale-months\"[^>]*>", TEMPLATE, re.DOTALL)
	assert match, "peer stale input missing"
	return match.group(0)


def _ticks() -> list[int]:
	match = re.search(r"PEER_STALE_MONTH_TICKS\s*=\s*\[([^\]]+)\]", SETTINGS_JS)
	assert match, "tick list missing"
	return [int(x) for x in match.group(1).split(",")]


def test_stale_input_is_range_slider():
	tag = _stale_input_tag()
	assert 'type="range"' in tag
	assert 'type="number"' not in tag
	assert "aria-describedby" in tag
	assert re.search(r'<label[^>]*for="wg-peer-stale-months"', TEMPLATE)


def test_slider_range_matches_tick_count():
	tag = _stale_input_tag()
	assert 'min="0"' in tag
	assert f'max="{len(_ticks()) - 1}"' in tag
	label_block = TEMPLATE.split('class="stale-months-labels"', 1)[1].split("</div>", 1)[0]
	assert label_block.count("stale-months-label") == len(_ticks())


def test_ticks_sorted_within_server_bounds_and_include_default():
	ticks = _ticks()
	assert ticks == sorted(set(ticks))
	assert ticks[0] >= PEER_STALE_MONTHS_MIN
	assert ticks[-1] <= PEER_STALE_MONTHS_MAX
	assert 6 in ticks
	assert 'value="2"' in _stale_input_tag() and ticks[2] == 6


def test_label_values_match_ticks():
	label_block = TEMPLATE.split('class="stale-months-labels"', 1)[1].split("</div>", 1)[0]
	labels = [int(x) for x in re.findall(r"stale-months-label\">(\d+)<", label_block)]
	assert labels == _ticks()


def test_save_sends_months_not_slider_index():
	match = re.search(r"payload\.peer_stale_months\s*=\s*(\w+)", SETTINGS_JS)
	assert match
	assert match.group(1) == "peerStaleMonths"
	# the raw slider value must never feed the payload
	assert "peer_stale_months = staleInput" not in SETTINGS_JS


def test_slider_css_exists():
	assert ".stale-months-slider" in SETTINGS_CSS
	assert ".stale-months-label" in SETTINGS_CSS
