#!/usr/bin/env python3
#
# tests/test_dashboard_widget_registry.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Anti-drift guard: the JS widget registry and the Python allowlist must stay in sync.

This test is the ONLY code that reads dashboard_widgets.js; runtime never does. It implements the
pinned extraction contract from the design (Decision 3) using stdlib ``re`` alone:

1. slice the ``const registry = Object.freeze([ ... ]);`` substring (array terminator is the first
   ``]);`` after the opener — safe because every entry is an ``Object.freeze({ ... })`` object
   literal with no bare ``]``);
2. extract single-quoted ``id:`` literals within that substring;
3. derive the entry count SOLELY from the ``defaultX:`` field (every entry carries exactly one);
4. assert ``len(ids) == entry_count == len(_DASHBOARD_WIDGETS)`` and ``set(ids) == _DASHBOARD_WIDGETS``.

If an entry fails to parse (e.g. double-quoted id, reordered fields), the id count no longer equals
the defaultX count and the test fails loudly rather than passing on a subset.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api.dashboard_layout import (
	_DASHBOARD_WIDGETS,
	DashboardLayout,
	DashboardWidgetLayout,
	_validate_dashboard_layout,
)

_WIDGETS_JS = Path(__file__).resolve().parents[1] / "app" / "static" / "js" / "dashboard_widgets.js"


def _registry_substring() -> str:
	source = _WIDGETS_JS.read_text(encoding="utf-8")
	opener = "const registry = Object.freeze(["
	start = source.index(opener)
	end = source.index("]);", start)
	return source[start:end]


def test_js_registry_matches_python_allowlist():
	substring = _registry_substring()
	ids = re.findall(r"\bid:\s*'([a-z][a-z0-9-]*)'", substring)
	entry_count = len(re.findall(r"\bdefaultX:\s*\d+", substring))

	# No entry failed to parse: a single number for ids, defaultX fields and the backend allowlist.
	assert len(ids) == entry_count == len(_DASHBOARD_WIDGETS)
	# Set equality: the JS ids and the Python frozenset are the exact same set.
	assert set(ids) == _DASHBOARD_WIDGETS


def test_every_registry_id_passes_validation():
	substring = _registry_substring()
	ids = re.findall(r"\bid:\s*'([a-z][a-z0-9-]*)'", substring)
	# Place every id once, stacked vertically so no two overlap and none crosses the grid bounds.
	widgets = [DashboardWidgetLayout(id=wid, x=0, y=index, w=1, h=1, visible=True) for index, wid in enumerate(ids)]
	_validate_dashboard_layout(DashboardLayout(version=1, widgets=widgets))


def test_unknown_registry_id_is_rejected():
	body = DashboardLayout(version=1, widgets=[DashboardWidgetLayout(id="not-a-widget", x=0, y=0, w=1, h=1)])
	with pytest.raises(HTTPException) as excinfo:
		_validate_dashboard_layout(body)
	assert excinfo.value.status_code == 422
