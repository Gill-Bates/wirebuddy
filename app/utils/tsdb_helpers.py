#!/usr/bin/env python3
#
# app/utils/tsdb_helpers.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Helpers for mapping and transforming TSDB query points."""

from __future__ import annotations

from typing import Any, Iterable


def build_latest_by_node(points: Iterable[Any]) -> dict[str | None, dict]:
	"""Build node_id -> latest speedtest record mapping from TSDB points.

	Later points overwrite earlier ones to keep the newest record per node.
	node_id is None for master speedtests.
	"""
	latest_by_node: dict[str | None, dict] = {}  # None = master
	for pt in points:
		val = getattr(pt, "value", None)
		ts = getattr(pt, "ts", None)
		if not isinstance(val, dict) or ts is None:
			continue
		node_id = val.get("node_id")
		latest_by_node[node_id] = {
			"ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
			**val,
		}
	return latest_by_node