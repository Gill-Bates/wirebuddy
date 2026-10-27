#!/usr/bin/env python3
#
# tests/test_traffic_truncation.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Country/ASN traffic covers the whole requested window.

The endpoints stream every snapshot of the window through
``tsdb.query_bucketed()`` with a merging reducer, so ``MAX_QUERY_POINTS`` no
longer decides completeness. ``truncated``/``effective_hours`` stay in the
response for compatibility and report a complete window.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from app.api.wireguard_stats_country import _aggregate_snapshots, _compute_asn_traffic, _compute_country_traffic, _merge_snapshots
from app.api.wireguard_utils import bytes_to_unit
from app.db import tsdb
from app.utils.conntrack import ASN_TRAFFIC_KEY, ASN_TRAFFIC_METRIC, GEO_TRAFFIC_KEY, GEO_TRAFFIC_METRIC
from app.utils.time import utcnow


def _seed(tmp_path: Path, count: int, *, span_hours: float, snapshot: dict[str, Any] | None = None) -> None:
	"""Append ``count`` snapshot points spread back over ``span_hours``."""
	now = utcnow()
	step = timedelta(hours=span_hours / max(count - 1, 1))
	value = snapshot or {"DE": {"rx": 10, "tx": 20, "peers": ["Alice"]}}
	for i in range(count):
		tsdb.append_point(tmp_path, peer_key=GEO_TRAFFIC_KEY, metric=GEO_TRAFFIC_METRIC, value=value, at=now - step * i)


def _by_code(data) -> dict[str, Any]:
	return {c.code: c for c in data.countries}


def test_window_beyond_point_cap_is_summed_completely(tmp_path: Path):
	# More snapshots than MAX_QUERY_POINTS, spread over ~20 days, queried for 30 days.
	over_cap = tsdb.MAX_QUERY_POINTS + 50
	_seed(tmp_path, over_cap, span_hours=480.0, snapshot={"DE": {"rx": 1_000_000, "tx": 2_000_000, "peers": ["Alice"]}})

	data = _compute_country_traffic(tmp_path, hours=720)

	assert data.requested_hours == 720
	assert data.truncated is False
	assert data.effective_hours == 720.0
	de = _by_code(data)["DE"]
	# Totals must cover every single snapshot, not just the first MAX_QUERY_POINTS.
	assert de.rx == round(bytes_to_unit(over_cap * 1_000_000, data.display_unit), 2)
	assert de.tx == round(bytes_to_unit(over_cap * 2_000_000, data.display_unit), 2)


def test_short_window_effective_hours_equal_requested(tmp_path: Path):
	_seed(tmp_path, 100, span_hours=10.0)

	data = _compute_country_traffic(tmp_path, hours=24)

	assert data.requested_hours == 24
	assert data.truncated is False
	assert data.effective_hours == 24.0


def _varied_snapshots(tmp_path: Path, key: str, metric: str, *, asn: bool) -> None:
	now = utcnow()
	for i in range(60):
		code = ("13335", "15169", "16509")[i % 3] if asn else ("DE", "US", "FR")[i % 3]
		peer = ("Alice", "Bob")[i % 2]
		other = ("Bob", "Carol")[i % 2]
		info: dict[str, Any] = {
			"rx": 1000 * (i + 1),
			"tx": 500 * (i + 1),
			"peers": [peer, other],
			"by_peer": {peer: {"rx": 600 * (i + 1), "tx": 300 * (i + 1)}, other: {"rx": 400 * (i + 1), "tx": 200 * (i + 1)}},
		}
		if asn:
			info["name"] = f"Name-{i}"
		tsdb.append_point(tmp_path, peer_key=key, metric=metric, value={code: info}, at=now - timedelta(minutes=i * 7))


def test_short_range_matches_raw_point_aggregation(tmp_path: Path):
	_varied_snapshots(tmp_path, GEO_TRAFFIC_KEY, GEO_TRAFFIC_METRIC, asn=False)
	since = utcnow() - timedelta(hours=24)
	raw = tsdb.query(tmp_path, peer_key=GEO_TRAFFIC_KEY, metric=GEO_TRAFFIC_METRIC, since=since, limit=tsdb.MAX_QUERY_POINTS)

	for peer in (None, "Alice", "Carol"):
		expected = _aggregate_snapshots(raw, peer)
		data = _compute_country_traffic(tmp_path, hours=24, peer_filter=peer)
		got = _by_code(data)
		assert set(got) == {k for k, v in expected.items() if v["rx"] + v["tx"] > 0}
		for code, info in expected.items():
			assert got[code].peer_names == info["peers"]
		# Compare in raw bytes through the display unit (same rounding on both sides).
		for code, info in expected.items():
			assert got[code].rx == round(bytes_to_unit(info["rx"], data.display_unit), 2)
			assert got[code].tx == round(bytes_to_unit(info["tx"], data.display_unit), 2)


def test_peer_filter_uses_by_peer_and_peers_are_unioned(tmp_path: Path):
	now = utcnow()
	snaps = [
		{"DE": {"rx": 100, "tx": 10, "peers": ["Alice", "Bob"], "by_peer": {"Alice": {"rx": 70, "tx": 7}, "Bob": {"rx": 30, "tx": 3}}}},
		{"DE": {"rx": 200, "tx": 20, "peers": ["Bob", "Carol"], "by_peer": {"Bob": {"rx": 120, "tx": 12}, "Carol": {"rx": 80, "tx": 8}}}},
	]
	for i, snap in enumerate(snaps):
		tsdb.append_point(tmp_path, peer_key=GEO_TRAFFIC_KEY, metric=GEO_TRAFFIC_METRIC, value=snap, at=now - timedelta(minutes=i + 1))

	everyone = _by_code(_compute_country_traffic(tmp_path, hours=1))["DE"]
	assert everyone.peer_names == ["Alice", "Bob", "Carol"]
	assert everyone.peers == 3

	bob = _aggregate_snapshots(
		tsdb.query_bucketed(
			tmp_path,
			peer_key=GEO_TRAFFIC_KEY,
			metric=GEO_TRAFFIC_METRIC,
			bucket_seconds=3600,
			reduce_fn=_merge_snapshots,
		),
		"Bob",
	)
	assert (bob["DE"]["rx"], bob["DE"]["tx"]) == (150, 15)
	assert bob["DE"]["peers"] == ["Bob"]

	alice = _compute_country_traffic(tmp_path, hours=1, peer_filter="Alice")
	assert alice.display_unit == "B"
	assert (_by_code(alice)["DE"].rx, _by_code(alice)["DE"].tx) == (70.0, 7.0)
	assert _compute_country_traffic(tmp_path, hours=1, peer_filter="Nobody").countries == []


def test_asn_name_comes_from_first_snapshot_and_totals_sum(tmp_path: Path):
	now = utcnow()
	for i, name in enumerate(("Oldest", "Newer", "Newest")):
		tsdb.append_point(
			tmp_path,
			peer_key=ASN_TRAFFIC_KEY,
			metric=ASN_TRAFFIC_METRIC,
			value={"13335": {"rx": 100, "tx": 50, "name": name, "peers": ["Alice"]}},
			at=now - timedelta(minutes=10 - i),
		)

	data = _compute_asn_traffic(tmp_path, hours=1)

	assert [a.asn for a in data.asns] == ["13335"]
	assert data.asns[0].name == "Oldest"
	assert (data.asns[0].rx, data.asns[0].tx) == (300.0, 150.0)
	assert data.truncated is False
