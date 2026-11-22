#!/usr/bin/env python3
#
# tests/test_conntrack_baseline_commit.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Conntrack sampling must not advance the baseline before a durable write.

``prepare_country_traffic()`` computes deltas without moving ``_ct_prev``; the
caller advances the baseline via ``commit_country_traffic()`` only after the
TSDB write succeeded. A failed aggregation, a crash, or a failed persist must
therefore leave the traffic pending so the next sample re-delivers it instead
of folding it into the baseline and losing it forever.
"""

from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from app.utils import conntrack as ct

_SUBNET = "10.0.0.0/24"
_GATEWAY = "10.0.0.1"

# Two conntrack snapshots for the same flow to a public destination: the second
# shows more bytes, so a delta exists between them.
_LINE_T0 = "tcp 6 src=10.0.0.2 dst=8.8.8.8 sport=1111 dport=443 bytes=100 src=8.8.8.8 dst=10.0.0.2 sport=443 dport=1111 bytes=200"
_LINE_T1 = "tcp 6 src=10.0.0.2 dst=8.8.8.8 sport=1111 dport=443 bytes=500 src=8.8.8.8 dst=10.0.0.2 sport=443 dport=1111 bytes=800"


@pytest.fixture()
def _reset_conntrack():
	ct.reset_state()
	yield
	ct.reset_state()


def _run_pass(lines: list[str], call, deltas_seen: list | None = None):
	"""Run one sampling pass (``call``) with conntrack I/O and aggregation stubbed out.

	Every delta handed to the aggregation is appended to ``deltas_seen`` so a test can
	compare what was delivered on different passes.
	"""
	subnets = [ipaddress.ip_network(_SUBNET)]
	gateways = {ipaddress.ip_address(_GATEWAY)}

	def fake_aggregate(deltas, _mapping=None):
		# Aggregation itself is not under test: any non-empty delta yields a stable country result.
		if deltas_seen is not None:
			deltas_seen.append(list(deltas))
		return ({"xx": {"rx": 1, "tx": 1}}, {}) if deltas else ({}, {})

	with (
		mock.patch.object(ct, "_get_wireguard_subnets", return_value=(subnets, gateways)),
		mock.patch.object(ct, "_read_conntrack_lines", return_value=lines),
		mock.patch.object(ct, "_CONNTRACK_ACCT") as acct,
		mock.patch.object(ct, "_aggregate_traffic", side_effect=fake_aggregate),
		mock.patch.object(ct, "_serialize_agg", side_effect=lambda agg: agg),
	):
		acct.read_text.return_value = "1"
		return call()


def _prepare(lines: list[str], deltas_seen: list | None = None) -> ct.CountrySample:
	return _run_pass(lines, ct.prepare_country_traffic, deltas_seen)


def test_prepare_does_not_advance_baseline_until_commit(_reset_conntrack):
	# First pass records the baseline, delivers nothing.
	first = _prepare([_LINE_T0])
	assert first.is_empty is True
	assert first.checkpoint is None

	# Second pass shows a delta.
	deltas_seen: list = []
	sample = _prepare([_LINE_T1], deltas_seen)
	assert sample.is_empty is False
	assert sample.country  # a delta was computed

	# Simulate a persist failure: the caller never commits. The same snapshot
	# re-delivers the identical delta on the next pass.
	redelivered = _prepare([_LINE_T1], deltas_seen)
	assert redelivered.country == sample.country
	# The aggregation received the same non-empty delta both times, not merely "something non-empty".
	first_delta, second_delta = deltas_seen
	assert first_delta
	assert second_delta == first_delta

	# Only after an explicit commit does the baseline advance, so the next
	# identical pass computes a zero delta and delivers no country traffic.
	assert ct.commit_country_traffic(redelivered.checkpoint) is True
	settled = _prepare([_LINE_T1])
	assert not settled.country


def test_commit_rejects_stale_checkpoint(_reset_conntrack):
	_prepare([_LINE_T0])  # baseline
	sample_a = _prepare([_LINE_T1])
	sample_b = _prepare([_LINE_T1])

	# Committing the newer sample advances the baseline.
	assert ct.commit_country_traffic(sample_b.checkpoint) is True
	# The older sample's checkpoint is now stale and must be refused, so it
	# cannot resurrect an outdated baseline.
	assert ct.commit_country_traffic(sample_a.checkpoint) is False


def test_commit_refused_after_reset(_reset_conntrack):
	_prepare([_LINE_T0])
	sample = _prepare([_LINE_T1])
	ct.reset_state()
	# A reset invalidates any pending commit.
	assert ct.commit_country_traffic(sample.checkpoint) is False


def test_commit_ignores_empty_checkpoint(_reset_conntrack):
	assert ct.commit_country_traffic(None) is False
	assert ct.commit_country_traffic(("bad",)) is False


def test_single_phase_wrapper_still_advances(_reset_conntrack):
	"""sample_country_traffic() keeps its immediate-commit behaviour."""

	def _run(lines):
		return _run_pass(lines, ct.sample_country_traffic)

	_run([_LINE_T0])  # baseline
	country, _asn = _run([_LINE_T1])
	assert country  # delta delivered
	# Single-phase committed immediately, so an identical pass is now empty.
	country2, _asn2 = _run([_LINE_T1])
	assert not country2


def test_failed_asn_write_does_not_double_count_country_bytes(_reset_conntrack, tmp_path, monkeypatch):
	"""Country stored, ASN write fails once: the retry must not store the country bytes again."""
	from app.tasks import scheduled

	written: list[tuple[str, object]] = []
	fail_asn_once = [True]

	def fake_append(_dir, *, peer_key, metric, value, at=None, **_kw):
		if peer_key == ct.ASN_TRAFFIC_KEY and fail_asn_once[0]:
			fail_asn_once[0] = False
			raise OSError("disk full")
		written.append((peer_key, value))

	def fake_aggregate(deltas, _mapping=None):
		return ({"xx": {"rx": 800, "tx": 500}}, {"64500": {"rx": 800, "tx": 500}}) if deltas else ({}, {})

	monkeypatch.setattr(scheduled.tsdb, "append_point", fake_append)
	scheduled._pending_asn_points.clear()
	subnets = [ipaddress.ip_network(_SUBNET)]
	gateways = {ipaddress.ip_address(_GATEWAY)}

	def _pass(line):
		with (
			mock.patch.object(ct, "_get_wireguard_subnets", return_value=(subnets, gateways)),
			mock.patch.object(ct, "_read_conntrack_lines", return_value=[line]),
			mock.patch.object(ct, "_CONNTRACK_ACCT") as acct,
			mock.patch.object(ct, "_aggregate_traffic", side_effect=fake_aggregate),
			mock.patch.object(ct, "_serialize_agg", side_effect=lambda agg: agg),
		):
			acct.read_text.return_value = "1"
			scheduled._flush_pending_asn_points(tmp_path)
			sample = ct.prepare_country_traffic()
			if not sample.is_empty:
				scheduled._persist_country_sample(tmp_path, sample, ct.commit_country_traffic)

	_pass(_LINE_T0)  # baseline
	_pass(_LINE_T1)  # country ok, ASN fails
	_pass(_LINE_T1)  # nothing new; pending ASN point is retried
	_pass(_LINE_T1)

	countries = [v for k, v in written if k == ct.GEO_TRAFFIC_KEY]
	asns = [v for k, v in written if k == ct.ASN_TRAFFIC_KEY]
	assert countries == [{"xx": {"rx": 800, "tx": 500}}]
	assert asns == [{"64500": {"rx": 800, "tx": 500}}]
	assert not scheduled._pending_asn_points


def test_failed_country_write_keeps_baseline_for_redelivery(_reset_conntrack, tmp_path, monkeypatch):
	"""If the country write itself fails nothing is committed, so the sample is re-delivered."""
	from app.tasks import scheduled

	def failing_append(*_a, **_kw):
		raise OSError("disk full")

	monkeypatch.setattr(scheduled.tsdb, "append_point", failing_append)
	scheduled._pending_asn_points.clear()
	_prepare([_LINE_T0])
	sample = _prepare([_LINE_T1])
	with pytest.raises(OSError, match="disk full"):
		scheduled._persist_country_sample(tmp_path, sample, ct.commit_country_traffic)
	assert not _prepare([_LINE_T1]).is_empty
	assert not scheduled._pending_asn_points
