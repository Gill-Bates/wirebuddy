#!/usr/bin/env python3
#
# tests/test_peer_tags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Unbound peer-tag regeneration has one policy, whoever triggers it.

A disabled global ad-blocker clears every peer tag, including the custom-rules
tag. Peer edits, startup and the DNS toggle must all reach that same state
rather than depending on which of them ran last.
"""

from __future__ import annotations

import sqlite3

import pytest

from app.api import wireguard_peers
from app.db.sqlite_settings import set_dns_blocklist_enabled
from app.dns import unbound

_PEER = {"peer_address": "10.13.13.2/32", "use_adblocker": 1, "blocklist_ids": None}


@pytest.fixture()
def written(monkeypatch: pytest.MonkeyPatch) -> list[list[dict]]:
	calls: list[list[dict]] = []
	monkeypatch.setattr(unbound, "write_peer_tags", lambda peers: calls.append(list(peers)))
	monkeypatch.setattr(wireguard_peers, "get_all_peers", lambda conn: [_PEER])
	return calls


def test_disabled_adblocker_clears_all_peer_tags(conn: sqlite3.Connection, written):
	set_dns_blocklist_enabled(conn, False)

	wireguard_peers.regenerate_all_peer_tags(conn)

	assert written == [[]]


def test_enabled_adblocker_writes_peer_tags(conn: sqlite3.Connection, written):
	set_dns_blocklist_enabled(conn, True)

	wireguard_peers.regenerate_all_peer_tags(conn)

	assert len(written) == 1
	assert [peer["peer_address"] for peer in written[0]] == ["10.13.13.2/32"]
