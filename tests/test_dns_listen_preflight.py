#!/usr/bin/env python3
#
# tests/test_dns_listen_preflight.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the Unbound listen-socket preflight check.

Locks the config parsing and the bind-probe behaviour that turns a bare
"unbound exited with code 1" into a message naming the busy address.
"""

from __future__ import annotations

import socket

import pytest

from app.dns.unbound_process import (
    _parse_listen_sockets,
    _probe_listen_socket,
    _SS_USERS_RE,
)


def test_parses_ipv4_ipv6_and_port():
    conf = """
server:
    interface: 10.13.13.1
    interface: fd13:13:13::1
    port: 5335
    username: "unbound"
"""
    assert _parse_listen_sockets(conf) == (["10.13.13.1", "fd13:13:13::1"], 5335)


def test_port_defaults_to_53_when_absent():
    assert _parse_listen_sockets("server:\n    interface: 10.0.0.1\n") == (["10.0.0.1"], 53)


def test_ignores_comments_and_strips_inline_suffixes():
    conf = """
    # interface: 192.168.1.1
    interface: 10.13.13.1@53
    interface: 10.14.14.1 # secondary
    port: 53 # default
"""
    assert _parse_listen_sockets(conf) == (["10.13.13.1", "10.14.14.1"], 53)


def test_free_port_reports_no_conflict():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    assert _probe_listen_socket("127.0.0.1", free_port) is None


@pytest.mark.parametrize(
    ("sock_type", "proto"),
    [(socket.SOCK_DGRAM, "UDP"), (socket.SOCK_STREAM, "TCP")],
)
def test_busy_port_is_detected(sock_type, proto):
    holder = socket.socket(socket.AF_INET, sock_type)
    try:
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        if sock_type == socket.SOCK_STREAM:
            holder.listen(1)
        result = _probe_listen_socket("127.0.0.1", port)
    finally:
        holder.close()
    assert result is not None
    assert f"127.0.0.1:{port}" in result
    assert proto in result
    assert "already in use" in result


def test_unassigned_address_is_not_a_conflict():
    # TEST-NET-1: never assigned to a local interface, so bind() yields
    # EADDRNOTAVAIL. That means "interface not up yet", not "port taken".
    assert _probe_listen_socket("192.0.2.123", 53) is None


def test_invalid_address_is_ignored():
    assert _probe_listen_socket("not-an-ip", 53) is None


def test_ss_users_regex_extracts_process_and_pid():
    line = (
        'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* '
        'users:(("systemd-resolve",pid=3352536,fd=15))'
    )
    assert _SS_USERS_RE.findall(line) == [("systemd-resolve", "3352536")]
