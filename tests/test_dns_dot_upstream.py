#!/usr/bin/env python3
#
# tests/test_dns_dot_upstream.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DoT upstream test: the TCP length prefix may arrive in separate reads."""

from __future__ import annotations

import socket
import ssl
import struct

from app.api.dns import _test_dot_server


class _TrickleSocket:
	"""Fake TLS socket that hands out at most one byte per ``recv`` call."""

	def __init__(self) -> None:
		self._buffer = b""

	def __enter__(self) -> _TrickleSocket:
		return self

	def __exit__(self, *exc: object) -> None:
		return None

	def sendall(self, message: bytes) -> None:
		transaction_id = message[2:4]
		reply = transaction_id + b"\x81\x80" + b"\x00" * 8
		self._buffer = struct.pack(">H", len(reply)) + reply

	def recv(self, size: int) -> bytes:
		chunk, self._buffer = self._buffer[: min(size, 1)], self._buffer[min(size, 1) :]
		return chunk


class _FakeContext:
	check_hostname = True
	verify_mode = ssl.CERT_REQUIRED

	def wrap_socket(self, sock: object, server_hostname: str) -> _TrickleSocket:
		return _TrickleSocket()


def test_length_prefix_split_across_reads_is_accepted(monkeypatch) -> None:
	monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _TrickleSocket())
	monkeypatch.setattr(ssl, "create_default_context", lambda *a, **k: _FakeContext())

	result = _test_dot_server("8.8.8.8@853#dns.example")

	assert result["success"] is True
	assert result["error"] is None
