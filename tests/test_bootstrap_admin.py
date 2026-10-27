#!/usr/bin/env python3
#
# tests/test_bootstrap_admin.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""The bootstrap admin password is printed once to stdout, never logged or stored."""

from __future__ import annotations

import logging
from pathlib import Path

from app.db.sqlite_schema import ensure_default_admin


def test_bootstrap_prints_password_once_and_never_logs_or_stores_it(conn, tmp_path: Path, monkeypatch, capsys, caplog):
	monkeypatch.chdir(tmp_path)
	with caplog.at_level(logging.DEBUG):
		assert ensure_default_admin(conn) is True

	out = capsys.readouterr().out
	password_line = next(line for line in out.splitlines() if "Password:" in line)
	secret = password_line.split("Password:", 1)[1].strip()
	assert secret
	assert "Username: admin" in out

	combined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
	assert secret not in combined_logs
	assert list(tmp_path.iterdir()) == []

	# A second call finds an existing user and prints nothing.
	assert ensure_default_admin(conn) is False
	assert capsys.readouterr().out == ""


def test_generated_password_pattern_and_policy():
	import re

	from app.db.sqlite_schema import _generate_pronounceable_password
	from app.models.users import _validate_password_strength

	for _ in range(200):
		pw = _generate_pronounceable_password()
		assert len(pw) == 9
		assert re.fullmatch(r"[A-Z][a-z]{5}\d{2}[!?#$%&*+\-=@]", pw)
		assert _validate_password_strength(pw) == pw
