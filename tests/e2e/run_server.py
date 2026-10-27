#!/usr/bin/env python3
#
# tests/e2e/run_server.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Start WireBuddy for browser E2E runs against a throwaway data directory.

    E2E_ADMIN_PASSWORD=... python tests/e2e/run_server.py DATA_DIR PORT

The admin is seeded with ``tools/ci-seed-admin.py`` *before* the server starts, which keeps the
first-boot bootstrap gate closed (see that script's docstring). The listener port comes from the
settings table, so it is written by the seeding step; ``app.server.main`` is also given it
explicitly. ``WIREBUDDY_SECRET_KEY`` is generated when the caller does not provide one; the seeding
step and the server share it through the environment. ``E2E_ADMIN_USERNAME`` defaults to ``admin``.
The real ``data/`` directory is refused.
"""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _prepare_data_dir(raw: str) -> Path:
	"""Resolve the data dir and refuse the real one."""
	path = Path(raw).resolve()
	real = (ROOT / "data").resolve()
	if path == real or real in path.parents or path in real.parents:
		raise SystemExit("refusing to use the real data directory")
	path.mkdir(parents=True, exist_ok=True)
	return path


def _seed_admin(port: int, username: str) -> None:
	"""Create the admin in the fresh database; exits non-zero when the database is not fresh."""
	result = subprocess.run(
		[sys.executable, str(ROOT / "tools" / "ci-seed-admin.py"), "--username", username, "--password-env", "E2E_ADMIN_PASSWORD", "--gui-port", str(port)],
		env=os.environ,
		check=False,
	)
	if result.returncode:
		raise SystemExit(f"seeding the admin failed (exit {result.returncode})")


def main(argv: list[str]) -> int:
	"""Seed, then run the server in this process until it is terminated."""
	if len(argv) != 2:
		print(__doc__, file=sys.stderr)
		return 2
	data_dir = _prepare_data_dir(argv[0])
	port = int(argv[1])
	if not os.environ.get("E2E_ADMIN_PASSWORD"):
		print("ERROR: E2E_ADMIN_PASSWORD is unset or empty", file=sys.stderr)
		return 1

	os.environ["WIREBUDDY_DATA_DIR"] = str(data_dir)
	os.environ.setdefault("WIREBUDDY_SECRET_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
	# A public origin would turn on Secure cookies, which a browser will not send over plain HTTP.
	os.environ.pop("WIREBUDDY_PUBLIC_ORIGIN", None)
	_seed_admin(port, os.environ.get("E2E_ADMIN_USERNAME", "admin"))

	from app.server import main as run_app

	run_app(port=port)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
