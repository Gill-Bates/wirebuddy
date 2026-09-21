#!/usr/bin/env python3
#
# tools/ci-seed-admin.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Seed a ready-to-use admin into a fresh WireBuddy database, for CI only.

The Playwright audit (``tools/ui-lint/run-ui-lint.mjs``) logs in and then walks
every view. On an untouched database it cannot: ``ensure_default_admin()``
creates ``admin`` with a generated password and ``must_change_password = 1``,
and because it created that user it also arms the bootstrap gate
(``app/main.py``: ``bootstrap_gate_active = bootstrap_admin_created``). While
that gate is open only ``/login``, ``/ui/change-password`` and a handful of
endpoints answer - every other ``/ui/`` path 302s back to ``/login`` and every
other ``/api/`` path returns 423. The audit's login-flow check treats the
password-change page as a successful login (its path does not contain
``/login``), so the run would not fail cleanly; it would report a pile of
confusing per-view findings instead.

Scraping the generated password out of the log and driving the change flow would
work, but it means re-implementing the CSRF handshake and re-logging-in after
``complete-required-change`` revokes every token. Creating the user *before the
server starts* is both shorter and closes the gate at the root: with a user
present, ``ensure_default_admin()`` returns False, the gate is never armed, and
``create_user()`` leaves ``must_change_password`` at its column default of 0.

Not for production, and it refuses to touch a database that already has users -
see ``ensure_default_admin`` for the real first-boot path.

    WIREBUDDY_SECRET_KEY=... WIREBUDDY_DATA_DIR=... \
        python tools/ci-seed-admin.py --username admin --password-env UI_LINT_PASSWORD
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# tools/ is not a package and this script is run directly, so the repo root has
# to be on sys.path before app.* resolves.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.sqlite_runtime import close_connection, connect
from app.db.sqlite_schema import init_schema, insert_default_settings
from app.db.sqlite_settings import set_setting, validate_secret_key
from app.db.sqlite_users import count_admins, create_user
from app.utils.config import load_config


def main() -> int:
	"""Create the audit's admin user, or explain why it could not."""
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("--username", default="admin", help="admin username to create (default: admin)")
	parser.add_argument(
		"--password-env",
		default="UI_LINT_PASSWORD",
		metavar="VAR",
		help="environment variable holding the password; never passed on the command line, "
		"where it would be visible in the process list (default: UI_LINT_PASSWORD)",
	)
	parser.add_argument(
		"--listen-all",
		action="store_true",
		help="set gui_localhost_only=false so the server binds 0.0.0.0 instead of 127.0.0.1",
	)
	# run.py reads the listener from the settings table (gui_port /
	# gui_localhost_only) and honours no HOST/PORT environment variable, so a
	# port other than 8000 can only be requested here.
	parser.add_argument(
		"--gui-port",
		type=int,
		default=None,
		metavar="PORT",
		help="set gui_port; omit to leave the default of 8000",
	)
	args = parser.parse_args()

	if args.gui_port is not None and not 1 <= args.gui_port <= 65535:
		print(f"ERROR: --gui-port {args.gui_port} is out of range", file=sys.stderr)
		return 1

	password = os.environ.get(args.password_env, "")
	if not password:
		print(f"ERROR: {args.password_env} is unset or empty", file=sys.stderr)
		return 1

	# load_config() exits the process itself when WIREBUDDY_SECRET_KEY is
	# missing or too short. It also decides the data dir and therefore the
	# database path, which is why this script has to run with exactly the
	# environment the server will later run with - the key peppers the
	# validation token written below.
	cfg = load_config()
	print(f"database: {cfg.db_path}")

	conn = connect(cfg.db_path)
	try:
		init_schema(conn)

		# Before any other setting is written. validate_secret_key() installs
		# the validation token on a fresh database, but refuses to do so once
		# other settings exist - it cannot tell "new database" from "wrong key"
		# at that point and fails closed. Writing a setting first would
		# therefore leave a database the app aborts on with
		# KEY_MISMATCH_DETECTED.
		if not validate_secret_key(conn, cfg.secret_key):
			print(
				"ERROR: WIREBUDDY_SECRET_KEY does not match this database. "
				"Seeding expects an empty data dir.",
				file=sys.stderr,
			)
			return 1

		insert_default_settings(conn)

		# Refuse to add a second admin to a database that is already set up:
		# this script exists for a throwaway CI instance, and silently
		# appending an account with a known password to a real one is the
		# failure mode worth being loud about.
		existing_admins = count_admins(conn)
		if existing_admins:
			print(
				f"ERROR: this database already has {existing_admins} active admin(s); refusing to seed.",
				file=sys.stderr,
			)
			return 1

		user_id = create_user(conn, args.username, password, is_admin=True)
		if user_id is None:
			print(f"ERROR: username {args.username!r} already exists", file=sys.stderr)
			return 1

		if args.listen_all:
			set_setting(conn, "gui_localhost_only", "false")
		if args.gui_port is not None:
			set_setting(conn, "gui_port", str(args.gui_port))

		# The audit needs a logged-in session, not a password-change page. This
		# is the property the whole script exists to establish, so it is
		# asserted rather than assumed.
		row = conn.execute(
			"SELECT must_change_password, is_admin, is_active FROM users WHERE id = ?",
			(user_id,),
		).fetchone()
		if not row or row["must_change_password"] or not row["is_admin"] or not row["is_active"]:
			print(f"ERROR: seeded user is not a usable active admin: {tuple(row) if row else None}", file=sys.stderr)
			return 1

		print(f"seeded active admin {args.username!r} (id={user_id}, must_change_password=0)")
	finally:
		close_connection(conn)
	return 0


if __name__ == "__main__":
	sys.exit(main())
