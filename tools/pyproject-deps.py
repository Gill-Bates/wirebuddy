#!/usr/bin/env python3
#
# tools/pyproject-deps.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Print one dependency group from pyproject.toml as a pip requirements list.

pyproject.toml replaced VERSION, requirements.txt and docs/requirements-docs.txt,
but a few consumers still need a flat file: pip's ``-r`` in CI, and Trivy's
filesystem scanner, which has no TOML analyzer for optional-dependencies. The
Docker builder is not one of them - it installs the project itself.

	python tools/pyproject-deps.py            # [project] dependencies
	python tools/pyproject-deps.py docs       # [project.optional-dependencies] docs
	python tools/pyproject-deps.py dev        # ... dev
	python tools/pyproject-deps.py --exclude pillow
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def requirement_name(requirement: str) -> str:
	"""Return the bare distribution name of a PEP 508 requirement string."""
	name = requirement.strip()
	for separator in ("[", ";", "=", "<", ">", "!", "~", " "):
		name = name.split(separator, 1)[0]
	return name.strip().lower().replace("_", "-")


def collect(group: str | None, pyproject: Path) -> list[str]:
	"""Return the dependency list for *group*, or the runtime list when None."""
	with pyproject.open("rb") as handle:
		data = tomllib.load(handle)

	project = data.get("project", {})
	if group is None:
		deps = project.get("dependencies")
		label = "[project] dependencies"
	else:
		deps = project.get("optional-dependencies", {}).get(group)
		label = f"[project.optional-dependencies] {group}"

	if deps is None:
		available = sorted(project.get("optional-dependencies", {}))
		raise SystemExit(f"{pyproject}: no {label}. Known extras: {', '.join(available) or 'none'}")
	return list(deps)


def main() -> int:
	"""Write the requested dependency group to stdout, one requirement per line."""
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument(
		"group",
		nargs="?",
		default=None,
		help="optional-dependencies extra to print; omit for the runtime dependencies",
	)
	parser.add_argument(
		"--pyproject",
		type=Path,
		default=_PYPROJECT,
		help=f"path to pyproject.toml (default: {_PYPROJECT})",
	)
	parser.add_argument(
		"--exclude",
		action="append",
		default=[],
		metavar="NAME",
		help="drop this distribution from the output; repeatable",
	)
	args = parser.parse_args()

	requirements = collect(args.group, args.pyproject)

	# A typo in --exclude would otherwise silently exclude nothing and produce a
	# green run against the wrong environment.
	excluded = {requirement_name(name) for name in args.exclude}
	unknown = excluded - {requirement_name(requirement) for requirement in requirements}
	if unknown:
		raise SystemExit(f"--exclude names nothing in the manifest: {', '.join(sorted(unknown))}")

	for requirement in requirements:
		if requirement_name(requirement) not in excluded:
			print(requirement)
	return 0


if __name__ == "__main__":
	sys.exit(main())
