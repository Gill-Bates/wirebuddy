#!/usr/bin/env python3
#
# .github/scripts/toolchain_parity.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Fail the release unless every architecture image carries identical toolchain versions."""

import argparse
import sys
from pathlib import Path

from ci_output import REPO_URL, log, print_header

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"

# Recorded by the build job's "Record toolchain versions" step; each must be present and non-empty.
REQUIRED_FIELDS = ("python", "wireguard_tools", "unbound", "sqlite3", "iptables", "openssl", "app_version", "build_info")


class ParityError(Exception):
	"""The toolchain records are missing, incomplete or differ between architectures."""


def parse_record(text: str) -> dict[str, str]:
	"""Read key=value lines; the multi-line BUILD_INFO adds its own keys, which are compared too."""
	record: dict[str, str] = {}
	for raw in text.splitlines():
		line = raw.strip()
		if not line:
			continue
		name, separator, value = line.partition("=")
		if not separator or not name:
			raise ParityError(f"malformed toolchain line: {line!r}")
		record[name] = value
	return record


def load_records(directory: Path, arches: list[str]) -> dict[str, dict[str, str]]:
	if not arches:
		raise ParityError("no architectures given")
	present = sorted(path.stem for path in directory.glob("*.txt")) if directory.is_dir() else []
	missing = sorted(set(arches) - set(present))
	extra = sorted(set(present) - set(arches))
	if missing:
		raise ParityError(f"no toolchain record for {', '.join(missing)}")
	if extra:
		raise ParityError(f"unexpected toolchain records: {', '.join(extra)}")
	records = {arch: parse_record((directory / f"{arch}.txt").read_text(encoding="utf-8")) for arch in arches}
	for arch, record in records.items():
		empty = [field for field in REQUIRED_FIELDS if not record.get(field)]
		if empty:
			raise ParityError(f"{arch} lacks {', '.join(empty)}")
	return records


def mismatches(records: dict[str, dict[str, str]]) -> list[str]:
	names = sorted({name for record in records.values() for name in record})
	found: list[str] = []
	for name in names:
		seen = {arch: record.get(name, "<missing>") for arch, record in records.items()}
		if len(set(seen.values())) > 1:
			found.append(f"{name}: " + ", ".join(f"{arch}={value}" for arch, value in sorted(seen.items())))
	return found


def main(argv: list[str] | None = None) -> int:
	if hasattr(sys.stdout, "reconfigure"):  # a test may swap stdout for a StringIO
		sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
	description = (__doc__ or "").strip().splitlines()[0]
	print_header(SCRIPT, description, __author__, HELP_URL)
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument("--dir", type=Path, required=True, help="Directory with one <arch>.txt per architecture")
	parser.add_argument("--arches", required=True, help="Space-separated architectures the release must carry")
	args = parser.parse_args(argv)
	try:
		records = load_records(args.dir, args.arches.split())
	except (OSError, ParityError) as exc:
		log("error", f"FAIL: {exc}")
		return 1
	for arch, record in records.items():
		print(f"--- {arch} ---")
		for name, value in sorted(record.items()):
			print(f"  {name}={value}")
	found = mismatches(records)
	if found:
		log("error", "FAIL: the architectures do not carry the same versions")
		for line in found:
			log("error", f"  {line}")
		log(
			"info",
			"Every rolling component is resolved once in the meta job and passed to both builds, so this means "
			"a build arg did not reach the Dockerfile, or a stale cached layer was reused.",
		)
		return 1
	count = len({name for record in records.values() for name in record})
	print(f"OK: {', '.join(sorted(records))} carry identical versions of all {count} components")
	return 0


if __name__ == "__main__":
	sys.exit(main())
