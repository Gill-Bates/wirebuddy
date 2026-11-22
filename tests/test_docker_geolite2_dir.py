#!/usr/bin/env python3
#
# tests/test_docker_geolite2_dir.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for the GeoLite2 directory preparation in the Docker setup."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_ENTRYPOINT = _ROOT / "docker" / "entrypoint.sh"
_DOCKERFILE = _ROOT / "docker" / "Dockerfile"
_BASH = shutil.which("bash") or "/bin/bash"


@pytest.fixture()
def fake_env(tmp_path: Path) -> dict[str, str]:
	"""Environment whose `python` only records that it was started."""
	bin_dir = tmp_path / "bin"
	bin_dir.mkdir()
	marker = tmp_path / "python-started"
	fake = bin_dir / "python"
	fake.write_text(f'#!/bin/sh\necho "$@" >> "{marker}"\nexit 0\n')
	fake.chmod(0o755)
	data = tmp_path / "data"
	data.mkdir()
	return {
		"PATH": f"{bin_dir}:{os.environ['PATH']}",
		"WIREBUDDY_DATA_DIR": str(data),
		"HOME": str(tmp_path),
	}


def _run(env: dict[str, str], mode: str) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		[_BASH, str(_ENTRYPOINT)],
		env={**env, "SERVER_MODE": mode},
		capture_output=True,
		text=True,
		timeout=30,
		check=False,
	)


@pytest.mark.parametrize("mode", ["master", "node"])
def test_empty_data_dir_creates_geolite2_and_starts(fake_env: dict[str, str], mode: str) -> None:
	result = _run(fake_env, mode)
	assert result.returncode == 0, result.stderr
	assert (Path(fake_env["WIREBUDDY_DATA_DIR"]) / "geolite2").is_dir()
	assert (Path(fake_env["PATH"].split(":")[0]).parent / "python-started").exists()


@pytest.mark.parametrize("mode", ["master", "node"])
def test_existing_files_and_repeated_start_keep_databases(fake_env: dict[str, str], mode: str) -> None:
	geo = Path(fake_env["WIREBUDDY_DATA_DIR"]) / "geolite2"
	geo.mkdir()
	db = geo / "GeoLite2-City.mmdb"
	db.write_bytes(b"existing-db")
	before = db.stat()
	for _ in range(2):
		assert _run(fake_env, mode).returncode == 0
	after = db.stat()
	assert db.read_bytes() == b"existing-db"
	assert (before.st_mtime_ns, before.st_ino) == (after.st_mtime_ns, after.st_ino)
	assert sorted(p.name for p in geo.iterdir()) == ["GeoLite2-City.mmdb"]


@pytest.mark.parametrize("mode", ["master", "node"])
def test_symlinked_geolite2_is_not_followed(fake_env: dict[str, str], tmp_path: Path, mode: str) -> None:
	target = tmp_path / "elsewhere"
	target.mkdir()
	(target / "keep.mmdb").write_bytes(b"x")
	link = Path(fake_env["WIREBUDDY_DATA_DIR"]) / "geolite2"
	link.symlink_to(target)
	result = _run(fake_env, mode)
	assert result.returncode == 0, result.stderr
	assert link.is_symlink()
	assert "symlink" in result.stderr
	assert [p.name for p in target.iterdir()] == ["keep.mmdb"]


def test_dangling_symlink_is_not_created_through(fake_env: dict[str, str], tmp_path: Path) -> None:
	link = Path(fake_env["WIREBUDDY_DATA_DIR"]) / "geolite2"
	link.symlink_to(tmp_path / "missing")
	assert _run(fake_env, "node").returncode == 0
	assert not (tmp_path / "missing").exists()


def test_geolite2_path_that_is_a_file_is_left_alone(fake_env: dict[str, str]) -> None:
	path = Path(fake_env["WIREBUDDY_DATA_DIR"]) / "geolite2"
	path.write_bytes(b"not a dir")
	result = _run(fake_env, "master")
	assert result.returncode == 0
	assert path.read_bytes() == b"not a dir"


def test_dockerfile_creates_geolite2_dir_without_embedding_databases() -> None:
	text = _DOCKERFILE.read_text()
	assert re.search(r"mkdir -p [^\n]*/app/data/geolite2", text)
	assert not re.search(r"^\s*(COPY|ADD)\b[^\n]*\.mmdb", text, re.MULTILINE)
