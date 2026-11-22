#!/usr/bin/env python3
#
# tests/test_country_flags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Flags are served locally from gillbates-country-flags; only validated codes reach the file system."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.utils.flags import FLAG_BASE_URL, local_flag_svg


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path / "data"))
	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 32)
	return TestClient(create_app(), base_url="http://localhost")


def test_local_flag_svg_returns_svg_for_valid_code():
	svg = local_flag_svg("DE")
	assert svg is not None
	assert b"<svg" in svg


@pytest.mark.parametrize("code", ["zz", "d", "deu", "..", "../x", "d1", "", "de/"])
def test_local_flag_svg_rejects_invalid_code(code: str):
	assert local_flag_svg(code) is None


def test_flag_route_serves_svg_without_session(client: TestClient):
	response = client.get(f"{FLAG_BASE_URL}/de.svg")
	assert response.status_code == 200
	assert response.headers["content-type"].startswith("image/svg+xml")


@pytest.mark.parametrize("code", ["zz", "deu", "%2e%2e"])
def test_flag_route_404_for_invalid_code(client: TestClient, code: str):
	assert client.get(f"{FLAG_BASE_URL}/{code}.svg").status_code == 404


def test_csp_img_src_has_no_cdn_origin(client: TestClient):
	csp = client.get("/health").headers.get("content-security-policy", "")
	assert "img-src 'self'" in csp
	assert "cdn.jsdelivr.net" not in csp.split("img-src", 1)[1].split(";", 1)[0]
