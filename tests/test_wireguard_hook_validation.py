#!/usr/bin/env python3
#
# tests/test_wireguard_hook_validation.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""PostUp/PostDown hook validation: size and charset limits."""

from __future__ import annotations

import pytest

from app.api.wireguard_config import _validate_hook


def test_valid_hook_passes():
	hook = "iptables -A FORWARD -i wg0 -j ACCEPT; ip link show wg0"
	assert _validate_hook(hook, "PostUp") == hook


def test_oversized_hook_is_rejected():
	hook = "; ".join(["ip link show wg0"] * 200)
	assert len(hook) > 2048
	with pytest.raises(ValueError, match="too long"):
		_validate_hook(hook, "PostUp")


def test_non_ascii_hook_is_rejected():
	with pytest.raises(ValueError, match="printable ASCII"):
		_validate_hook("ip link show wgä0", "PostDown")
