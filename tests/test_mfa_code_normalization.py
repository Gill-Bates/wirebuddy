#!/usr/bin/env python3
#
# tests/test_mfa_code_normalization.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#
# SPDX-License-Identifier: MIT
#

"""Preserve MFA code normalization and validation during cleanup."""

import pytest
from pydantic import ValidationError

from app.models.users import MFAVerifyRequest


@pytest.mark.parametrize(("code", "expected"), [
	("123456", "123456"),
	("12345678", "12345678"),
	(" ab-12 cd ", "ab12cd"),
	("１２３４５６", "１２３４５６"),
	("²²²²²²", "²²²²²²"),
	("äbc123", "äbc123"),
	("a" * 20, "a" * 20),
])
def test_mfa_code_normalization(code, expected):
	request = MFAVerifyRequest(username="alice", mfa_token="a" * 20, code=code)
	assert request.code == expected


@pytest.mark.parametrize(("code", "error"), [
	("12345", "at least 6 characters"),
	("a" * 21, "at most 20 characters"),
	(" -- -- ", "Code cannot be empty"),
	("abc!23", "Code must contain only letters and numbers"),
	("abc_23", "Code must contain only letters and numbers"),
	("12\t3456", "Code must contain only letters and numbers"),
])
def test_mfa_code_rejection(code, error):
	with pytest.raises(ValidationError, match=error):
		MFAVerifyRequest(username="alice", mfa_token="a" * 20, code=code)
