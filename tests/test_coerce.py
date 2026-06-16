#!/usr/bin/env python3
#
# tests/test_coerce.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the centralized persisted-boolean coercion contract.

Locks the truthy/falsy value sets and the fail-closed behavior of
``coerce_db_bool`` after consolidating the scattered settings-bool logic onto
``app.utils.coerce``.
"""

from __future__ import annotations

import pytest

from app.utils.coerce import BOOL_FALSE_VALUES, BOOL_TRUE_VALUES, coerce_db_bool


def test_value_sets_are_disjoint_and_expected():
    assert BOOL_TRUE_VALUES == {"1", "true", "yes", "on"}
    assert BOOL_FALSE_VALUES == {"0", "false", "no", "off"}
    assert BOOL_TRUE_VALUES.isdisjoint(BOOL_FALSE_VALUES)


@pytest.mark.parametrize("value", sorted(BOOL_TRUE_VALUES) + ["TRUE", " On ", "Yes"])
def test_truthy_strings(value):
    assert coerce_db_bool(value) is True


@pytest.mark.parametrize("value", sorted(BOOL_FALSE_VALUES) + ["FALSE", " Off "])
def test_falsy_strings(value):
    assert coerce_db_bool(value) is False


def test_bool_and_int_inputs():
    assert coerce_db_bool(True) is True
    assert coerce_db_bool(False) is False
    assert coerce_db_bool(1) is True
    assert coerce_db_bool(0) is False


@pytest.mark.parametrize("value", [2, -1, 5, 99])
def test_non_canonical_integers_fail_closed(value):
    # Only the canonical 1/0 encoding is accepted; corruption fails closed.
    assert coerce_db_bool(value) is False


@pytest.mark.parametrize("value", [None, "", "   ", "maybe", "2", "enabled", object(), b"1", 1.0, 3.14])
def test_unknown_empty_and_non_str_types_fail_closed(value):
    # Unknown strings and non-bool/int/str types must coerce to False.
    assert coerce_db_bool(value) is False


def test_coerce_db_bool_reexported_from_auth():
    # frontend_shared / frontend_pages import it from .auth; keep that path valid.
    from app.api.auth import coerce_db_bool as auth_coerce

    assert auth_coerce("yes") is True
    assert auth_coerce("nope") is False


def test_settings_bool_helpers_use_shared_sets():
    from app.db.sqlite_settings import _setting_is_truthy

    assert _setting_is_truthy("on") is True
    assert _setting_is_truthy("off") is False
    assert _setting_is_truthy(None, default=True) is True
    assert _setting_is_truthy("garbage") is False
