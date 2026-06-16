#!/usr/bin/env python3
#
# app/utils/coerce.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Canonical boolean coercion for persisted (DB/settings) string values.

Single source for *which* string encodings count as true/false for application
settings, so the contract changes in one place. Distinct call-site behaviours
(fail-closed bool vs. ``"1"|"0"|None`` write-normalisation vs. truthy-only reads)
stay at their call sites and reuse only the shared value sets.

Note: this is intentionally separate from environment-flag parsing (a narrower
``{"1","true","yes"}`` set in a different domain), which is left duplicated.
"""

from __future__ import annotations

# The accepted string encodings for a persisted boolean. Centralised so a change
# to the contract (e.g. adding "enabled") updates every consumer at once.
BOOL_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
BOOL_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def coerce_db_bool(value: object) -> bool:
	"""Coerce SQLite-style boolean-ish values into a strict bool.

	Strict by design — safe for auth fields (is_admin, otp_enabled, ...):

	* ``bool`` -> itself
	* ``int`` -> only canonical ``1`` is true; any other integer (corruption,
	  bad migration) fails closed to ``False``
	* ``str`` -> matched against the canonical true/false sets
	* anything else (bytes, float, Decimal, custom objects, ``None``) fails
	  closed to ``False`` rather than being parsed through ``str()``
	"""
	if isinstance(value, bool):
		return value
	if isinstance(value, int):
		return value == 1
	if not isinstance(value, str):
		return False
	text = value.strip().lower()
	if text in BOOL_TRUE_VALUES:
		return True
	if text in BOOL_FALSE_VALUES:
		return False
	# Unrecognised/empty strings fail closed.
	return False
