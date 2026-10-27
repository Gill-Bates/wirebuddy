#!/usr/bin/env python3
#
# tests/test_peer_create_keys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""PeerCreate key-consistency must match the create endpoint contract (P3.2).

The endpoint imports an existing keypair when both keys are given, rejects a
lone key, and generates a fresh pair when neither is given. The model used to
reject the both-set case, which made keypair import impossible before the
endpoint ever ran. The model now enforces "both or neither"; preshared_key
stays independent. Keys below are random test material, not real secrets.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.peers import PeerCreate

_PUB = "g48kcKhlSuoTL0O9OYc7rNbqw00O0Z/rhebNjIE2rnM="
_PRIV = "q/R1a8pqNM0JfQjLSUX7MSS2cSiPNy8p+6a2dSVLI6k="
_PSK = "aL1W9Orhm4p0X4pb3oGAeRzuksvHrT/x+TflfZJeopo="

_BASE = {"name": "peer1", "allowed_ips": "10.0.0.2/32", "allowed_ips_mode": "split"}


def test_both_keys_accepted():
	peer = PeerCreate(**_BASE, public_key=_PUB, private_key=_PRIV)
	assert peer.public_key == _PUB
	assert peer.private_key == _PRIV


def test_neither_key_accepted():
	peer = PeerCreate(**_BASE)
	assert peer.public_key is None
	assert peer.private_key is None


def test_only_public_key_rejected():
	with pytest.raises(ValidationError, match="both private and public key"):
		PeerCreate(**_BASE, public_key=_PUB)


def test_only_private_key_rejected():
	with pytest.raises(ValidationError, match="both private and public key"):
		PeerCreate(**_BASE, private_key=_PRIV)


def test_preshared_key_independent_of_keypair():
	# A standalone PSK with no keypair must still be accepted (import path).
	peer = PeerCreate(**_BASE, public_key=_PUB, private_key=_PRIV, preshared_key=_PSK)
	assert peer.preshared_key == _PSK

	peer_no_pair = PeerCreate(**_BASE, preshared_key=_PSK)
	assert peer_no_pair.preshared_key == _PSK
