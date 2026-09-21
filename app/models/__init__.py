#!/usr/bin/env python3
#
# app/models/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Pydantic models for WireBuddy."""

from .peers import (
	PeerConfig,
	PeerCreate,
	PeerPublic,
	PeerStats,
	PeerUpdate,
)
from .users import (
	LoginRequest,
	PasswordChangeRequest,
	TokenResponse,
	UserCreate,
	UserPublic,
	UserUpdate,
)

__all__ = [
	# Users
	"LoginRequest",
	"PasswordChangeRequest",
	"PeerConfig",
	# Peers
	"PeerCreate",
	"PeerPublic",
	"PeerStats",
	"PeerUpdate",
	"TokenResponse",
	"UserCreate",
	"UserPublic",
	"UserUpdate",
]
