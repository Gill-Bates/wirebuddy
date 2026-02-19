#!/usr/bin/env python3
#
# app/models/__init__.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Pydantic models for WireBuddy."""

from .users import (
	LoginRequest,
	PasswordChangeRequest,
	TokenResponse,
	UserCreate,
	UserPublic,
	UserUpdate,
)
from .peers import (
	PeerCreate,
	PeerPublic,
	PeerUpdate,
	PeerConfig,
	PeerStats,
)

__all__ = [
	# Users
	"LoginRequest",
	"PasswordChangeRequest",
	"TokenResponse",
	"UserCreate",
	"UserPublic",
	"UserUpdate",
	# Peers
	"PeerCreate",
	"PeerPublic",
	"PeerUpdate",
	"PeerConfig",
	"PeerStats",
]
