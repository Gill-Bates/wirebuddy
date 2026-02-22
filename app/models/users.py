#!/usr/bin/env python3
#
# app/models/users.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""User-related Pydantic models."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator

# Username: 3-64 chars, starts/ends with alphanumeric, allows _ or - in middle
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{1,62}[a-z0-9])?$")


def _validate_username(v: str) -> str:
	"""Validate and normalize username."""
	v_lower = v.strip().lower()
	if not _USERNAME_RE.match(v_lower):
		raise ValueError(
			"Username must be 3-64 alphanumeric chars, may contain _ or - "
			"(but not at start/end), no consecutive special chars"
		)
	# Additional check: no consecutive special chars
	if "--" in v_lower or "__" in v_lower or "_-" in v_lower or "-_" in v_lower:
		raise ValueError("Username cannot contain consecutive special characters")
	return v_lower


class LoginRequest(BaseModel):
	"""Login request payload."""
	username: str = Field(..., min_length=1, max_length=64)
	password: str = Field(..., min_length=1, max_length=256)

	@field_validator("username")
	@classmethod
	def normalize_username(cls, v: str) -> str:
		"""Normalize username for consistent lookups."""
		return v.strip().lower()


class TokenResponse(BaseModel):
	"""Authentication token response."""
	token: str
	expires_at: datetime
	token_type: Literal["Bearer"] = "Bearer"


class UserCreate(BaseModel):
	"""User creation payload."""
	username: str = Field(..., min_length=3, max_length=64)
	password: str = Field(..., min_length=8, max_length=256)
	is_admin: bool = False

	@field_validator("username")
	@classmethod
	def validate_username(cls, v: str) -> str:
		return _validate_username(v)


class UserUpdate(BaseModel):
	"""User update payload.
	
	Note: Password changes must use the /change-password endpoint.
	"""
	username: Optional[str] = Field(None, min_length=3, max_length=64)
	is_admin: Optional[bool] = None
	is_active: Optional[bool] = None

	@field_validator("username")
	@classmethod
	def validate_username(cls, v: Optional[str]) -> Optional[str]:
		if v is None:
			return v
		return _validate_username(v)


class UserPublic(BaseModel):
	"""Public user representation (without password)."""
	id: int
	username: str
	is_admin: bool
	is_active: bool
	created_at: datetime
	last_login_at: Optional[datetime] = None
	last_login_ip: Optional[IPvAnyAddress] = None


class PasswordChangeRequest(BaseModel):
	"""Password change request payload."""
	current_password: Optional[str] = Field(None, min_length=1, max_length=256)
	new_password: str = Field(..., min_length=8, max_length=256)

	@model_validator(mode="after")
	def validate_passwords_differ(self) -> "PasswordChangeRequest":
		"""Ensure new password is different from current (when current is provided)."""
		if self.current_password and self.current_password == self.new_password:
			raise ValueError("New password must be different from current password")
		return self
