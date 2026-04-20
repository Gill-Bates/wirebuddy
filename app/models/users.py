#!/usr/bin/env python3
#
# app/models/users.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""User-related Pydantic models."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator

# Username: 3-64 chars, starts/ends with alphanumeric, allows _ or - in middle
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$")
_CONSECUTIVE_SPECIAL_RE = re.compile(r"[-_]{2}")
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
# Restrict to visible special characters (excludes whitespace and control chars)
_SPECIAL_RE = re.compile(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?|`~]")
_COMMON_PASSWORDS = {
	"password",
	"password123",
	"password1",
	"qwerty",
	"qwerty123",
	"admin",
	"admin123",
	"letmein",
	"welcome",
	"welcome123",
	"12345678",
	"123456789",
	"1234567890",
	"abc123",
	"password!",
	"password1!",
	"changeme",
	"trustno1",
	"iloveyou",
}
# bcrypt truncates at 72 bytes, so enforce this limit
_PASSWORD_MAX_BYTES = 72
# Minimum password length for adequate entropy
_PASSWORD_MIN_LENGTH = 10


def _normalize_username(v: str) -> str:
	"""Shared username normalization for all username fields."""
	normalized = v.strip().lower()
	if not normalized or not normalized.isprintable():
		raise ValueError("Invalid username")
	# Enforce minimum length after normalization
	if len(normalized) < 3:
		raise ValueError("Username must be at least 3 characters after normalization")
	return normalized


def _validate_username(v: str) -> str:
	"""Validate and normalize username."""
	v_lower = _normalize_username(v)
	if not _USERNAME_RE.match(v_lower):
		raise ValueError(
			"Username must be 3-64 chars, start/end with alphanumeric, "
			"and contain only letters, digits, hyphens, or underscores"
		)
	if _CONSECUTIVE_SPECIAL_RE.search(v_lower):
		raise ValueError("Username cannot contain consecutive special characters")
	return v_lower


def _validate_password_strength(v: str) -> str:
	"""Validate basic password strength and encoding-safe length."""
	# Enforce minimum length for adequate entropy
	if len(v) < _PASSWORD_MIN_LENGTH:
		raise ValueError(f"Password must be at least {_PASSWORD_MIN_LENGTH} characters")
	
	if len(v.encode("utf-8")) > _PASSWORD_MAX_BYTES:
		raise ValueError("Password must be at most 72 bytes")

	if v.lower() in _COMMON_PASSWORDS:
		raise ValueError("Password is too common")

	checks = (_UPPER_RE, _LOWER_RE, _DIGIT_RE, _SPECIAL_RE)
	if sum(bool(regex.search(v)) for regex in checks) < 3:
		raise ValueError(
			"Password must contain at least 3 of: uppercase, lowercase, digit, special character"
		)
	return v


class LoginRequest(BaseModel):
	"""Login request payload."""
	username: str = Field(..., min_length=1, max_length=64)
	password: str = Field(..., min_length=1, max_length=256)

	@field_validator("username")
	@classmethod
	def normalize_username(cls, v: str) -> str:
		"""Normalize and validate username for consistent authentication."""
		# Use same validation path as UserCreate for consistency
		return _validate_username(v)


class MFAVerifyRequest(BaseModel):
	"""MFA verification payload (TOTP code or recovery code)."""
	username: str = Field(..., min_length=1, max_length=64)
	mfa_token: str = Field(..., min_length=20, max_length=512)
	code: str = Field(
		...,
		min_length=6,
		max_length=20,
		description="6-8 digit TOTP code or recovery code",
	)

	@field_validator("username")
	@classmethod
	def normalize_username(cls, v: str) -> str:
		return _normalize_username(v)

	@field_validator("code")
	@classmethod
	def normalize_code(cls, v: str) -> str:
		"""Normalize and validate TOTP/recovery code."""
		normalized = v.strip().replace(" ", "").replace("-", "")
		# TOTP codes are 6-8 digits, recovery codes may be alphanumeric
		if not normalized:
			raise ValueError("Code cannot be empty")
		# Validate format: either pure digits (TOTP) or alphanumeric (recovery)
		if not (normalized.isdigit() or normalized.isalnum()):
			raise ValueError("Code must contain only letters and numbers")
		return normalized

	@field_validator("mfa_token")
	@classmethod
	def normalize_mfa_token(cls, v: str) -> str:
		"""Normalize and validate MFA token format."""
		normalized = v.strip()
		# Basic JWT/base64 format check (alphanumeric + allowed chars)
		if not re.match(r"^[A-Za-z0-9._-]+$", normalized):
			raise ValueError("Invalid token format")
		return normalized


class OTPConfirmRequest(BaseModel):
	"""OTP setup confirmation payload."""
	code: str = Field(..., min_length=1, max_length=64)

	@field_validator("code")
	@classmethod
	def normalize_code(cls, v: str) -> str:
		"""Normalize and validate TOTP code."""
		normalized = v.strip().replace(" ", "").replace("-", "")
		if not normalized.isdigit():
			raise ValueError("TOTP code must be numeric")
		if len(normalized) < 6 or len(normalized) > 8:
			raise ValueError("TOTP code must be 6-8 digits")
		return normalized


class OTPDisableRequest(BaseModel):
	"""OTP disable payload requiring re-authentication proof."""
	current_password: str | None = Field(None, min_length=1, max_length=256)
	code: str | None = Field(None, min_length=1, max_length=64)

	@field_validator("current_password")
	@classmethod
	def normalize_current_password(cls, v: str | None) -> str | None:
		if v is None:
			return v
		normalized = v.strip()
		if not normalized:
			raise ValueError("Current password cannot be empty")
		return normalized

	@field_validator("code")
	@classmethod
	def normalize_code(cls, v: str | None) -> str | None:
		if v is None:
			return v
		normalized = v.strip().replace(" ", "").replace("-", "")
		if not normalized.isdigit():
			raise ValueError("TOTP code must be numeric")
		if len(normalized) < 6 or len(normalized) > 8:
			raise ValueError("TOTP code must be 6-8 digits")
		return normalized

	@model_validator(mode="after")
	def validate_reauth_present(self) -> OTPDisableRequest:
		if not self.current_password and not self.code:
			raise ValueError("Either current_password or code is required")
		return self


class RecoveryDownloadRequest(BaseModel):
	"""Recovery-code ZIP download request payload."""
	token: str = Field(..., min_length=1, max_length=512)

	@field_validator("token")
	@classmethod
	def normalize_token(cls, v: str) -> str:
		"""Normalize and validate token format."""
		normalized = v.strip()
		# Basic JWT/base64 format check
		if not re.match(r"^[A-Za-z0-9._-]+$", normalized):
			raise ValueError("Invalid token format")
		return normalized


class TokenResponse(BaseModel):
	"""Authentication token response."""
	token: str
	expires_at: datetime
	token_type: Literal["Bearer"] = "Bearer"


class UserCreate(BaseModel):
	"""User creation payload."""
	username: str = Field(..., min_length=3, max_length=64)
	# Note: Field max_length=256 for input convenience, but bcrypt truncates at 72 bytes
	password: str = Field(..., min_length=10, max_length=256)
	is_admin: bool = False

	@field_validator("username")
	@classmethod
	def validate_username(cls, v: str) -> str:
		return _validate_username(v)

	@field_validator("password")
	@classmethod
	def validate_password(cls, v: str) -> str:
		return _validate_password_strength(v)


class UserUpdate(BaseModel):
	"""User update payload.
	
	Note: Password changes must use the /change-password endpoint.
	"""
	username: str | None = Field(None, min_length=3, max_length=64)
	is_admin: bool | None = None
	is_active: bool | None = None

	@field_validator("username")
	@classmethod
	def validate_username(cls, v: str | None) -> str | None:
		if v is None:
			return v
		return _validate_username(v)


class UserPublic(BaseModel):
	"""Public user representation (without password)."""
	id: int
	username: str
	is_admin: bool
	is_active: bool
	otp_enabled: bool
	created_at: datetime
	last_login_at: datetime | None = None
	last_login_ip: IPvAnyAddress | None = None


class PasswordChangeRequest(BaseModel):
	"""Self-service password change request payload."""
	current_password: str = Field(..., min_length=1, max_length=256)
	new_password: str = Field(..., min_length=10, max_length=256)

	@field_validator("new_password")
	@classmethod
	def validate_new_password(cls, v: str) -> str:
		return _validate_password_strength(v)

	@model_validator(mode="after")
	def validate_passwords_differ(self) -> PasswordChangeRequest:
		"""Ensure new password is different from current password."""
		# Normalize before comparison (strip whitespace)
		if self.current_password.strip() == self.new_password.strip():
			raise ValueError("New password must be different from current password")
		return self


class AdminPasswordResetRequest(BaseModel):
	"""Admin-initiated password reset payload."""
	new_password: str = Field(..., min_length=10, max_length=256)

	@field_validator("new_password")
	@classmethod
	def validate_new_password(cls, v: str) -> str:
		return _validate_password_strength(v)
