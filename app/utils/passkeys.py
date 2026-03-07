#!/usr/bin/env python3
#
# app/utils/passkeys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WebAuthn/Passkey utility helpers for registration and authentication.

Challenge Storage: Uses SQLite-backed storage for multi-worker/multi-process
deployments. Challenges are stored in the `passkey_challenges` table with
automatic expiration cleanup.
"""

from __future__ import annotations

import binascii
import enum
import hashlib
import hmac
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from typing import Any

from webauthn import (
	generate_authentication_options,
	generate_registration_options,
	verify_authentication_response,
	verify_registration_response,
)
from webauthn.helpers import (
	base64url_to_bytes,
	bytes_to_base64url,
)
from webauthn.helpers.structs import (
	AuthenticationCredential,
	AuthenticatorAssertionResponse,
	AuthenticatorAttestationResponse,
	AuthenticatorSelectionCriteria,
	PublicKeyCredentialDescriptor,
	RegistrationCredential,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)

_log = logging.getLogger(__name__)

# Configuration constants
_MAX_PASSKEYS_PER_USER = int(os.environ.get("MAX_PASSKEYS_PER_USER", "20"))


# Custom exceptions
class InvalidChallengeError(Exception):
	"""Raised when a challenge is invalid, expired, or already consumed."""


@dataclass
class AuthenticationChallengeResult:
	"""Result of consuming an authentication challenge."""
	user_id: int | None  # None = usernameless/discoverable flow


@dataclass
class PasskeyRegistrationResult:
	"""Result of a successful passkey registration verification."""
	credential_id: str  # base64url encoded
	public_key: bytes
	sign_count: int
	transports: list[str] | None


@dataclass
class PasskeyAuthenticationResult:
	"""Result of a successful passkey authentication verification."""
	credential_id: str  # base64url encoded
	new_sign_count: int


def _get_user_handle_secret() -> bytes:
	"""Get the secret key for deriving WebAuthn user handles.
	
	Uses WIREBUDDY_SECRET_KEY to ensure user handles are opaque, non-enumerable,
	and consistent across restarts.
	"""
	secret = os.environ.get("WIREBUDDY_SECRET_KEY", "")
	if not secret:
		raise RuntimeError("WIREBUDDY_SECRET_KEY not set - required for passkey user handles")
	return secret.encode("utf-8")


def _user_handle_for_id(user_id: int) -> bytes:
	"""Generate an opaque WebAuthn user.id from internal user_id.
	
	Per WebAuthn spec §5.4.3, user.id MUST be an opaque byte sequence that
	does not contain PII. Sequential integers leak account enumeration.
	
	Uses HMAC-SHA256(secret, user_id) to generate 32 bytes.
	"""
	secret = _get_user_handle_secret()
	return hmac.new(secret, str(user_id).encode("utf-8"), hashlib.sha256).digest()


def _validate_base64url(value: str, name: str) -> None:
	"""Validate a base64url string.
	
	Raises:
		ValueError: If the string is not valid base64url
	"""
	if not value:
		raise ValueError(f"{name} cannot be empty")
	
	try:
		# Attempt decode - this validates format and character set
		base64url_to_bytes(value)
	except (binascii.Error, ValueError) as e:
		raise ValueError(f"{name} is not valid base64url: {e}") from e


def _parse_registration_credential(credential_json: dict[str, Any]) -> RegistrationCredential:
	"""Parse a browser credential JSON into a RegistrationCredential.
	
	The browser sends camelCase keys, but py-webauthn uses snake_case dataclasses.
	This function handles the conversion.
	
	Args:
		credential_json: The credential response from navigator.credentials.create()
		
	Returns:
		RegistrationCredential instance
		
	Raises:
		ValueError: If required fields are missing or invalid
	"""
	try:
		# Extract required fields with camelCase -> snake_case fallback
		cred_id = credential_json.get("id")
		raw_id = credential_json.get("rawId") or credential_json.get("raw_id")
		response = credential_json.get("response", {})
		
		if not cred_id:
			raise ValueError("Missing credential id")
		if not raw_id:
			raise ValueError("Missing rawId")
		
		# Parse response
		client_data_json = response.get("clientDataJSON") or response.get("client_data_json")
		attestation_object = response.get("attestationObject") or response.get("attestation_object")
		
		if not client_data_json:
			raise ValueError("Missing clientDataJSON")
		if not attestation_object:
			raise ValueError("Missing attestationObject")
		
		# Parse transports if present
		transports = response.get("transports")
		parsed_transports = None
		if transports:
			from webauthn.helpers.structs import AuthenticatorTransport
			parsed_transports = []
			for t in transports:
				try:
					parsed_transports.append(AuthenticatorTransport(t))
				except ValueError:
					_log.warning("Unknown transport: %s", t)
		
		# Build the response object
		attestation_response = AuthenticatorAttestationResponse(
			client_data_json=base64url_to_bytes(client_data_json),
			attestation_object=base64url_to_bytes(attestation_object),
			transports=parsed_transports,
		)
		
		return RegistrationCredential(
			id=cred_id,
			raw_id=base64url_to_bytes(raw_id),
			response=attestation_response,
			type="public-key",
		)
	except Exception as e:
		_log.warning("Failed to parse registration credential: %s", e)
		raise ValueError(f"Invalid registration credential: {e}") from e


def _parse_authentication_credential(credential_json: dict[str, Any]) -> AuthenticationCredential:
	"""Parse a browser credential JSON into an AuthenticationCredential.
	
	The browser sends camelCase keys, but py-webauthn uses snake_case dataclasses.
	This function handles the conversion.
	
	Args:
		credential_json: The credential response from navigator.credentials.get()
		
	Returns:
		AuthenticationCredential instance
		
	Raises:
		ValueError: If required fields are missing or invalid
	"""
	try:
		# Extract required fields with camelCase -> snake_case fallback
		cred_id = credential_json.get("id")
		raw_id = credential_json.get("rawId") or credential_json.get("raw_id")
		response = credential_json.get("response", {})
		
		if not cred_id:
			raise ValueError("Missing credential id")
		if not raw_id:
			raise ValueError("Missing rawId")
		
		# Parse response
		client_data_json = response.get("clientDataJSON") or response.get("client_data_json")
		authenticator_data = response.get("authenticatorData") or response.get("authenticator_data")
		signature = response.get("signature")
		user_handle = response.get("userHandle") or response.get("user_handle")
		
		if not client_data_json:
			raise ValueError("Missing clientDataJSON")
		if not authenticator_data:
			raise ValueError("Missing authenticatorData")
		if not signature:
			raise ValueError("Missing signature")
		
		# Build the response object
		assertion_response = AuthenticatorAssertionResponse(
			client_data_json=base64url_to_bytes(client_data_json),
			authenticator_data=base64url_to_bytes(authenticator_data),
			signature=base64url_to_bytes(signature),
			user_handle=base64url_to_bytes(user_handle) if user_handle else None,
		)
		
		return AuthenticationCredential(
			id=cred_id,
			raw_id=base64url_to_bytes(raw_id),
			response=assertion_response,
			type="public-key",
		)
	except Exception as e:
		_log.warning("Failed to parse authentication credential: %s", e)
		raise ValueError(f"Invalid authentication credential: {e}") from e


def store_registration_challenge(
	conn: sqlite3.Connection,
	challenge: str,
	user_id: int,
	username: str,
) -> None:
	"""Store a registration challenge in SQLite for later verification.
	
	This is multi-worker safe as challenges are stored in the shared database.
	
	Raises:
		sqlite3.IntegrityError: If challenge already exists (replay attack)
	"""
	# Deferred import to avoid circular dependency: sqlite_passkeys → passkeys
	from ..db.sqlite_passkeys import store_challenge
	store_challenge(conn, challenge, "registration", user_id, username)
	_log.debug("Stored registration challenge for user_id=%d", user_id)


def consume_registration_challenge(
	conn: sqlite3.Connection,
	challenge: str,
) -> tuple[int, str]:
	"""Consume and return (user_id, username) if challenge is valid.
	
	This is multi-worker safe as challenges are stored in the shared database.
	
	Returns:
		tuple[int, str]: (user_id, username)
		
	Raises:
		InvalidChallengeError: If challenge is invalid, expired, or already consumed
	"""
	# Deferred import to avoid circular dependency
	from ..db.sqlite_passkeys import consume_challenge
	try:
		user_id, username = consume_challenge(conn, challenge, "registration")
	except KeyError:
		_log.warning("Registration challenge not found (replay or expired)")
		raise InvalidChallengeError("Unknown or already-consumed challenge") from None
	except ValueError as e:
		_log.error("Challenge ceremony type mismatch: %s", e)
		raise InvalidChallengeError(str(e)) from None
	
	if user_id is None or username is None:
		_log.error("Registration challenge missing user_id or username")
		raise InvalidChallengeError("Invalid challenge data")
	
	_log.info("Registration challenge consumed for user_id=%d", user_id)
	return (user_id, username)


def store_authentication_challenge(
	conn: sqlite3.Connection,
	challenge: str,
	user_id: int | None = None,
) -> None:
	"""Store an authentication challenge in SQLite for later verification.
	
	This is multi-worker safe as challenges are stored in the shared database.
	
	Args:
		conn: Database connection
		challenge: The base64url-encoded challenge
		user_id: User ID, or None for usernameless (discoverable credential) flows
	"""
	# Deferred import to avoid circular dependency
	from ..db.sqlite_passkeys import store_challenge
	store_challenge(conn, challenge, "authentication", user_id, None)
	_log.debug("Stored authentication challenge for user_id=%s", user_id)


def consume_authentication_challenge(
	conn: sqlite3.Connection,
	challenge: str,
) -> AuthenticationChallengeResult:
	"""Consume and return challenge result if valid.
	
	This is multi-worker safe as challenges are stored in the shared database.
	
	Returns:
		AuthenticationChallengeResult with user_id (None for usernameless flows)
		
	Raises:
		InvalidChallengeError: If challenge is invalid, expired, or already consumed
	"""
	# Deferred import to avoid circular dependency
	from ..db.sqlite_passkeys import consume_challenge
	try:
		user_id, _ = consume_challenge(conn, challenge, "authentication")
	except KeyError:
		_log.warning("Authentication challenge not found (replay or expired)")
		raise InvalidChallengeError("Unknown or already-consumed challenge") from None
	except ValueError as e:
		_log.error("Challenge ceremony type mismatch: %s", e)
		raise InvalidChallengeError(str(e)) from None
	
	_log.info("Authentication challenge consumed for user_id=%s", user_id)
	return AuthenticationChallengeResult(user_id=user_id)


def get_registration_options(
	conn: sqlite3.Connection,
	rp_id: str,
	rp_name: str,
	user_id: int,
	username: str,
	existing_credential_ids: list[str] | None = None,
) -> dict[str, Any]:
	"""Generate WebAuthn registration options (PublicKeyCredentialCreationOptions).
	
	Args:
		rp_id: Relying Party ID (domain name)
		rp_name: Human-readable RP name
		user_id: Internal user ID
		username: Username for display
		existing_credential_ids: List of already-registered credential IDs (base64url)
		
	Returns:
		Dictionary suitable for JSON serialization to frontend
		
	Raises:
		ValueError: If existing_credential_ids contains invalid base64url strings
		ValueError: If user has too many passkeys registered
	"""
	# Enforce maximum passkeys per user
	if existing_credential_ids and len(existing_credential_ids) >= _MAX_PASSKEYS_PER_USER:
		raise ValueError(
			f"Maximum of {_MAX_PASSKEYS_PER_USER} passkeys per user. "
			"Delete unused passkeys before registering new ones."
		)
	
	# Convert existing credentials to exclude list
	exclude_credentials = []
	if existing_credential_ids:
		for cred_id in existing_credential_ids:
			_validate_base64url(cred_id, "credential_id")
			exclude_credentials.append(
				PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
			)

	# Use opaque user handle instead of sequential integer
	user_handle = _user_handle_for_id(user_id)

	options = generate_registration_options(
		rp_id=rp_id,
		rp_name=rp_name,
		user_id=user_handle,
		user_name=username,
		user_display_name=username,
		exclude_credentials=exclude_credentials if exclude_credentials else None,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement.PREFERRED,
			user_verification=UserVerificationRequirement.PREFERRED,
		),
	)

	# Store challenge for later verification
	challenge_b64 = bytes_to_base64url(options.challenge)
	store_registration_challenge(conn, challenge_b64, user_id, username)

	# Convert to JSON-serializable dict
	return _options_to_dict(options)


def verify_registration(
	credential_json: dict[str, Any],
	expected_challenge: str,
	expected_origin: str,
	expected_rp_id: str,
) -> PasskeyRegistrationResult:
	"""Verify a WebAuthn registration response.
	
	Args:
		credential_json: The credential response from the browser
		expected_challenge: The challenge we stored (base64url)
		expected_origin: Expected origin (e.g., "https://vpn.example.com")
		expected_rp_id: Expected RP ID (domain)
		
	Returns:
		PasskeyRegistrationResult with credential info
		
	Raises:
		webauthn.errors.InvalidRegistrationResponse: On verification failure
	"""
	# Parse the credential from browser JSON (camelCase) to py-webauthn dataclass (snake_case)
	credential = _parse_registration_credential(credential_json)

	verification = verify_registration_response(
		credential=credential,
		expected_challenge=base64url_to_bytes(expected_challenge),
		expected_origin=expected_origin,
		expected_rp_id=expected_rp_id,
	)

	# Extract transports if available
	transports = None
	if hasattr(credential, "response") and hasattr(credential.response, "transports"):
		transports = credential.response.transports
	if transports:
		transports = [str(t.value) if hasattr(t, "value") else str(t) for t in transports]

	return PasskeyRegistrationResult(
		credential_id=bytes_to_base64url(verification.credential_id),
		public_key=verification.credential_public_key,
		sign_count=verification.sign_count,
		transports=transports,
	)


def get_authentication_options(
	conn: sqlite3.Connection,
	rp_id: str,
	user_id: int | None = None,
	credential_ids: list[str] | None = None,
) -> dict[str, Any]:
	"""Generate WebAuthn authentication options (PublicKeyCredentialRequestOptions).
	
	Args:
		conn: Database connection
		rp_id: Relying Party ID
		user_id: User ID (None for usernameless/discoverable credential flow)
		credential_ids: List of allowed credential IDs (base64url) for this user
		
	Returns:
		Dictionary suitable for JSON serialization to frontend
		
	Raises:
		ValueError: If credential_ids contains invalid base64url strings
	"""
	allow_credentials = None
	if credential_ids:
		allow_credentials = []
		for cred_id in credential_ids:
			_validate_base64url(cred_id, "credential_id")
			allow_credentials.append(
				PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
			)

	options = generate_authentication_options(
		rp_id=rp_id,
		allow_credentials=allow_credentials,
		user_verification=UserVerificationRequirement.PREFERRED,
	)

	# Store challenge
	challenge_b64 = bytes_to_base64url(options.challenge)
	store_authentication_challenge(conn, challenge_b64, user_id)

	return _options_to_dict(options)


def verify_authentication(
	credential_json: dict[str, Any],
	expected_challenge: str,
	expected_origin: str,
	expected_rp_id: str,
	credential_public_key: bytes,
	credential_current_sign_count: int,
) -> PasskeyAuthenticationResult:
	"""Verify a WebAuthn authentication response.
	
	Args:
		credential_json: The credential response from the browser
		expected_challenge: The challenge we stored (base64url)
		expected_origin: Expected origin
		expected_rp_id: Expected RP ID
		credential_public_key: The stored public key for this credential
		credential_current_sign_count: The current sign count in DB
		
	Returns:
		PasskeyAuthenticationResult with new sign count
		
	Raises:
		webauthn.errors.InvalidAuthenticationResponse: On verification failure
	"""
	# Parse the credential from browser JSON (camelCase) to py-webauthn dataclass (snake_case)
	credential = _parse_authentication_credential(credential_json)

	verification = verify_authentication_response(
		credential=credential,
		expected_challenge=base64url_to_bytes(expected_challenge),
		expected_origin=expected_origin,
		expected_rp_id=expected_rp_id,
		credential_public_key=credential_public_key,
		credential_current_sign_count=credential_current_sign_count,
	)

	return PasskeyAuthenticationResult(
		credential_id=bytes_to_base64url(verification.credential_id),
		new_sign_count=verification.new_sign_count,
	)


def _options_to_dict(options: Any) -> dict[str, Any]:
	"""Convert webauthn options object to JSON-serializable dict.
	
	Handles bytes -> base64url conversion for challenge and IDs.
	"""
	# The webauthn library options have a json() method or can be dict-ified
	if hasattr(options, "model_dump"):
		# Pydantic v2
		data = options.model_dump()
	elif hasattr(options, "dict"):
		# Pydantic v1
		data = options.dict()
	elif hasattr(options, "__dict__"):
		# Fallback for unexpected types - log warning
		_log.warning(
			"_options_to_dict: falling back to __dict__ for %s - verify webauthn library compatibility",
			type(options).__name__,
		)
		data = options.__dict__.copy()
	else:
		raise TypeError(f"Cannot convert {type(options).__name__} to dict")

	# Recursively convert bytes to base64url strings
	return _convert_bytes_recursive(data)


def _convert_bytes_recursive(obj: Any, _depth: int = 0, _seen: set[int] | None = None) -> Any:
	"""Recursively convert bytes objects to base64url strings and dataclasses to dicts.
	
	Args:
		obj: Object to convert
		_depth: Current recursion depth (internal use)
		_seen: Set of visited object IDs to prevent cycles (internal use)
		
	Raises:
		RecursionError: If maximum depth exceeded or circular reference detected
	"""
	# Protect against infinite recursion
	if _depth > 100:
		raise RecursionError("Maximum recursion depth exceeded in _convert_bytes_recursive")
	
	# Protect against circular references
	if _seen is None:
		_seen = set()
	
	# For mutable objects, check if we've seen them before
	obj_id = id(obj)
	if isinstance(obj, (dict, list)) and obj_id in _seen:
		raise RecursionError("Circular reference detected in _convert_bytes_recursive")
	
	if isinstance(obj, bytes):
		return bytes_to_base64url(obj)
	
	if isinstance(obj, dict):
		_seen.add(obj_id)
		try:
			return {k: _convert_bytes_recursive(v, _depth + 1, _seen) for k, v in obj.items()}
		finally:
			_seen.discard(obj_id)
	
	if isinstance(obj, list):
		_seen.add(obj_id)
		try:
			return [_convert_bytes_recursive(item, _depth + 1, _seen) for item in obj]
		finally:
			_seen.discard(obj_id)
	
	# Handle enums (use isinstance to avoid false positives)
	if isinstance(obj, enum.Enum):
		return obj.value
	
	# Handle known WebAuthn/Pydantic models (whitelist approach)
	# Only serialize objects that have both __dict__ and a known serialization pattern
	if hasattr(obj, "__dict__") and not isinstance(obj, type):
		# Whitelist: only serialize if it looks like a WebAuthn struct or dataclass
		if hasattr(obj, "__class__") and (
			obj.__class__.__module__.startswith("webauthn")
			or hasattr(obj, "__dataclass_fields__")
			or hasattr(obj, "model_fields")  # Pydantic
		):
			return {k: _convert_bytes_recursive(v, _depth + 1, _seen) for k, v in obj.__dict__.items()}
		# Unknown object type - log warning and skip
		_log.warning(
			"_convert_bytes_recursive: skipping unknown object type %s",
			type(obj).__name__,
		)
	
	return obj


def parse_transports(transports_json: str | None) -> list[str]:
	"""Parse transports JSON string from DB to list."""
	if not transports_json:
		return []
	try:
		return json.loads(transports_json)
	except (json.JSONDecodeError, TypeError):
		return []


def serialize_transports(transports: list[str] | None) -> str | None:
	"""Serialize transports list to JSON string for DB storage."""
	if not transports:
		return None
	return json.dumps(transports)


def _clear_challenge_cache(conn: sqlite3.Connection) -> None:
	"""Clear all challenges from database. FOR TESTING ONLY.
	
	Args:
		conn: Database connection
		
	Raises:
		RuntimeError: If not in test mode
	"""
	if not os.environ.get("TESTING"):
		raise RuntimeError("Refusing to clear challenge cache outside test mode")
	
	from ..db.sqlite_runtime import transaction
	with transaction(conn):
		conn.execute("DELETE FROM passkey_challenges")
	
	_log.warning("Challenge cache cleared (test mode)")
