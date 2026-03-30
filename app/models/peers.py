#!/usr/bin/env python3
#
# app/models/peers.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard peer-related Pydantic models."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

__all__ = [
	"PeerCreate",
	"PeerUpdate",
	"PeerPublic",
	"PeerConfig",
	"PeerStats",
]

_INTERFACE_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,14}")
_WG_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=")
_BLOCKLIST_ID_RE = re.compile(r"[a-z0-9_-]{1,64}")
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _validate_interface_name(value: str) -> str:
	value = value.strip()
	if not _INTERFACE_RE.fullmatch(value):
		raise ValueError("Interface must start with letter, max 15 chars, alphanumeric with - or _")
	return value


def _validate_wg_key(value: Optional[str]) -> Optional[str]:
	if value is None:
		return value
	value = value.strip()
	if not _WG_KEY_RE.fullmatch(value):
		raise ValueError("Invalid WireGuard key format (must be 44-char base64)")
	return value


def _normalize_csv(value: str, *, field_name: str) -> list[str]:
	items = [item.strip() for item in value.split(",") if item.strip()]
	if not items:
		raise ValueError(f"{field_name} must not be empty")
	return items


def _validate_cidr_list(value: str, *, field_name: str) -> str:
	items = _normalize_csv(value, field_name=field_name)
	for item in items:
		try:
			ipaddress.ip_network(item, strict=False)
		except ValueError as exc:
			raise ValueError(f"Invalid CIDR in {field_name}: {item!r}") from exc
	return ", ".join(items)


def _validate_interface_list(value: str, *, field_name: str) -> str:
	items = _normalize_csv(value, field_name=field_name)
	for item in items:
		try:
			ipaddress.ip_interface(item)
		except ValueError as exc:
			raise ValueError(f"Invalid interface address in {field_name}: {item!r}") from exc
	return ", ".join(items)


def _validate_ip_list(value: str, *, field_name: str) -> str:
	items = _normalize_csv(value, field_name=field_name)
	for item in items:
		try:
			ipaddress.ip_address(item)
		except ValueError as exc:
			raise ValueError(f"Invalid IP address in {field_name}: {item!r}") from exc
	return ", ".join(items)


def _validate_hostname(host: str) -> str:
	if len(host) > 253:
		raise ValueError("Host is too long")
	labels = host.split(".")
	if any(not label for label in labels):
		raise ValueError("Host contains an empty label")
	if not all(_HOST_LABEL_RE.fullmatch(label) for label in labels):
		raise ValueError("Host contains invalid characters")
	return host


def _validate_endpoint_value(value: Optional[str]) -> Optional[str]:
	if value is None:
		return value
	candidate = value.strip()
	if not candidate:
		return None

	if candidate.startswith("["):
		match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", candidate)
		if not match:
			raise ValueError(f"Invalid endpoint format: {candidate!r}")
		host = match.group(1)
		port_raw = match.group(2)
		try:
			ipaddress.ip_address(host)
		except ValueError as exc:
			raise ValueError(f"Invalid IPv6 endpoint host: {host!r}") from exc
	else:
		if candidate.count(":") != 1:
			raise ValueError(f"Invalid endpoint format: {candidate!r}")
		host, port_raw = candidate.rsplit(":", 1)
		host = host.strip()
		if not host:
			raise ValueError(f"Invalid endpoint format: {candidate!r}")
		try:
			ipaddress.ip_address(host)
		except ValueError:
			_validate_hostname(host)

	port = int(port_raw)
	if port < 1 or port > 65535:
		raise ValueError(f"Endpoint port out of range: {port}")
	return candidate


def _validate_blocklist_ids(value: Optional[list[str]]) -> Optional[list[str]]:
	if value is None:
		return value
	validated: list[str] = []
	for item in value:
		candidate = item.strip()
		if not _BLOCKLIST_ID_RE.fullmatch(candidate):
			raise ValueError(f"Invalid blocklist ID: {item!r}")
		validated.append(candidate)
	return validated


class PeerCreate(BaseModel):
	"""Peer creation payload."""
	name: str = Field(..., min_length=1, max_length=128, description="Display name for this peer (required)")
	allowed_ips: str = Field(..., min_length=1, max_length=256)
	allowed_ips_mode: Literal["full", "split", "custom"] = "full"
	client_isolation: bool = Field(
		default=False,
		description="Block peer-to-peer communication via server-side firewall rules",
	)
	endpoint: Optional[str] = Field(None, max_length=256)
	interface: str = Field(default="wg0", max_length=32)
	node_id: Optional[str] = Field(
		None,
		max_length=64,
		description="Assign peer to a remote node (null=local/master)",
	)
	use_adblocker: bool = True
	dns_logging_enabled: bool = Field(
		default=True,
		description="Enable DNS query logging for this peer",
	)
	blocklist_ids: Optional[list[str]] = Field(
		None,
		description="Enabled blocklist IDs (null=all, []=none, ['ads','porn']=specific)",
	)
	
	# Optional: provide keys, or let server generate them
	public_key: Optional[str] = None
	private_key: Optional[str] = None
	preshared_key: Optional[str] = None

	@field_validator("name")
	@classmethod
	def name_not_blank(cls, v: str) -> str:
		if not v or not v.strip():
			raise ValueError("Peer name is required and cannot be blank")
		return v.strip()

	@field_validator("interface")
	@classmethod
	def interface_valid(cls, v: str) -> str:
		return _validate_interface_name(v)

	@field_validator("allowed_ips")
	@classmethod
	def allowed_ips_valid(cls, v: str) -> str:
		return _validate_cidr_list(v, field_name="allowed_ips")

	@field_validator("endpoint")
	@classmethod
	def endpoint_valid(cls, v: Optional[str]) -> Optional[str]:
		return _validate_endpoint_value(v)

	@field_validator("blocklist_ids")
	@classmethod
	def blocklist_ids_valid(cls, v: Optional[list[str]]) -> Optional[list[str]]:
		return _validate_blocklist_ids(v)

	@field_validator("public_key", "private_key", "preshared_key")
	@classmethod
	def validate_key(cls, v: Optional[str]) -> Optional[str]:
		return _validate_wg_key(v)


class PeerUpdate(BaseModel):
	"""Peer update payload."""
	name: Optional[str] = Field(None, max_length=128)
	allowed_ips: Optional[str] = Field(None, max_length=256)
	allowed_ips_mode: Optional[Literal["full", "split", "custom"]] = None
	client_isolation: Optional[bool] = Field(
		None,
		description="Block peer-to-peer communication via server-side firewall rules",
	)
	endpoint: Optional[str] = Field(None, max_length=256)
	is_enabled: Optional[bool] = None
	use_adblocker: Optional[bool] = None
	dns_logging_enabled: Optional[bool] = None
	blocklist_ids: Optional[list[str]] = Field(
		None,
		description="Enabled blocklist IDs (null=all, []=none, ['ads','porn']=specific)",
	)
	node_id: Optional[str] = Field(
		None,
		max_length=64,
		description="Migrate peer to a different node (null=local/master)",
	)

	@field_validator("name")
	@classmethod
	def name_not_blank_if_provided(cls, v: Optional[str]) -> Optional[str]:
		if v is not None and not v.strip():
			raise ValueError("Peer name cannot be blank")
		return v.strip() if v else v

	@field_validator("allowed_ips")
	@classmethod
	def allowed_ips_valid(cls, v: Optional[str]) -> Optional[str]:
		if v is None:
			return v
		return _validate_cidr_list(v, field_name="allowed_ips")

	@field_validator("endpoint")
	@classmethod
	def endpoint_valid(cls, v: Optional[str]) -> Optional[str]:
		return _validate_endpoint_value(v)

	@field_validator("blocklist_ids")
	@classmethod
	def blocklist_ids_valid(cls, v: Optional[list[str]]) -> Optional[list[str]]:
		return _validate_blocklist_ids(v)


class PeerPublic(BaseModel):
	"""Public peer representation."""
	id: int
	public_key: str
	name: Optional[str] = None
	allowed_ips: str
	allowed_ips_mode: Literal["full", "split", "custom"] = "full"
	client_isolation: bool = False
	peer_address: Optional[str] = None
	endpoint: Optional[str] = None
	interface: str
	node_id: Optional[str] = None
	is_enabled: bool
	use_adblocker: bool = True
	dns_logging_enabled: bool = True
	blocklist_ids: Optional[list[str]] = None  # null=all enabled
	created_at: datetime
	updated_at: datetime


class PeerConfig(BaseModel):
	"""Full peer configuration (for QR code / config file)."""
	interface_name: str
	private_key: str
	address: str
	dns: Optional[str] = None
	mtu: int = Field(default=1420, ge=1280, le=65535)
	# Server details
	server_public_key: str
	server_endpoint: str
	allowed_ips: str = "0.0.0.0/0, ::/0"
	persistent_keepalive: int = Field(default=25, ge=0, le=65535)
	preshared_key: Optional[str] = None

	@field_validator("interface_name")
	@classmethod
	def interface_name_valid(cls, v: str) -> str:
		return _validate_interface_name(v)

	@field_validator("private_key", "server_public_key", "preshared_key")
	@classmethod
	def validate_key(cls, v: Optional[str]) -> Optional[str]:
		return _validate_wg_key(v)

	@field_validator("address")
	@classmethod
	def address_valid(cls, v: str) -> str:
		return _validate_interface_list(v, field_name="address")

	@field_validator("dns")
	@classmethod
	def dns_valid(cls, v: Optional[str]) -> Optional[str]:
		if v is None:
			return v
		return _validate_ip_list(v, field_name="dns")

	@field_validator("server_endpoint")
	@classmethod
	def server_endpoint_valid(cls, v: str) -> str:
		validated = _validate_endpoint_value(v)
		if validated is None:
			raise ValueError("server_endpoint must not be empty")
		return validated

	@field_validator("allowed_ips")
	@classmethod
	def allowed_ips_valid(cls, v: str) -> str:
		return _validate_cidr_list(v, field_name="allowed_ips")

	@staticmethod
	def _sanitize_config_value(value: str) -> str:
		"""Prevent newline injection in WireGuard config."""
		if any(char in value for char in ("\n", "\r", "\x00")):
			raise ValueError(f"Config value contains illegal control character: {value!r}")
		return value.strip()

	def to_wg_config(self) -> str:
		"""Generate WireGuard config file content."""
		# Sanitize all values to prevent config injection
		private_key = self._sanitize_config_value(self.private_key)
		address = self._sanitize_config_value(self.address)
		server_public_key = self._sanitize_config_value(self.server_public_key)
		server_endpoint = self._sanitize_config_value(self.server_endpoint)
		allowed_ips = self._sanitize_config_value(self.allowed_ips)
		
		parts = [
			f"# WireBuddy peer config for interface {self.interface_name}",
			"[Interface]",
			f"PrivateKey = {private_key}",
			f"Address = {address}",
			f"MTU = {self.mtu}",
		]
		
		if self.dns:
			dns = self._sanitize_config_value(self.dns)
			parts.append(f"DNS = {dns}")
		
		parts.extend([
			"",
			"[Peer]",
			f"PublicKey = {server_public_key}",
			f"AllowedIPs = {allowed_ips}",
			f"Endpoint = {server_endpoint}",
			f"PersistentKeepalive = {self.persistent_keepalive}",
		])
		
		if self.preshared_key:
			psk = self._sanitize_config_value(self.preshared_key)
			parts.append(f"PresharedKey = {psk}")
		
		return "\n".join(parts) + "\n"


class PeerStats(BaseModel):
	"""Peer statistics from WireGuard."""
	public_key: str
	endpoint: Optional[str] = None
	latest_handshake: Optional[datetime] = None
	transfer_rx: int = Field(default=0, ge=0)  # bytes received
	transfer_tx: int = Field(default=0, ge=0)  # bytes transmitted
	allowed_ips: Optional[str] = None
