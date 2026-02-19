#!/usr/bin/env python3
#
# app/models/peers.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard peer-related Pydantic models."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class PeerCreate(BaseModel):
	"""Peer creation payload."""
	name: Optional[str] = Field(None, max_length=128)
	description: Optional[str] = Field(None, max_length=512)
	allowed_ips: str = Field(..., min_length=1, max_length=256)
	allowed_ips_mode: Literal["full", "split", "custom"] = "full"
	client_isolation: bool = Field(
		default=False,
		description="Block peer-to-peer communication via server-side firewall rules",
	)
	endpoint: Optional[str] = Field(None, max_length=256)
	interface: str = Field(default="wg0", max_length=32)
	use_adblocker: bool = True
	blocklist_ids: Optional[list[str]] = Field(
		None,
		description="Enabled blocklist IDs (null=all, []=none, ['ads','porn']=specific)",
	)
	
	# Optional: provide keys, or let server generate them
	public_key: Optional[str] = None
	private_key: Optional[str] = None
	preshared_key: Optional[str] = None

	@field_validator("interface")
	@classmethod
	def interface_valid(cls, v: str) -> str:
		if not re.fullmatch(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$", v):
			raise ValueError("Interface must start with letter, max 15 chars, alphanumeric with - or _")
		return v

	@field_validator("public_key", "private_key", "preshared_key")
	@classmethod
	def validate_key(cls, v: Optional[str]) -> Optional[str]:
		if v is None:
			return v
		if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", v):
			raise ValueError("Invalid WireGuard key format (must be 44-char base64)")
		return v


class PeerUpdate(BaseModel):
	"""Peer update payload."""
	name: Optional[str] = Field(None, max_length=128)
	description: Optional[str] = Field(None, max_length=512)
	allowed_ips: Optional[str] = Field(None, max_length=256)
	allowed_ips_mode: Optional[Literal["full", "split", "custom"]] = None
	client_isolation: Optional[bool] = Field(
		None,
		description="Block peer-to-peer communication via server-side firewall rules",
	)
	endpoint: Optional[str] = Field(None, max_length=256)
	is_enabled: Optional[bool] = None
	use_adblocker: Optional[bool] = None
	blocklist_ids: Optional[list[str]] = Field(
		None,
		description="Enabled blocklist IDs (null=all, []=none, ['ads','porn']=specific)",
	)


class PeerPublic(BaseModel):
	"""Public peer representation."""
	id: int
	public_key: str
	name: Optional[str] = None
	description: Optional[str] = None
	allowed_ips: str
	allowed_ips_mode: Literal["full", "split", "custom"] = "full"
	client_isolation: bool = False
	peer_address: Optional[str] = None
	endpoint: Optional[str] = None
	interface: str
	is_enabled: bool
	use_adblocker: bool = True
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

	@staticmethod
	def _sanitize_config_value(value: str) -> str:
		"""Prevent newline injection in WireGuard config."""
		if "\n" in value or "\r" in value:
			raise ValueError(f"Config value contains newline: {value!r}")
		return value

	def to_wg_config(self) -> str:
		"""Generate WireGuard config file content."""
		# Sanitize all values to prevent config injection
		private_key = self._sanitize_config_value(self.private_key)
		address = self._sanitize_config_value(self.address)
		server_public_key = self._sanitize_config_value(self.server_public_key)
		server_endpoint = self._sanitize_config_value(self.server_endpoint)
		allowed_ips = self._sanitize_config_value(self.allowed_ips)
		
		parts = [
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
