#!/usr/bin/env python3
#
# app/api/wireguard_interfaces_crud.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface create/update/delete endpoints."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import logging
import re
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..db.sqlite_interfaces import (
	create_interface as db_create_interface,
)
from ..db.sqlite_interfaces import (
	delete_interface as db_delete_interface,
)
from ..db.sqlite_interfaces import (
	delete_peers_by_interface,
	get_interface,
	list_interfaces,
)
from ..db.sqlite_interfaces import (
	update_interface as db_update_interface,
)
from ..db.sqlite_nodes import (
	bump_config_version_for_interface,
	bump_node_config_version,
	create_node_interface,
	delete_node_interfaces,
	get_all_nodes,
)
from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import (
	get_dns_blocklist_enabled,
	get_dns_query_logging_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_setting,
	set_dns_service_enabled,
)
from ..dns import unbound_process as unbound
from ..dns.unbound_config import write_config as write_unbound_config
from ..dns.unbound_config import write_local_data_overrides
from ..node import notifier as node_notifier
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_config, get_conn, get_tsdb_dir
from ..utils.vault import encrypt as vault_encrypt
from .auth import require_admin
from .response import ok_response
from .wireguard_config import _validate_hook, write_interface_config
from .wireguard_utils import generate_keypair, run_wg_command, validate_interface_name

_log = logging.getLogger(__name__)

# Sentinel telling an omitted field apart from an explicit False.
_UNSET = object()

router = APIRouter()

__all__ = ["InterfaceCreate", "InterfaceUpdate", "router"]

# Outbound interface names must use this restricted character set.
_OUTBOUND_IFACE_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_split_dns_sync(conn: sqlite3.Connection) -> tuple[int, str | None]:
	"""Read the split-DNS inputs and rewrite the override file.

	Blocking (SQLite + filesystem); call via ``run_in_threadpool``.
	"""
	interfaces = list_interfaces(conn)
	fqdn = get_setting(conn, "wg_fqdn")
	return write_local_data_overrides(interfaces, fqdn), fqdn


async def _regenerate_split_dns(conn: sqlite3.Connection) -> str | None:
	"""Regenerate split-DNS local-data and reload Unbound.

	Called after interface create/update/delete to ensure DNS overrides
	for wg_fqdn point to the correct internal addresses.

	Returns a warning string on failure so callers can surface it in the
	response payload without failing the overall operation.
	"""
	try:
		count, fqdn = await run_in_threadpool(_write_split_dns_sync, conn)
		if count > 0:
			ok, msg = await unbound.reload_config()
			if ok:
				_log.info("SPLIT_DNS_UPDATED records=%d fqdn=%s", count, fqdn)
			else:
				_log.warning("SPLIT_DNS_RELOAD_FAILED records=%d msg=%s", count, msg)
				return f"Split-DNS reload failed: {msg}"
	# Catch only expected errors; let programming errors propagate
	except (OSError, sqlite3.Error) as exc:
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return f"Split-DNS regeneration failed: {exc}"
	return None


def _read_unbound_settings_sync(conn: sqlite3.Connection) -> dict[str, object]:
	"""Read the Unbound config inputs in one go.

	Blocking; call via ``run_in_threadpool`` so a DB lock cannot stall the event
	loop while the individual getters run.
	"""
	return {
		"enable_logging": get_dns_query_logging_enabled(conn),
		"enable_blocklist": get_dns_blocklist_enabled(conn),
		"upstream_dns": get_dns_upstream_servers(conn),
		"enable_dnssec": get_dnssec_enabled(conn),
	}


def _read_create_preflight_sync(conn: sqlite3.Connection, name: str) -> tuple[bool, list[sqlite3.Row]]:
	"""Return whether the interface already exists, plus all existing interfaces.

	Blocking; call via ``run_in_threadpool``.
	"""
	return get_interface(conn, name) is not None, list_interfaces(conn)


def _read_create_preflight_rows_sync(conn: sqlite3.Connection, name: str) -> tuple[sqlite3.Row | None, list[sqlite3.Row]]:
	"""Return the interface row (or None), plus all existing interfaces.

	Blocking; call via ``run_in_threadpool``.
	"""
	return get_interface(conn, name), list_interfaces(conn)


def _interface_exists_sync(conn: sqlite3.Connection, name: str) -> bool:
	"""Return whether an interface row exists.

	Blocking; call via ``run_in_threadpool``.
	"""
	return get_interface(conn, name) is not None


def _read_enrolled_nodes_sync(conn: sqlite3.Connection) -> list[sqlite3.Row]:
	"""Return the nodes that have completed enrollment.

	Blocking; call via ``run_in_threadpool``.
	"""
	return [node for node in get_all_nodes(conn) if node["status"] in ("online", "offline")]


def _provision_node_interface_sync(
	conn: sqlite3.Connection,
	*,
	node_id: str,
	interface_name: str,
	private_key: str,
	public_key: str,
) -> str:
	"""Store a node's keypair for an interface and return its new config version.

	Blocking; call via ``run_in_threadpool``.
	"""
	create_node_interface(conn, node_id, interface_name, private_key, public_key)
	return bump_node_config_version(conn, node_id)


def _get_default_route_iface() -> str:
	"""Detect the system's default outbound network interface.

	Reads /proc/net/route for the entry with Destination=0.0.0.0 and
	Mask=0.0.0.0 (all values in hex). Falls back to 'eth0' if detection
	fails.
	"""
	try:
		with Path("/proc/net/route").open() as fh:
			next(fh)  # skip header line
			for line in fh:
				parts = line.split()
				# Columns: Iface Dest Gateway Flags RefCnt Use Metric Mask ...
				if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
					detected = parts[0]
					_log.debug("AUTO_DETECTED_DEFAULT_ROUTE_IFACE iface=%s", detected)
					return detected
	except (OSError, StopIteration, IndexError):
		pass
	_log.warning("Could not detect default route interface, falling back to eth0")
	return "eth0"


def _script_fingerprint(script: str | None) -> str:
	"""Return a short stable fingerprint for script audit logging."""
	if not script:
		return "none"
	digest = hashlib.sha256(script.encode("utf-8", errors="replace")).hexdigest()[:12]
	return f"sha256:{digest} len:{len(script)}"


def _validate_interface_addresses(
	address: str,
	address6: str | None,
) -> tuple[ipaddress.IPv4Interface, str | None]:
	"""Validate the already-resolved IPv4/IPv6 address strings for an interface.

	Shared by create and update: callers resolve their own effective address
	(create uses the payload directly; update falls back to the existing row
	for PATCH-omitted fields) before calling this.

	Raises:
		HTTPException(422): On invalid format, wrong IP version, or a
			host-only prefix (interfaces need a subnet, not a /32 or /128).
	"""
	try:
		v4 = ipaddress.ip_interface(address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid address: {address}")
	if v4.version != 4:
		raise HTTPException(status_code=422, detail="address must be an IPv4 CIDR (e.g. 10.0.0.1/24)")
	if v4.network.prefixlen == 32:
		raise HTTPException(
			status_code=422,
			detail="address must include a subnet prefix (e.g. /24), not a /32 host address",
		)

	if address6:
		try:
			v6_obj = ipaddress.ip_interface(address6)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {address6}")
		if v6_obj.version != 6:
			raise HTTPException(status_code=422, detail="address6 must be an IPv6 CIDR (e.g. fd00::1/64)")
		if v6_obj.network.prefixlen == 128:
			raise HTTPException(
				status_code=422,
				detail="address6 must include a subnet prefix (e.g. /64), not a /128 host address",
			)

	return v4, (address6 or None)


def _check_subnet_and_port_conflicts(
	new_v4_net: ipaddress.IPv4Network,
	new_v6_net: ipaddress.IPv6Network | None,
	new_listen_port: int,
	existing_interfaces: list[sqlite3.Row],
	*,
	exclude_name: str | None = None,
) -> None:
	"""Reject subnet overlaps or a duplicate listen port against other interfaces.

	``exclude_name`` skips the row being updated (create has no such row yet,
	so it is always None there; update must pass its own name or every save
	would conflict with itself).

	Raises:
		HTTPException(409): On overlap or listen-port conflict.
	"""
	for iface in existing_interfaces:
		if exclude_name is not None and iface["name"] == exclude_name:
			continue
		if iface["address"]:
			try:
				existing_v4 = ipaddress.ip_interface(iface["address"]).network
				if new_v4_net.overlaps(existing_v4):
					raise HTTPException(
						status_code=409,
						detail=f"IPv4 subnet {new_v4_net} overlaps with interface '{iface['name']}' ({existing_v4})",
					)
			except ValueError as exc:
				# Ignore malformed legacy entries but keep the diagnostic log.
				_log.debug("Skipping invalid IPv4 address in DB for interface %s: %s", iface["name"], exc)
		if new_v6_net and iface["address6"]:
			try:
				existing_v6 = ipaddress.ip_interface(iface["address6"]).network
				if new_v6_net.overlaps(existing_v6):
					raise HTTPException(
						status_code=409,
						detail=f"IPv6 subnet {new_v6_net} overlaps with interface '{iface['name']}' ({existing_v6})",
					)
			except ValueError as exc:
				# Ignore malformed legacy entries but keep the diagnostic log.
				_log.debug("Skipping invalid IPv6 address in DB for interface %s: %s", iface["name"], exc)
		if iface["listen_port"] == new_listen_port:
			raise HTTPException(
				status_code=409,
				detail=f"Listen port {new_listen_port} is already used by interface '{iface['name']}'",
			)


class InterfaceCreate(BaseModel):
	"""Schema for creating a new WireGuard interface."""

	name: str = Field(..., min_length=1, max_length=15, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
	address: str = Field(
		default="10.13.13.1/24",
		min_length=7,
		description="IPv4 interface address with subnet (e.g., 10.13.13.1/24)",
	)
	address6: str | None = Field(
		default="fd13:13:13::1/64",
		description="IPv6 interface address with prefix (e.g., fd13:13:13::1/64). Set to empty string to disable.",
	)
	listen_port: int = Field(default=51820, ge=1, le=65535)
	dns: str | None = Field(default=None, description="DNS servers for clients")
	post_up: str | None = Field(default=None, description="PostUp script")
	post_down: str | None = Field(default=None, description="PostDown script")
	show_on_dashboard: bool = Field(
		default=True,
		description="Show this interface on dashboard network gauges",
	)


class InterfaceUpdate(BaseModel):
	"""Schema for updating an existing WireGuard interface.

	Note: This endpoint uses PATCH semantics – only explicitly provided
	fields are updated; omitted fields retain their current values.
	"""

	address: str | None = Field(
		default=None,
		min_length=7,
		description="IPv4 interface address with subnet (e.g., 10.13.13.1/24)",
	)
	address6: str | None = Field(
		default=None,
		description="IPv6 interface address with prefix (optional)",
	)
	listen_port: int | None = Field(default=None, ge=1, le=65535)
	dns: str | None = Field(default=None, description="DNS servers for clients")
	post_up: str | None = Field(default=None, description="PostUp script")
	post_down: str | None = Field(default=None, description="PostDown script")
	show_on_dashboard: bool | None = Field(
		default=None,
		description="Show this interface on dashboard network gauges",
	)


def _build_default_firewall_rules(
	v4_subnet: str,
	v6_subnet: str | None,
	outbound_iface: str = "eth0",
) -> tuple[str, str]:
	"""Build default PostUp/PostDown iptables rules for NAT and DNS."""
	if not _OUTBOUND_IFACE_RE.fullmatch(outbound_iface):
		raise ValueError(f"Suspicious outbound interface name: {outbound_iface!r}")
	try:
		v4_net = ipaddress.ip_network(v4_subnet, strict=False)
		if v4_net.version != 4:
			raise ValueError("v4_subnet must be IPv4")
	except ValueError as exc:
		raise ValueError(f"Invalid IPv4 subnet for firewall rules: {v4_subnet!r}") from exc

	v6_net_str: str | None = None
	if v6_subnet:
		try:
			v6_net = ipaddress.ip_network(v6_subnet, strict=False)
			if v6_net.version != 6:
				raise ValueError("v6_subnet must be IPv6")
			v6_net_str = str(v6_net)
		except ValueError as exc:
			raise ValueError(f"Invalid IPv6 subnet for firewall rules: {v6_subnet!r}") from exc

	oi = outbound_iface
	v4_subnet_safe = str(v4_net)
	up_rules = [
		f"iptables -t nat -A POSTROUTING -s {v4_subnet_safe} -o {oi} -j MASQUERADE",
		"iptables -A FORWARD -i %i -j ACCEPT",
		"iptables -A FORWARD -o %i -j ACCEPT",
		"iptables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
	]
	down_rules = [
		f"iptables -t nat -D POSTROUTING -s {v4_subnet_safe} -o {oi} -j MASQUERADE",
		"iptables -D FORWARD -i %i -j ACCEPT",
		"iptables -D FORWARD -o %i -j ACCEPT",
		"iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
	]

	if v6_net_str:
		up_rules += [
			f"ip6tables -t nat -A POSTROUTING -s {v6_net_str} -o {oi} -j MASQUERADE",
			"ip6tables -A FORWARD -i %i -j ACCEPT",
			"ip6tables -A FORWARD -o %i -j ACCEPT",
			"ip6tables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
		]
		down_rules += [
			f"ip6tables -t nat -D POSTROUTING -s {v6_net_str} -o {oi} -j MASQUERADE",
			"ip6tables -D FORWARD -i %i -j ACCEPT",
			"ip6tables -D FORWARD -o %i -j ACCEPT",
			"ip6tables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
		]

	return "; ".join(up_rules), "; ".join(down_rules)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _persist_new_interface_sync(
	conn: sqlite3.Connection,
	*,
	payload: InterfaceCreate,
	config_path: Path,
	private_key_encrypted: str,
	public_key: str,
	v6_str: str | None,
	post_up: str | None,
	post_down: str | None,
	pepper: str,
) -> None:
	"""Insert the interface row and write its config; undo both on failure.

	Blocking (SQLite + filesystem); call via ``run_in_threadpool`` and never
	await inside. Raises ``HTTPException`` for client-visible failures.
	"""
	conf_file = config_path / f"{payload.name}.conf"
	# Convert unique-name conflicts into a client error.
	try:
		db_create_interface(
			conn,
			name=payload.name,
			private_key=private_key_encrypted,
			public_key=public_key,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=payload.dns,
			post_up=post_up,
			post_down=post_down,
			show_on_dashboard=payload.show_on_dashboard,
		)
	except sqlite3.IntegrityError:
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists")
	except Exception:
		# Log details server-side and return a generic message.
		_log.exception("INTERFACE_DB_CREATE_FAILED name=%s", payload.name)
		raise HTTPException(status_code=500, detail="Failed to save interface; please check server logs")

	# Use keyword arguments and clean up partial files on failure.
	try:
		write_interface_config(
			config_path=config_path,
			name=payload.name,
			private_key=private_key_encrypted,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=payload.dns,
			post_up=post_up,
			post_down=post_down,
			conn=conn,
			pepper=pepper,
		)
	except Exception:
		_log.exception("INTERFACE_CONFIG_WRITE_FAILED name=%s", payload.name)
		cleanup_ok = True
		try:
			db_delete_interface(conn, payload.name)
		except Exception:
			cleanup_ok = False
			_log.exception("INTERFACE_CREATE_CLEANUP_DB_FAILED name=%s", payload.name)
		try:
			conf_file.unlink(missing_ok=True)
		except Exception:
			cleanup_ok = False
			_log.exception("INTERFACE_CREATE_CLEANUP_FILE_FAILED name=%s", payload.name)
		detail = "Failed to write interface config; the interface was not created"
		if not cleanup_ok:
			detail = "Failed to write interface config; cleanup may be incomplete"
		raise HTTPException(status_code=500, detail=detail)


def _update_interface_sync(
	conn: sqlite3.Connection,
	*,
	name: str,
	config_path: Path,
	private_key: str,
	pepper: str,
	address: str,
	address6: str | None,
	listen_port: int,
	dns: str | None,
	post_up: str | None,
	post_down: str | None,
	show_on_dashboard: bool | None,
) -> None:
	"""Update the DB row and rewrite the config in one transaction.

	Blocking; call via ``run_in_threadpool`` and never await inside. On failure
	the DB rolls back and the previous config file content is restored.
	"""
	conf_file = config_path / f"{name}.conf"
	old_config_content = None
	if conf_file.exists():
		# Continue without a backup if it cannot be read; rollback will be DB-only.
		with contextlib.suppress(OSError):
			old_config_content = conf_file.read_text()

	try:
		with transaction(conn, immediate=True):
			db_update_interface(
				conn,
				name=name,
				address=address,
				address6=address6,
				listen_port=listen_port,
				dns=dns,
				post_up=post_up,
				post_down=post_down,
				show_on_dashboard=show_on_dashboard,
			)
			write_interface_config(
				config_path=config_path,
				name=name,
				private_key=private_key,
				address=address,
				address6=address6,
				listen_port=listen_port,
				dns=dns,
				post_up=post_up,
				post_down=post_down,
				conn=conn,
				pepper=pepper,
			)
	except Exception:
		_log.exception("INTERFACE_UPDATE_FAILED name=%s", name)
		if old_config_content and conf_file.exists():
			try:
				conf_file.write_text(old_config_content)
			except OSError:
				_log.exception("Failed to restore config file during rollback for %s", name)
		# Log details server-side and return a generic message.
		raise HTTPException(status_code=500, detail="Failed to update interface config; changes were rolled back")


def _delete_interface_sync(
	conn: sqlite3.Connection,
	*,
	name: str,
	conf_file: Path,
	db_exists: bool,
	file_exists: bool,
) -> tuple[list[str], dict[str, str], str | None]:
	"""Delete the interface row, its peers, its node keypairs and its config file.

	The config file is renamed to a staging name first and only unlinked after
	the DB transaction committed, so a DB failure restores it and never leaves a
	row without a config. Blocking; call via ``run_in_threadpool``.

	Returns:
		Tuple of (peer public keys for TSDB cleanup, {node_id: new config
		version} for the nodes that lost a keypair, cleanup warning or None).
	"""
	staged: Path | None = None
	if file_exists:
		# The staging name does not end in ".conf", so *.conf scans ignore it.
		staged = conf_file.with_name(f".{conf_file.name}.deleting")
		try:
			conf_file.replace(staged)
		except FileNotFoundError:
			staged = None
		except OSError:
			_log.exception("INTERFACE_FILE_DELETE_FAILED name=%s", name)
			raise HTTPException(status_code=500, detail="Failed to delete interface config file")

	public_keys: list[str] = []
	node_versions: dict[str, str] = {}
	if db_exists:
		try:
			public_keys = [str(peer["public_key"]) for peer in get_all_peers(conn, name)]
		except Exception:
			_log.exception("Failed to fetch peers for interface %s", name)
			# Continue with DB delete even if peer fetch fails.

		try:
			with transaction(conn, immediate=True):
				# Node keypairs must go first: delete_interface() refuses to drop an
				# interface that node_interfaces rows still reference.
				affected_node_ids = delete_node_interfaces(conn, name)
				if affected_node_ids:
					_log.info("INTERFACE_NODE_KEYPAIRS_DELETED name=%s nodes=%d", name, len(affected_node_ids))
				deleted = delete_peers_by_interface(conn, name)
				_log.info("INTERFACE_PEERS_DELETED name=%s count=%d", name, deleted)
				db_delete_interface(conn, name)
				# Recompute after the rows are gone so the version reflects the
				# config the node will actually be served.
				for node_id in affected_node_ids:
					node_versions[node_id] = bump_node_config_version(conn, node_id)
		except Exception:
			_log.exception("INTERFACE_DB_DELETE_FAILED name=%s", name)
			if staged is not None:
				try:
					staged.replace(conf_file)
				except OSError:
					_log.exception("INTERFACE_CONFIG_RESTORE_FAILED name=%s", name)
			raise HTTPException(status_code=500, detail="Failed to delete interface from database")

	# The DB is committed at this point, so a failed unlink must not fail the
	# request - but it leaves the decrypted private key on disk, so it is
	# reported instead of being silently swallowed. Startup cleans up leftovers.
	cleanup_warning: str | None = None
	if staged is not None:
		try:
			staged.unlink(missing_ok=True)
		except OSError:
			_log.exception("INTERFACE_STAGED_CONFIG_UNLINK_FAILED name=%s", name)
			cleanup_warning = "Interface deleted, but its staged private-key configuration could not be removed from disk"
	return public_keys, node_versions, cleanup_warning


@router.post("/interfaces", status_code=201)
async def create_interface(
	request: Request,
	payload: InterfaceCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Create a new WireGuard interface configuration."""
	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{payload.name}.conf"

	if conf_file.exists():
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists")

	# Both reads are one sync unit off the event loop; a DB lock here would
	# otherwise stall every other request for up to the busy_timeout.
	db_exists, existing_interfaces = await run_in_threadpool(_read_create_preflight_sync, conn, payload.name)
	if db_exists:
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists in database")

	v6_str = payload.address6 or None
	v4, v6_str = _validate_interface_addresses(payload.address, v6_str)

	# Check for subnet overlap with existing interfaces
	new_v4_net = v4.network
	new_v6_net = ipaddress.ip_interface(v6_str).network if v6_str else None

	_check_subnet_and_port_conflicts(new_v4_net, new_v6_net, payload.listen_port, existing_interfaces)

	# Validate hook scripts before touching the database or disk.
	try:
		if payload.post_up:
			_validate_hook(payload.post_up, "PostUp")
		if payload.post_down:
			_validate_hook(payload.post_down, "PostDown")
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc))

	private_key, public_key = await generate_keypair()

	# Detect the outbound interface instead of assuming eth0.
	post_up = payload.post_up
	post_down = payload.post_down
	if not post_up or not post_down:
		v4_subnet = str(v4.network)
		v6_subnet = str(ipaddress.ip_interface(v6_str).network) if v6_str else None
		outbound_iface = _get_default_route_iface()
		_log.info("AUTO_DETECTED_OUTBOUND_IFACE iface=%s for interface=%s", outbound_iface, payload.name)
		default_up, default_down = _build_default_firewall_rules(v4_subnet, v6_subnet, outbound_iface)
		if not post_up:
			post_up = default_up
		if not post_down:
			post_down = default_down

	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)

	# DB insert and config write run as one sync unit off the event loop.
	await run_in_threadpool(
		_persist_new_interface_sync,
		conn,
		payload=payload,
		config_path=config_path,
		private_key_encrypted=private_key_encrypted,
		public_key=public_key,
		v6_str=v6_str,
		post_up=post_up,
		post_down=post_down,
		pepper=cfg.secret_key,
	)

	_log.info("INTERFACE_CREATED name=%s address=%s address6=%s", payload.name, payload.address, v6_str)
	if post_up:
		_log.info(
			"INTERFACE_SCRIPT_CREATED name=%s type=PostUp fingerprint=%s",
			payload.name,
			_script_fingerprint(post_up),
		)
	if post_down:
		_log.info(
			"INTERFACE_SCRIPT_CREATED name=%s type=PostDown fingerprint=%s",
			payload.name,
			_script_fingerprint(post_down),
		)

	# Auto-start if this is the first interface
	if config_path.is_dir():
		existing_count = len(list(config_path.glob("*.conf")))
		if existing_count == 1:
			try:
				code, _, stderr = await run_wg_command("wg-quick", "up", payload.name)
				if code == 0:
					_log.info("INTERFACE_AUTO_STARTED name=%s (first interface)", payload.name)
				else:
					_log.warning("Failed to auto-start first interface %s: %s", payload.name, stderr)
			except Exception as exc:
				_log.warning("Exception during auto-start of first interface %s: %s", payload.name, exc)

			# Auto-start Unbound DNS when first interface is created
			try:
				if unbound.is_unbound_installed():
					# Extract IP from interface address (strip CIDR)
					listen_ipv4 = [payload.address.split("/")[0]]
					listen_ipv6 = [v6_str.split("/")[0]] if v6_str else None
					# Write Unbound config with interface IPs
					dns_settings = await run_in_threadpool(_read_unbound_settings_sync, conn)
					await run_in_threadpool(
						write_unbound_config,
						listen_addrs_ipv4=listen_ipv4,
						listen_addrs_ipv6=listen_ipv6,
						**dns_settings,
					)
					ok, msg = await unbound.start()
					if ok:
						await run_in_threadpool(set_dns_service_enabled, conn, True)
						_log.info("UNBOUND_AUTO_STARTED (first interface created)")
					else:
						_log.warning("Failed to auto-start Unbound: %s", msg)
			except Exception as exc:
				_log.warning("Exception during Unbound auto-start: %s", exc)

	data = {
		"name": payload.name,
		"public_key": public_key,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
	}

	# Surface DNS regeneration warnings in the response.
	dns_warning = await _regenerate_split_dns(conn)
	if dns_warning:
		data["warning"] = dns_warning

	# Auto-generate keypairs for all enrolled nodes on the new interface
	# so that peers can be assigned to these nodes immediately.
	try:
		enrolled_nodes = await run_in_threadpool(_read_enrolled_nodes_sync, conn)
		for node in enrolled_nodes:
			node_priv, node_pub = await generate_keypair()
			new_version = await run_in_threadpool(
				_provision_node_interface_sync,
				conn,
				node_id=str(node["id"]),
				interface_name=payload.name,
				private_key=node_priv,
				public_key=node_pub,
			)
			await node_notifier.notify_config_changed(str(node["id"]), new_version)
			_log.info(
				"INTERFACE_CREATE auto-generated keypair for node=%s interface=%s",
				node["name"],
				payload.name,
			)
	except Exception as exc:
		_log.warning("Failed to auto-generate node keypairs for new interface %s: %s", payload.name, exc)

	return ok_response(data=data)


# PUT replaces the full resource; PATCH handles partial updates.
# Current implementation uses PATCH semantics (partial update via model_fields_set).
# Removing @router.put decorator to avoid semantic confusion.
@router.patch("/interfaces/{name}", status_code=200)
async def update_interface(
	request: Request,
	name: str,
	payload: InterfaceUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update (patch) a WireGuard interface config in DB and on disk."""
	validate_interface_name(name)

	iface, other_interfaces = await run_in_threadpool(_read_create_preflight_rows_sync, conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	fields_set = payload.model_fields_set
	if not fields_set:
		raise HTTPException(status_code=422, detail="No fields provided for update")

	new_address = payload.address if "address" in fields_set else iface["address"]
	new_listen_port = payload.listen_port if "listen_port" in fields_set else iface["listen_port"]
	if new_address is None:
		raise HTTPException(status_code=422, detail="address cannot be null")
	if new_listen_port is None:
		raise HTTPException(status_code=422, detail="listen_port cannot be null")

	v6_str = payload.address6 if "address6" in fields_set else iface["address6"]
	v4, v6_str = _validate_interface_addresses(new_address, v6_str)

	new_dns = payload.dns if "dns" in fields_set else iface["dns"]
	new_post_up = payload.post_up if "post_up" in fields_set else iface["post_up"]
	new_post_down = payload.post_down if "post_down" in fields_set else iface["post_down"]

	# Check for subnet overlap / port conflict with other interfaces
	new_v4_net = v4.network
	new_v6_net = ipaddress.ip_interface(v6_str).network if v6_str else None
	_check_subnet_and_port_conflicts(
		new_v4_net,
		new_v6_net,
		new_listen_port,
		other_interfaces,
		exclude_name=name,
	)

	# Validate hook scripts before writing.
	try:
		if new_post_up:
			_validate_hook(new_post_up, "PostUp")
		if new_post_down:
			_validate_hook(new_post_down, "PostDown")
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc))

	# AUDIT: log PostUp/PostDown script changes
	if "post_up" in fields_set and new_post_up != iface["post_up"]:
		_log.warning(
			"INTERFACE_SCRIPT_CHANGED name=%s type=PostUp old=%s new=%s",
			name,
			_script_fingerprint(iface["post_up"]),
			_script_fingerprint(new_post_up),
		)
	if "post_down" in fields_set and new_post_down != iface["post_down"]:
		_log.warning(
			"INTERFACE_SCRIPT_CHANGED name=%s type=PostDown old=%s new=%s",
			name,
			_script_fingerprint(iface["post_down"]),
			_script_fingerprint(new_post_down),
		)

	cfg = get_config(request)
	config_path = WG_CONFIG_PATH

	# Handle show_on_dashboard field (DB-only, not in config file)
	# Preserve the distinction between an omitted value and explicit False.
	new_show_on_dashboard = _UNSET
	if "show_on_dashboard" in fields_set:
		new_show_on_dashboard = payload.show_on_dashboard
	# Only pass to DB if explicitly set, otherwise db_update_interface keeps existing value
	new_show_on_dashboard_db = new_show_on_dashboard if new_show_on_dashboard is not _UNSET else None

	await run_in_threadpool(
		_update_interface_sync,
		conn,
		name=name,
		config_path=config_path,
		private_key=iface["private_key"],
		pepper=cfg.secret_key,
		address=new_address,
		address6=v6_str,
		listen_port=new_listen_port,
		dns=new_dns,
		post_up=new_post_up,
		post_down=new_post_down,
		show_on_dashboard=new_show_on_dashboard_db,
	)

	code, _, _ = await run_wg_command("wg", "show", name)

	# Check if only show_on_dashboard was changed (no config-relevant changes)
	config_relevant_fields = {"address", "address6", "listen_port", "dns", "post_up", "post_down"}
	config_changed = bool(fields_set & config_relevant_fields)

	# Only require restart if interface is active AND config was actually changed
	restart_required = (code == 0) and config_changed

	# Node config_version must reflect interface-level fields (dns/post_up/
	# post_down/listen_port/address), not just peer changes, or nodes with a
	# conditional config pull never notice this update.
	node_bump_warning = None
	if config_changed:
		try:
			bumped = await run_in_threadpool(bump_config_version_for_interface, conn, name)
			for node_id, new_version in bumped.items():
				await node_notifier.notify_config_changed(node_id, new_version)
		except Exception:
			_log.warning("Failed to bump node config_version after interface update: %s", name, exc_info=True)
			node_bump_warning = (
				"Interface updated, but remote nodes could not be notified of the change; they may keep running the previous configuration until the next sync."
			)

	data = {
		"name": name,
		"address": new_address,
		"address6": v6_str,
		"listen_port": new_listen_port,
		"dns": new_dns,
		"restart_required": restart_required,
	}

	# Surface DNS regeneration warnings in the response.
	dns_warning = await _regenerate_split_dns(conn)
	if dns_warning:
		data["warning"] = dns_warning
	if node_bump_warning:
		data["warning"] = f"{data['warning']} {node_bump_warning}" if data.get("warning") else node_bump_warning

	return ok_response(data=data)


@router.delete("/interfaces/{name}", status_code=200)
async def delete_interface(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a WireGuard interface configuration."""
	validate_interface_name(name)

	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"

	db_exists = await run_in_threadpool(_interface_exists_sync, conn, name)
	file_exists = conf_file.exists()

	# Check if interface is active in kernel
	code, _, _ = await run_wg_command("wg", "show", name)
	is_active = code == 0

	if not db_exists and not file_exists and not is_active:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	# Bring down active interface. A failed shutdown must abort the delete:
	# otherwise the interface keeps running in the kernel with no DB row left
	# to identify it, which then hampers stale-interface cleanup.
	if is_active:
		if file_exists:
			# Normal case: config file exists, use wg-quick
			code, _, stderr = await run_wg_command("wg-quick", "down", name)
			if code != 0:
				_log.error("Failed to bring down interface %s via wg-quick: %s", name, stderr)
				raise HTTPException(
					status_code=500,
					detail=f"Failed to bring down active interface '{name}'; delete aborted: {stderr}",
				)
		else:
			# Orphaned interface: config file missing, use ip link commands directly
			_log.warning("INTERFACE_DELETE_ORPHANED name=%s (no config file, using ip link)", name)
			code, _, stderr = await run_wg_command("ip", "link", "set", name, "down")
			if code != 0:
				_log.error("Failed to set interface %s down: %s", name, stderr)
				raise HTTPException(
					status_code=500,
					detail=f"Failed to bring down active interface '{name}'; delete aborted: {stderr}",
				)
			code, _, stderr = await run_wg_command("ip", "link", "delete", name)
			if code != 0:
				_log.error("Failed to delete interface %s: %s", name, stderr)
				raise HTTPException(
					status_code=500,
					detail=f"Failed to remove active interface '{name}'; delete aborted: {stderr}",
				)

	# File staging and the DB transaction run as one sync unit off the event loop.
	peer_public_keys, node_versions, cleanup_warning = await run_in_threadpool(
		_delete_interface_sync,
		conn,
		name=name,
		conf_file=conf_file,
		db_exists=db_exists,
		file_exists=file_exists,
	)

	# Remove TSDB data only after successful database deletion.
	for public_key in peer_public_keys:
		try:
			await run_in_threadpool(tsdb.delete_peer_data, tsdb_dir, public_key, force=True)
		except Exception:
			_log.exception("Failed to delete TSDB data for peer %s...", public_key[:8])

	_log.info("INTERFACE_DELETED name=%s", name)

	# Tell the nodes that lost a keypair to pull their new config.
	for node_id, new_version in node_versions.items():
		try:
			await node_notifier.notify_config_changed(node_id, new_version)
		except Exception as exc:
			_log.warning("Failed to notify node %s about deleted interface %s: %s", node_id, name, exc)

	# Auto-stop Unbound if no interfaces remain
	remaining_interfaces = await run_in_threadpool(list_interfaces, conn)
	if not remaining_interfaces:
		try:
			if unbound.is_unbound_installed():
				is_running = await unbound.is_running()
				if is_running:
					ok, msg = await unbound.stop()
					if ok:
						await run_in_threadpool(set_dns_service_enabled, conn, False)
						_log.info("UNBOUND_AUTO_STOPPED (no interfaces remaining)")
					else:
						_log.warning("Failed to auto-stop Unbound: %s", msg)
		except Exception as exc:
			_log.warning("Exception during Unbound auto-stop: %s", exc)

	# Surface DNS regeneration and cleanup warnings in the response.
	warnings = [w for w in (cleanup_warning, await _regenerate_split_dns(conn)) if w]
	msg = f"Interface '{name}' deleted"
	if warnings:
		return ok_response(message=msg, data={"warning": " ".join(warnings)})
	return ok_response(message=msg)


# ---------------------------------------------------------------------------
# Next available subnet endpoint
# ---------------------------------------------------------------------------


@router.get("/interfaces/_next-subnet")
@router.get("/interfaces/next-subnet")
async def get_next_subnet(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Calculate the next available IPv4/IPv6 subnet and port for a new interface.

	Scans existing interfaces and finds unused subnets in the 10.13.X.0/24 range
	and fd13:13:X::/64 range.
	"""
	interfaces = await run_in_threadpool(list_interfaces, conn)

	# Collect used third octets (for 10.13.X.0/24 pattern)
	used_v4_octets: set[int] = set()
	# Collect used fourth hex group (for fd13:13:X::/64 pattern)
	used_v6_groups: set[int] = set()
	# Collect used ports
	used_ports: set[int] = set()

	for iface in interfaces:
		# Parse IPv4 address
		addr_v4 = iface["address"]
		if addr_v4:
			try:
				net = ipaddress.ip_interface(addr_v4)
				octets = net.ip.packed
				# Check if it matches 10.13.X.Y pattern
				if octets[0] == 10 and octets[1] == 13:
					used_v4_octets.add(octets[2])
			except (ValueError, TypeError):
				pass

		# Parse IPv6 address
		addr_v6 = iface["address6"]
		if addr_v6:
			try:
				net6 = ipaddress.ip_interface(addr_v6)
				# Check if it matches fd13:13:X:: pattern
				parts = net6.ip.exploded.split(":")
				if parts[0] == "fd13" and parts[1] == "0013":
					# Third group is the variable part
					used_v6_groups.add(int(parts[2], 16))
			except (ValueError, TypeError):
				pass

		# Collect used port
		port = iface["listen_port"]
		if port:
			used_ports.add(int(port))

	# Find next available IPv4 octet (10.13.13.0/24 ... 10.13.254.0/24)
	next_v4_octet = 13
	while next_v4_octet in used_v4_octets and next_v4_octet <= 254:
		next_v4_octet += 1
	if next_v4_octet > 254:
		raise HTTPException(status_code=409, detail="No available IPv4 subnets in 10.13.x.0/24 range")

	# Find next available IPv6 group
	next_v6_group = 13
	while next_v6_group in used_v6_groups and next_v6_group <= 0xFFFF:
		next_v6_group += 1
	if next_v6_group > 0xFFFF:
		raise HTTPException(status_code=409, detail="No available IPv6 subnets in fd13:13:x::/64 range")

	# Find next available port (start at 51820)
	next_port = 51820
	while next_port in used_ports and next_port <= 65535:
		next_port += 1
	if next_port > 65535:
		raise HTTPException(status_code=409, detail="No available listen ports in range 51820-65535")

	# Construct suggested addresses
	suggested_v4 = f"10.13.{next_v4_octet}.1/24"
	suggested_v6 = f"fd13:13:{next_v6_group:x}::1/64"

	return ok_response(
		data={
			"address": suggested_v4,
			"address6": suggested_v6,
			"listen_port": next_port,
		}
	)
