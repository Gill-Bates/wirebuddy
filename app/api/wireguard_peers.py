#!/usr/bin/env python3
#
# app/api/wireguard_peers.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard peer management API routes."""

from __future__ import annotations

from ..db.sqlite_peers import (
	allocate_peer_ip,
	get_all_peers,
	get_peer_by_id,
	get_peer_by_public_key,
)
from ..db.sqlite_peers_mutations import (
	create_peer as db_create_peer,
	delete_peer as db_delete_peer,
	update_peer as db_update_peer,
)
from ..db.sqlite_runtime import (
	UNSET,
)

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..models.peers import PeerCreate, PeerPublic, PeerUpdate
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_conn, get_tsdb_dir, get_config
from ..utils.vault import encrypt as vault_encrypt
from .auth import get_current_user, require_admin
from .response import ok_response
from .wireguard_config import sync_interface_config
from .wireguard_isolation import apply_client_isolation_runtime
from .wireguard_utils import (
	get_enabled_blocklist_ids,
	filter_peer_blocklist_ids,
	generate_keypair,
	generate_preshared_key,
	run_wg_command,
	wg_set_peer_with_psk,
	validate_keypair,
	parse_blocklist_ids,
	safe_row_get,
)

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]


def _regenerate_peer_tags(conn: sqlite3.Connection) -> None:
	"""Regenerate Unbound peer-tags.conf for per-peer blocklist filtering.
	
	Raises:
		Exception: If peer tag generation fails (caller should handle).
	"""
	from ..dns import unbound as _unbound
	
	enabled_blocklist_ids = get_enabled_blocklist_ids(conn)
	peers = get_all_peers(conn)
	peer_list = []
	
	for row in peers:
		blocklist_ids = parse_blocklist_ids(row["blocklist_ids"])
		# Resolve effective blocklists
		if blocklist_ids is None:
			effective_ids = list(enabled_blocklist_ids)
		else:
			filtered = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids)
			effective_ids = filtered or []
		
		peer_list.append({
			"peer_address": row["peer_address"],
			"use_adblocker": bool(row["use_adblocker"]),
			"blocklist_ids": effective_ids,
		})
	
	_unbound.write_peer_tags(peer_list)


def _row_to_public(row: sqlite3.Row, enabled_blocklist_ids: list[str]) -> PeerPublic:
	"""Convert a SQLite peer row into the public response model."""
	blocklist_ids = parse_blocklist_ids(row["blocklist_ids"])
	if blocklist_ids is not None:
		blocklist_ids = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids) or []
	
	return PeerPublic(
		id=row["id"],
		public_key=row["public_key"],
		name=row["name"],
		description=row["description"],
		allowed_ips=row["allowed_ips"],
		allowed_ips_mode=safe_row_get(row, "allowed_ips_mode", "full"),
		peer_address=row["peer_address"],
		endpoint=row["endpoint"],
		interface=row["interface"],
		is_enabled=bool(row["is_enabled"]),
		use_adblocker=bool(row["use_adblocker"]),
		blocklist_ids=blocklist_ids,
		client_isolation=bool(safe_row_get(row, "client_isolation", False)),
		created_at=row["created_at"],
		updated_at=row["updated_at"],
	)


@router.get("/peers")
def list_peers(
	interface: Optional[str] = None,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all peers."""
	enabled_blocklist_ids = get_enabled_blocklist_ids(conn)
	rows = get_all_peers(conn, interface)
	data = [_row_to_public(row, enabled_blocklist_ids) for row in rows]
	return ok_response(data=data)


@router.post("/peers", status_code=201)
async def create_peer(
	request: Request,
	payload: PeerCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Create a new peer.
	
	WG-first approach: Add peer to WireGuard interface first, then store in DB.
	This ensures consistency - if WG fails, we don't have orphaned DB entries.
	"""
	cfg = get_config(request)
	enabled_blocklist_ids = await run_in_threadpool(get_enabled_blocklist_ids, conn)
	
	# 1. Verify interface exists and is active
	code, _, stderr = await run_wg_command("wg", "show", payload.interface)
	if code != 0:
		raise HTTPException(
			status_code=400,
			detail=f"Interface '{payload.interface}' is not active. Bring it up first.",
		)
	
	# 2. Generate or validate keypair
	private_key = payload.private_key
	public_key = payload.public_key
	
	if private_key and public_key:
		# Validate user-supplied keys
		await validate_keypair(private_key, public_key)
	elif private_key or public_key:
		raise HTTPException(
			status_code=422,
			detail="Provide both private and public key, or neither",
		)
	else:
		# Generate keypair
		private_key, public_key = await generate_keypair()
	
	# 3. Generate preshared key if not provided
	preshared_key = payload.preshared_key
	if not preshared_key:
		preshared_key = await generate_preshared_key()
	
	# 4. Check if peer already exists in DB
	existing = await run_in_threadpool(get_peer_by_public_key, conn, public_key)
	if existing:
		raise HTTPException(status_code=409, detail="Peer with this public key already exists")

	# 5. Store peer in WireGuard + DB (with retry on concurrent IP allocation conflict)
	# Encrypt private_key and preshared_key before storage
	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)
	preshared_key_encrypted = vault_encrypt(preshared_key, cfg.secret_key)
	
	# allowed_ips = client-side routing (what client routes through VPN)
	# peer_address = peer's VPN IP (used in server config and QR code)
	peer_address: str | None = None
	peer_id: int | None = None
	
	for attempt in range(3):
		with conn:
			peer_address = allocate_peer_ip(conn, payload.interface)
			if not peer_address:
				raise HTTPException(
					status_code=500,
					detail=f"No available IP addresses in interface '{payload.interface}' subnet",
				)

			code, _, stderr = await wg_set_peer_with_psk(
				payload.interface,
				public_key,
				peer_address,
				preshared_key,
			)
			if code != 0:
				err = stderr.strip()
				_log.error("WG_SET_FAILED interface=%s code=%d stderr=%s", payload.interface, code, err)
				raise HTTPException(
					status_code=500,
					detail=f"Failed to add peer to WireGuard: {err}",
				)

			try:
				peer_id = db_create_peer(
					conn,
					public_key=public_key,
					private_key=private_key_encrypted,
					preshared_key=preshared_key_encrypted,
					allowed_ips=payload.allowed_ips,
					allowed_ips_mode=payload.allowed_ips_mode,
					peer_address=peer_address,
					name=payload.name,
					description=payload.description,
					endpoint=payload.endpoint,
					interface=payload.interface,
					use_adblocker=payload.use_adblocker,
					blocklist_ids=filter_peer_blocklist_ids(payload.blocklist_ids, enabled_blocklist_ids),
					client_isolation=payload.client_isolation,
				)
				break
			except sqlite3.IntegrityError as e:
				# Rollback: remove peer from WireGuard
				_log.error("DB integrity error, rolling back WG peer: %s", e)
				await run_wg_command("wg", "set", payload.interface, "peer", public_key, "remove")
				ip_conflict = "idx_peers_address_interface_unique" in str(e) or "peer_address" in str(e).lower()
				if ip_conflict and attempt < 2:
					continue
				if ip_conflict:
					raise HTTPException(status_code=409, detail="Peer IP address conflict. Please retry.")
				raise HTTPException(status_code=409, detail="Peer already exists or conflicts with existing data")
			except Exception as e:
				# Rollback: remove peer from WireGuard
				_log.error("DB insert failed, rolling back WG peer: %s", e)
				await run_wg_command("wg", "set", payload.interface, "peer", public_key, "remove")
				raise HTTPException(status_code=500, detail="Failed to store peer in database")
	
	# 6. Post-create synchronization with full rollback on failure
	try:
		await run_in_threadpool(
			sync_interface_config,
			WG_CONFIG_PATH,
			payload.interface,
			conn,
			pepper=cfg.secret_key,
		)
		await apply_client_isolation_runtime(payload.interface, conn)
		
		# 7. Seed TSDB series so peer directories exist immediately after creation
		try:
			await run_in_threadpool(tsdb.append_point, tsdb_dir, peer_key=public_key, metric="rx_bytes", value=0)
			await run_in_threadpool(tsdb.append_point, tsdb_dir, peer_key=public_key, metric="tx_bytes", value=0)
		except Exception as exc:
			_log.warning("Failed to seed TSDB for peer %s...: %s", public_key[:8], exc)
		
		# 8. Regenerate Unbound peer tags for per-peer blocklist filtering
		try:
			await run_in_threadpool(_regenerate_peer_tags, conn)
		except Exception as exc:
			_log.exception("Failed to regenerate peer tags — DNS filtering may be stale")
			# Continue - this is not fatal to peer creation
		
	except Exception as exc:
		# Rollback: remove from WG and DB
		_log.error("Post-create sync failed; rolling back peer %s: %s", public_key[:8], exc)
		await run_wg_command("wg", "set", payload.interface, "peer", public_key, "remove")
		if peer_id:
			await run_in_threadpool(db_delete_peer, conn, peer_id)
		raise HTTPException(
			status_code=500,
			detail="Peer created but config sync failed; rolled back",
		)
	
	peer = await run_in_threadpool(get_peer_by_public_key, conn, public_key)
	_log.info("PEER_CREATED public_key=%s... interface=%s peer_address=%s", public_key[:8], payload.interface, peer_address)
	
	peer_data = _row_to_public(peer, enabled_blocklist_ids).model_dump(mode="json")
	return ok_response(data=peer_data)


@router.get("/peers/{peer_id}")
def get_peer(
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get a peer by ID."""
	enabled_blocklist_ids = get_enabled_blocklist_ids(conn)
	peer = get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	return ok_response(data=_row_to_public(peer, enabled_blocklist_ids))


@router.patch("/peers/{peer_id}")
async def update_peer(
	request: Request,
	peer_id: int,
	payload: PeerUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update a peer."""
	cfg = get_config(request)
	peer = await run_in_threadpool(get_peer_by_id, conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	fields_set = payload.model_fields_set
	enabled_blocklist_ids = await run_in_threadpool(get_enabled_blocklist_ids, conn)

	def _val_or_unset(field: str):
		return getattr(payload, field) if field in fields_set else UNSET

	blocklist_ids_update = UNSET
	if "blocklist_ids" in fields_set:
		blocklist_ids_update = filter_peer_blocklist_ids(payload.blocklist_ids, enabled_blocklist_ids)

	await run_in_threadpool(
		db_update_peer,
		conn,
		peer_id,
		name=_val_or_unset("name"),
		description=_val_or_unset("description"),
		allowed_ips=_val_or_unset("allowed_ips"),
		allowed_ips_mode=_val_or_unset("allowed_ips_mode"),
		endpoint=_val_or_unset("endpoint"),
		is_enabled=_val_or_unset("is_enabled"),
		use_adblocker=_val_or_unset("use_adblocker"),
		blocklist_ids=blocklist_ids_update,
		client_isolation=_val_or_unset("client_isolation"),
	)
	
	# Runtime enable/disable support
	if "is_enabled" in fields_set:
		if not payload.is_enabled:
			# Remove peer from runtime
			code, _, stderr = await run_wg_command(
				"wg", "set", interface_name,
				"peer", public_key,
				"remove",
			)
			if code != 0:
				_log.warning("Failed to remove disabled peer from WG runtime: %s", stderr)
		else:
			# Re-add peer to runtime with current settings
			peer_address = peer["peer_address"]
			if peer_address:
				preshared_key = peer.get("preshared_key")
				if preshared_key:
					from ..utils.vault import decrypt as vault_decrypt
					psk_plain = vault_decrypt(preshared_key, cfg.secret_key)
					code, _, stderr = await wg_set_peer_with_psk(
						interface_name,
						public_key,
						peer_address,
						psk_plain,
					)
				else:
					code, _, stderr = await run_wg_command(
						"wg", "set", interface_name,
						"peer", public_key,
						"allowed-ips", peer_address,
					)
				if code != 0:
					_log.warning("Failed to re-add enabled peer to WG runtime: %s", stderr)
	elif "allowed_ips" in fields_set and payload.allowed_ips is not None:
		# Keep server-side cryptokey routing strict: always peer_address on server.
		# payload.allowed_ips is client-side policy and must not be pushed to server.
		peer_address = peer["peer_address"]
		if not peer_address:
			_log.warning("Peer %s has no peer_address; skipped runtime allowed-ips repair", public_key[:8])
		else:
			code, _, stderr = await run_wg_command(
				"wg", "set", interface_name,
				"peer", public_key,
				"allowed-ips", peer_address,
			)
			if code != 0:
				_log.warning("Failed to update peer allowed-ips in WireGuard: %s", stderr)
	
	# Sync config file if peer routing/enabled state changed.
	if any(k in fields_set for k in ("allowed_ips", "allowed_ips_mode", "is_enabled", "client_isolation")):
		await run_in_threadpool(
			sync_interface_config,
			WG_CONFIG_PATH,
			interface_name,
			conn,
			pepper=cfg.secret_key,
		)
		await apply_client_isolation_runtime(interface_name, conn)
	
	# Regenerate Unbound peer tags if blocklist settings changed
	if "blocklist_ids" in fields_set or "use_adblocker" in fields_set:
		try:
			await run_in_threadpool(_regenerate_peer_tags, conn)
		except Exception as exc:
			_log.exception("Failed to regenerate peer tags — DNS filtering may be stale")
	
	updated = await run_in_threadpool(get_peer_by_id, conn, peer_id)
	_log.info("PEER_UPDATED id=%d public_key=%s...", peer_id, public_key[:8])
	updated_data = _row_to_public(updated, enabled_blocklist_ids).model_dump(mode="json")
	return ok_response(data=updated_data)


@router.delete("/peers/{peer_id}", status_code=204)
async def delete_peer(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a peer."""
	cfg = get_config(request)
	peer = await run_in_threadpool(get_peer_by_id, conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	
	# Remove from WireGuard (fail hard - don't create ghost peers)
	code, _, stderr = await run_wg_command(
		"wg", "set", interface_name,
		"peer", public_key,
		"remove",
	)
	if code != 0:
		raise HTTPException(
			status_code=500,
			detail=f"Failed to remove peer from WireGuard: {stderr}. DB unchanged.",
		)
	
	# Delete from database
	await run_in_threadpool(db_delete_peer, conn, peer_id)
	
	# Sync config file
	await run_in_threadpool(
		sync_interface_config,
		WG_CONFIG_PATH,
		interface_name,
		conn,
		pepper=cfg.secret_key,
	)
	await apply_client_isolation_runtime(interface_name, conn)
	
	# Delete TSDB data
	await run_in_threadpool(tsdb.delete_peer_data, tsdb_dir, public_key)
	
	# Regenerate Unbound peer tags
	try:
		await run_in_threadpool(_regenerate_peer_tags, conn)
	except Exception as exc:
		_log.exception("Failed to regenerate peer tags — DNS filtering may be stale")
	
	_log.info("PEER_DELETED id=%d public_key=%s...", peer_id, public_key[:8])
