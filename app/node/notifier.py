#!/usr/bin/env python3
#
# app/node/notifier.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node configuration change notifier — push mechanism for instant sync.

Uses Server-Sent Events (SSE) to notify nodes of configuration changes.
Nodes subscribe via GET /api/nodes/events and receive events when their
config_version changes.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import AsyncIterator

_log = logging.getLogger(__name__)

# Per-node event queues: node_id -> set of asyncio.Queue
# Each connected SSE client gets its own queue
_node_queues: dict[str, set[asyncio.Queue[str]]] = defaultdict(set)
_lock = asyncio.Lock()


async def subscribe(node_id: str) -> AsyncIterator[str]:
	"""Subscribe to config change events for a node.
	
	Yields SSE-formatted event strings when config changes.
	"""
	queue: asyncio.Queue[str] = asyncio.Queue()
	async with _lock:
		_node_queues[node_id].add(queue)
	_log.debug("Node %s subscribed to config events (clients=%d)", node_id, len(_node_queues[node_id]))
	
	try:
		while True:
			event = await queue.get()
			yield event
	finally:
		async with _lock:
			_node_queues[node_id].discard(queue)
			if not _node_queues[node_id]:
				del _node_queues[node_id]
		_log.debug("Node %s unsubscribed from config events", node_id)


async def notify_config_changed(node_id: str, config_version: str) -> int:
	"""Notify all connected clients for a node that config has changed.
	
	Returns the number of clients notified.
	"""
	async with _lock:
		queues = _node_queues.get(node_id, set()).copy()
	
	if not queues:
		_log.debug("No SSE clients connected for node %s", node_id)
		return 0
	
	# SSE event format
	event = f"event: config_changed\ndata: {config_version}\n\n"
	
	notified = 0
	for queue in queues:
		try:
			queue.put_nowait(event)
			notified += 1
		except asyncio.QueueFull:
			_log.warning("Event queue full for node %s, dropping event", node_id)
	
	_log.info("Notified %d SSE client(s) for node %s: config_version=%s...", 
			  notified, node_id, config_version[:16] if config_version else "none")
	return notified


def get_connected_nodes() -> list[str]:
	"""Return list of node IDs with active SSE connections."""
	return list(_node_queues.keys())


def get_connection_count(node_id: str) -> int:
	"""Return number of active SSE connections for a node."""
	return len(_node_queues.get(node_id, set()))
