#!/usr/bin/env python3
#
# app/node/notifier.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node configuration change notifier — push mechanism for instant sync.

Uses Server-Sent Events (SSE) to notify nodes of configuration changes.
Nodes subscribe via GET /api/nodes/events and receive events when their
config_version changes.

Delivery guarantees:
- At-most-once delivery (best-effort)
- Latest config always prioritized (old events dropped under backpressure)
- Per-client isolation (no shared queue contention)
- Keepalive comments every 25s to prevent proxy timeouts
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import AsyncGenerator

_log = logging.getLogger(__name__)

# Per-node event queues: node_id -> set of asyncio.Queue
# Each connected SSE client gets its own queue
_node_queues: dict[str, set[asyncio.Queue[str]]] = defaultdict(set)
_lock = asyncio.Lock()

# Maximum queued events per client before backpressure/dropping
_MAX_QUEUED_EVENTS = 64
# SSE keepalive interval to prevent proxy timeouts
_KEEPALIVE_INTERVAL = 25


async def subscribe(node_id: str) -> AsyncGenerator[str, None]:
    """Subscribe to config change events for a node.
    
    Yields SSE-formatted event strings when config changes.
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_MAX_QUEUED_EVENTS)
    async with _lock:
        _node_queues[node_id].add(queue)
        client_count = len(_node_queues[node_id])
    _log.debug("Node %s subscribed to config events (clients=%d)", node_id, client_count)
    
    try:
        while True:
            try:
                # Wait for event with timeout to inject keepalive
                event = await asyncio.wait_for(queue.get(), timeout=_KEEPALIVE_INTERVAL)
                yield event
            except asyncio.TimeoutError:
                # Send keepalive comment to prevent proxy timeout
                yield ": keepalive\n\n"
    except asyncio.CancelledError:
        _log.debug("SSE client cancelled for node %s", node_id)
        raise
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
        _log.debug("No SSE clients connected for node %s (config_version=%s...) — node will sync on next poll",
                  node_id, config_version[:16] if config_version else "none")
        return 0
    
    # SSE event format with id for replay support
    event = (
        f"id: {config_version}\n"
        f"event: config_changed\n"
        f"data: {config_version}\n\n"
    )
    
    notified = 0
    for queue in queues:
        try:
            queue.put_nowait(event)
            notified += 1
        except asyncio.QueueFull:
            # Drop oldest event to ensure newest config is always delivered
            _log.warning("Event queue full for node %s, dropping oldest event to make room", node_id)
            try:
                queue.get_nowait()  # Drop oldest
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(event)  # Insert newest
                notified += 1
            except asyncio.QueueFull:
                _log.error("Failed to enqueue event for node %s even after dropping oldest", node_id)
    
    _log.debug("Notified %d SSE client(s) for node %s: config_version=%s...", 
              notified, node_id, config_version[:16] if config_version else "none")
    return notified


async def get_connected_nodes() -> list[str]:
    """Return list of node IDs with active SSE connections."""
    async with _lock:
        return list(_node_queues.keys())


async def get_connection_count(node_id: str) -> int:
    """Return number of active SSE connections for a node."""
    async with _lock:
        return len(_node_queues.get(node_id, set()))


def is_node_connected_sync(node_id: str) -> bool:
    """Check if a node has active SSE connections (sync, lock-free read).
    
    Safe for read-only checks from synchronous code -- dict reads are
    atomic in CPython due to the GIL.
    """
    connected = bool(_node_queues.get(node_id))
    if not connected and node_id:
        _log.debug("Node %s has no active SSE connections (queues: %s)", 
                  node_id, list(_node_queues.keys())[:5])
    return connected


async def notify_restart(node_id: str) -> int:
    """Notify a node to restart/shutdown gracefully.
    
    The node daemon will exit and Docker/systemd will restart it.
    Returns the number of clients notified.
    """
    async with _lock:
        queues = _node_queues.get(node_id, set()).copy()
    
    if not queues:
        _log.warning("No SSE clients connected for node %s — cannot send restart signal", node_id)
        return 0
    
    event = (
        f"event: restart_requested\n"
        f"data: restart\n\n"
    )
    
    notified = 0
    for queue in queues:
        try:
            queue.put_nowait(event)
            notified += 1
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(event)
                notified += 1
            except asyncio.QueueFull:
                _log.error("Failed to enqueue restart event for node %s", node_id)
    
    _log.info("Sent restart signal to %d SSE client(s) for node %s", notified, node_id)
    return notified

