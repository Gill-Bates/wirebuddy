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
from typing import AsyncGenerator

_log = logging.getLogger(__name__)

# Per-node event queues: node_id -> set of asyncio.Queue
# Each connected SSE client gets its own queue
_node_queues: dict[str, set[asyncio.Queue[str]]] = {}
_lock = asyncio.Lock()

# Queue size optimized for latest-wins: only the newest event matters
# Larger queues would accumulate stale events that get dropped anyway
_QUEUE_SIZE = 1
# SSE keepalive interval to prevent proxy timeouts
_KEEPALIVE_INTERVAL = 25


def _enqueue_latest(queue: asyncio.Queue[str], event: str) -> bool:
    """Enqueue event, replacing old event if queue is full (latest-wins).
    
    Returns True if event was enqueued, False on failure.
    """
    try:
        queue.put_nowait(event)
        return True
    except asyncio.QueueFull:
        # Latest-wins: drop old event and enqueue new one
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False


async def subscribe(node_id: str) -> AsyncGenerator[str, None]:
    """Subscribe to config change events for a node.
    
    Yields SSE-formatted event strings when config changes.
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_SIZE)
    async with _lock:
        _node_queues.setdefault(node_id, set()).add(queue)
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
        if _enqueue_latest(queue, event):
            notified += 1
        else:
            _log.error("Failed to enqueue config change for node %s (queue overflow)", node_id)
    
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


async def is_node_connected(node_id: str) -> bool:
    """Check if a node has active SSE connections (multi-worker safe via DB).
    
    Uses database timestamp instead of in-memory dict to work correctly
    with multiple uvicorn workers. Runs DB query in threadpool to avoid
    blocking the async event loop.
    """
    from ..db.sqlite_runtime import connect
    from ..db.sqlite_nodes import is_node_sse_connected
    from ..utils.config import get_config
    
    cfg = get_config()
    try:
        # Run blocking DB call in threadpool
        def _check_db():
            conn = connect(cfg.db_path)
            try:
                return is_node_sse_connected(conn, node_id)
            finally:
                conn.close()
        
        return await asyncio.to_thread(_check_db)
    except Exception as exc:
        _log.debug("Failed to check SSE status for node %s: %s", node_id, exc)
        # Fall back to in-memory check (same-worker only)
        async with _lock:
            return bool(_node_queues.get(node_id))


def is_node_connected_sync(node_id: str) -> bool:
    """Synchronous version of is_node_connected() for non-async callers.
    
    WARNING: Blocks the calling thread. Prefer is_node_connected() in async code.
    """
    from ..db.sqlite_runtime import connect
    from ..db.sqlite_nodes import is_node_sse_connected
    from ..utils.config import get_config
    
    cfg = get_config()
    try:
        conn = connect(cfg.db_path)
        try:
            return is_node_sse_connected(conn, node_id)
        finally:
            conn.close()
    except Exception as exc:
        _log.debug("Failed to check SSE status for node %s: %s", node_id, exc)
        # Fall back to in-memory check (same-worker only)
        return bool(_node_queues.get(node_id))


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
        if _enqueue_latest(queue, event):
            notified += 1
        else:
            _log.error("Failed to enqueue restart event for node %s (queue overflow)", node_id)
    
    _log.info("Sent restart signal to %d SSE client(s) for node %s", notified, node_id)
    return notified


async def notify_node_removed(node_id: str) -> int:
    """Notify a node that it has been removed from management.
    
    The node daemon will clear its persisted state and exit cleanly.
    Exit code signals Docker/systemd to NOT auto-restart.
    
    Returns the number of clients notified.
    """
    async with _lock:
        queues = _node_queues.get(node_id, set()).copy()
    
    if not queues:
        _log.warning(
            "No SSE clients connected for node %s — cannot send removal signal. "
            "Node will detect removal on next heartbeat (401) and clean up.",
            node_id
        )
        return 0
    
    event = (
        f"event: node_removed\n"
        f"data: removed\n\n"
    )
    
    notified = 0
    for queue in queues:
        if _enqueue_latest(queue, event):
            notified += 1
        else:
            _log.error("Failed to enqueue removal event for node %s (queue overflow)", node_id)
    
    _log.info("Sent node_removed signal to %d SSE client(s) for node %s", notified, node_id)
    return notified

