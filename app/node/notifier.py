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
import re
import threading
from collections.abc import AsyncGenerator

_log = logging.getLogger(__name__)

# Per-node event queues: node_id -> set of asyncio.Queue
# Each connected SSE client gets its own queue
_node_queues: dict[str, set[asyncio.Queue[str]]] = {}
_lock = asyncio.Lock()  # For async access
_sync_lock = threading.Lock()  # For sync/thread access

# Queue size optimized for latest-wins: only the newest event matters
# Larger queues would accumulate stale events that get dropped anyway
_QUEUE_SIZE = 1
# SSE keepalive interval to prevent proxy timeouts
_KEEPALIVE_INTERVAL = 25

_MAX_NODE_ID_LEN = 64
_NODE_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_node_id(node_id: str) -> str:
    """Validate node ID to prevent injection and memory issues."""
    if len(node_id) > _MAX_NODE_ID_LEN or not _NODE_ID_RE.fullmatch(node_id):
        raise ValueError(f"Invalid node_id: {node_id!r}")
    return node_id


def _sanitize_sse_value(value: str) -> str:
    """Remove newlines from SSE data values to prevent protocol injection."""
    return value.replace("\n", " ").replace("\r", " ")


def _format_sse_event(event_type: str, data: str, event_id: str | None = None) -> str:
    """Format SSE event with proper protocol structure.
    
    All fields are sanitized to prevent SSE protocol injection via newlines.
    """
    lines = [
        f"event: {_sanitize_sse_value(event_type)}",
        f"data: {_sanitize_sse_value(data)}",
    ]
    if event_id:
        lines.insert(0, f"id: {_sanitize_sse_value(event_id)}")
    lines.append("")  # Empty line terminates event
    return "\n".join(lines) + "\n"


def _short_version(version: str, max_len: int = 16) -> str:
    """Truncate version string for logging."""
    return version[:max_len] if len(version) > max_len else version


def _enqueue_latest(queue: asyncio.Queue[str], event: str) -> bool:
    """Enqueue event, replacing old event if queue is full (latest-wins).
    
    Returns True if event was enqueued, False on failure.
    """
    try:
        if queue.full():
            try:
                queue.get_nowait()  # Discard old event
            except asyncio.QueueEmpty:
                pass  # Race: another coroutine drained it
        queue.put_nowait(event)
        return True
    except (asyncio.QueueFull, asyncio.QueueEmpty):
        return False


async def _race(
    queue: asyncio.Queue[str],
    shutdown_event: asyncio.Event | None,
    timeout: float,
) -> str | None:
    """Return queue item, None for timeout, or ""-sentinel for shutdown."""
    if shutdown_event is None:
        try:
            return await asyncio.wait_for(queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    queue_task = asyncio.create_task(queue.get())
    shutdown_task = asyncio.create_task(shutdown_event.wait())
    
    wait_tasks = [queue_task, shutdown_task]
    try:
        done, pending = await asyncio.wait(
            wait_tasks,
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        if shutdown_task in done:
            queue_task.cancel()
            await asyncio.gather(queue_task, return_exceptions=True)
            return ""  # shutdown sentinel
        
        if queue_task in done:
            shutdown_task.cancel()
            await asyncio.gather(shutdown_task, return_exceptions=True)
            return queue_task.result()
            
        return None  # timeout
    except asyncio.CancelledError:
        for task in wait_tasks:
            task.cancel()
        await asyncio.gather(*wait_tasks, return_exceptions=True)
        raise


async def subscribe(
    node_id: str,
    shutdown_event: asyncio.Event | None = None,
) -> AsyncGenerator[str, None]:
    """Subscribe to config change events for a node.
    
    Yields SSE-formatted event strings when config changes.
    """
    node_id = _validate_node_id(node_id)
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_SIZE)
    
    async with _lock:
        _node_queues.setdefault(node_id, set()).add(queue)
        client_count = len(_node_queues[node_id])
    _log.debug("Node %s subscribed to config events (clients=%d)", node_id, client_count)
    
    try:
        close_event = _format_sse_event("close", "server_shutdown")
        while True:
            result = await _race(queue, shutdown_event, _KEEPALIVE_INTERVAL)
            if result == "":
                yield close_event
                break
            if result is None:
                yield ": keepalive\n\n"
                continue
            yield result
    except asyncio.CancelledError:
        _log.debug("SSE client cancelled for node %s", node_id)
        raise
    finally:
        # Cleanup must be protected from cancellation to prevent resource leak
        # If cancelled during lock acquisition, fall back to best-effort cleanup
        try:
            async with _lock:
                queues = _node_queues.get(node_id)
                if queues:
                    queues.discard(queue)
                    if not queues:
                        del _node_queues[node_id]
        except asyncio.CancelledError:
            # Best-effort cleanup without lock (race possible but better than leak)
            _log.debug("Cleanup cancelled for node %s, attempting best-effort", node_id)
            queues = _node_queues.get(node_id)
            if queues:
                queues.discard(queue)
                if not queues:
                    try:
                        del _node_queues[node_id]
                    except KeyError:
                        pass  # Another task cleaned up already
        _log.debug("Node %s unsubscribed from config events", node_id)


async def _queue_db_command(node_id: str, command: str) -> bool:
    """Queue a pending command in SQLite for multi-worker delivery."""
    from ..db.sqlite_runtime import connect
    from ..db.sqlite_nodes import set_node_pending_command
    from ..utils.config import get_config

    cfg = get_config()
    try:
        def _queue():
            conn = connect(cfg.db_path)
            try:
                return set_node_pending_command(conn, node_id, command)
            finally:
                conn.close()
        return await asyncio.to_thread(_queue)
    except Exception as exc:
        _log.warning("Failed to queue %s command for node %s: %s", command, node_id, exc)
        return False


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
    Thread-safe: Uses threading.Lock for safe access from sync contexts.
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
        # Fall back to in-memory check (thread-safe with threading.Lock)
        with _sync_lock:
            return bool(_node_queues.get(node_id))


async def _notify_or_queue(
    node_id: str,
    event_type: str,
    event_data: str,
    db_command: str,
    action_name: str,
    *,
    event_id: str | None = None,
) -> int:
    """Send SSE event to node or queue command in DB (multi-worker safe).
    
    Args:
        node_id: Target node ID
        event_type: SSE event type (e.g., "restart_requested")
        event_data: SSE event data payload
        db_command: DB command to queue if SSE unavailable
        action_name: Human-readable action name for logging
        event_id: Optional ID for the SSE event
    
    Returns:
        Number of clients notified (>0 if delivered or queued)
    """
    node_id = _validate_node_id(node_id)
    
    # Try direct notification to SSE clients in current worker
    async with _lock:
        queues = _node_queues.get(node_id, set()).copy()
    
    if queues:
        # Have direct SSE connection in this worker - send immediately
        event = _format_sse_event(event_type=event_type, data=event_data, event_id=event_id)
        
        notified = 0
        for queue in queues:
            if _enqueue_latest(queue, event):
                notified += 1
            else:
                _log.warning("Failed to enqueue %s event for node %s (queue full)", action_name, node_id)
        
        _log.info("Sent %s signal to %d SSE client(s) for node %s", action_name, notified, node_id)
        return notified
    
    # No SSE clients in current worker - check if connected to another worker
    if await is_node_connected(node_id):
        queued = await _queue_db_command(node_id, db_command)
        if queued:
            _log.info("Queued %s command in DB for node %s (SSE in other worker)", action_name, node_id)
            return 1
    
    # No SSE connection anywhere
    _log.warning("No SSE clients connected for node %s — cannot send %s signal", node_id, action_name)
    return 0


async def notify_config_changed(node_id: str, config_version: str) -> int:
    """Notify all connected clients for a node that config has changed.
    
    Returns the number of clients notified or queued.
    """
    return await _notify_or_queue(
        node_id=node_id,
        event_type="config_changed",
        event_data=config_version,
        db_command="config_changed",
        action_name="config change",
        event_id=config_version,
    )


async def notify_restart(node_id: str) -> int:
    """Notify a node to restart/shutdown gracefully.
    
    The node daemon will exit and Docker/systemd will restart it.
    Returns the number of clients notified (>0 if delivered or queued).
    
    Multi-worker safe: If no SSE clients in current worker, checks DB
    for SSE connection in other workers and queues command if present.
    """
    return await _notify_or_queue(
        node_id=node_id,
        event_type="restart_requested",
        event_data="restart",
        db_command="restart",
        action_name="restart",
    )


async def notify_run_speedtest(node_id: str) -> int:
    """Notify a node to run an immediate speedtest.
    
    Returns the number of clients notified (>0 if delivered or queued).
    
    Multi-worker safe: If no SSE clients in current worker, checks DB
    for SSE connection in other workers and queues command if present.
    """
    return await _notify_or_queue(
        node_id=node_id,
        event_type="run_speedtest",
        event_data="speedtest",
        db_command="speedtest",
        action_name="speedtest",
    )


async def notify_node_removed(node_id: str) -> int:
    """Notify a node that it has been removed from management.
    
    The node daemon will clear its persisted state and exit cleanly.
    Exit code signals Docker/systemd to NOT auto-restart.
    
    Returns the number of clients notified (>0 if delivered or queued).
    
    Multi-worker safe: If no SSE clients in current worker, checks DB
    for SSE connection in other workers and queues command if present.
    Fallback: Node will detect removal on next heartbeat (401 response).
    """
    return await _notify_or_queue(
        node_id=node_id,
        event_type="node_removed",
        event_data="removed",
        db_command="removed",
        action_name="removal",
    )
