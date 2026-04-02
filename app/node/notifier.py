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
import threading
from typing import AsyncGenerator

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


async def subscribe(
    node_id: str,
    shutdown_event: asyncio.Event | None = None,
) -> AsyncGenerator[str, None]:
    """Subscribe to config change events for a node.
    
    Yields SSE-formatted event strings when config changes.
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_SIZE)
    async with _lock:
        _node_queues.setdefault(node_id, set()).add(queue)
        client_count = len(_node_queues[node_id])
    _log.debug("Node %s subscribed to config events (clients=%d)", node_id, client_count)
    
    try:
        close_event = _format_sse_event("close", "server_shutdown")
        while True:
            if shutdown_event is not None and shutdown_event.is_set():
                yield close_event
                break

            queue_task = asyncio.create_task(queue.get())
            shutdown_task = (
                asyncio.create_task(shutdown_event.wait())
                if shutdown_event is not None
                else None
            )
            wait_tasks = [queue_task]
            if shutdown_task is not None:
                wait_tasks.append(shutdown_task)

            try:
                done, pending = await asyncio.wait(
                    wait_tasks,
                    timeout=_KEEPALIVE_INTERVAL,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            except asyncio.CancelledError:
                for task in wait_tasks:
                    task.cancel()
                await asyncio.gather(*wait_tasks, return_exceptions=True)
                raise

            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            if shutdown_task is not None and shutdown_task in done:
                yield close_event
                await asyncio.gather(queue_task, return_exceptions=True)
                break

            if queue_task in done:
                yield queue_task.result()
                continue

            # Timeout: send keepalive comment to prevent proxy timeout.
            await asyncio.gather(queue_task, return_exceptions=True)
            yield ": keepalive\n\n"
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


async def notify_config_changed(node_id: str, config_version: str) -> int:
    """Notify all connected clients for a node that config has changed.
    
    Returns the number of clients notified or queued.
    """
    async with _lock:
        queues = _node_queues.get(node_id, set()).copy()
    
    if queues:
        # SSE event format with id for replay support.
        event = _format_sse_event(
            event_type="config_changed",
            data=config_version,
            event_id=config_version,
        )

        notified = 0
        for queue in queues:
            if _enqueue_latest(queue, event):
                notified += 1
            else:
                _log.warning("Failed to enqueue config change for node %s (queue full)", node_id)

        _log.debug(
            "Notified %d SSE client(s) for node %s: config_version=%s",
            notified, node_id, _short_version(config_version),
        )
        return notified

    # No SSE clients in this worker: if the node is connected elsewhere, queue a
    # config_changed command in DB so the next keepalive picks it up immediately.
    if await is_node_connected(node_id):
        from ..db.sqlite_runtime import connect
        from ..db.sqlite_nodes import set_node_pending_command
        from ..utils.config import get_config

        cfg = get_config()
        try:
            def _queue_cmd():
                conn = connect(cfg.db_path)
                try:
                    return set_node_pending_command(conn, node_id, "config_changed")
                finally:
                    conn.close()

            queued = await asyncio.to_thread(_queue_cmd)
            if queued:
                _log.debug(
                    "Queued config_changed in DB for node %s: config_version=%s",
                    node_id, _short_version(config_version),
                )
                return 1
        except Exception as exc:
            _log.warning("Failed to queue config_changed for node %s: %s", node_id, exc)

    _log.debug(
        "No SSE clients connected for node %s (config_version=%s) — node will sync on next poll",
        node_id, _short_version(config_version),
    )
    return 0


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
) -> int:
    """Send SSE event to node or queue command in DB (multi-worker safe).
    
    Args:
        node_id: Target node ID
        event_type: SSE event type (e.g., "restart_requested")
        event_data: SSE event data payload
        db_command: DB command to queue if SSE unavailable
        action_name: Human-readable action name for logging
    
    Returns:
        Number of clients notified (>0 if delivered or queued)
    """
    # Try direct notification to SSE clients in current worker
    async with _lock:
        queues = _node_queues.get(node_id, set()).copy()
    
    if queues:
        # Have direct SSE connection in this worker - send immediately
        event = _format_sse_event(event_type=event_type, data=event_data)
        
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
        # Node has SSE connection in another worker - queue command in DB
        from ..db.sqlite_runtime import connect
        from ..db.sqlite_nodes import set_node_pending_command
        from ..utils.config import get_config
        
        cfg = get_config()
        try:
            def _queue_cmd():
                conn = connect(cfg.db_path)
                try:
                    return set_node_pending_command(conn, node_id, db_command)
                finally:
                    conn.close()
            
            queued = await asyncio.to_thread(_queue_cmd)
            if queued:
                _log.info("Queued %s command in DB for node %s (SSE in other worker)", action_name, node_id)
                return 1
        except Exception as exc:
            _log.warning("Failed to queue %s command for node %s: %s", action_name, node_id, exc)
    
    # No SSE connection anywhere
    _log.warning("No SSE clients connected for node %s — cannot send %s signal", node_id, action_name)
    return 0


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

