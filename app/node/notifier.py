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
- SSE ping events every 25s to prevent proxy timeouts
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncGenerator

from anyio import EndOfStream

from .events import NodeCommandPayload, NodeEventBus, NodeEventType

_log = logging.getLogger(__name__)

_event_bus: NodeEventBus | None = None
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


def _format_sse_ping() -> str:
    """Format a lightweight SSE ping event."""
    return _format_sse_event("ping", "{}")


def _short_version(version: str, max_len: int = 16) -> str:
    """Truncate version string for logging."""
    return version[:max_len] if len(version) > max_len else version


def configure_event_bus(event_bus: NodeEventBus | None) -> None:
    """Attach the lifespan-scoped node event bus used for local fanout."""
    global _event_bus
    _event_bus = event_bus


async def _race(
    receive_stream,
    shutdown_event: asyncio.Event | None,
    timeout: float,
) -> object | None:
    """Return next event, None for timeout, or ""-sentinel for shutdown/end-of-stream."""
    if shutdown_event is None:
        try:
            return await asyncio.wait_for(receive_stream.receive(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        except EndOfStream:
            return ""

    receive_task = asyncio.create_task(receive_stream.receive())
    shutdown_task = asyncio.create_task(shutdown_event.wait())
    
    wait_tasks = [receive_task, shutdown_task]
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
            receive_task.cancel()
            await asyncio.gather(receive_task, return_exceptions=True)
            return ""  # shutdown sentinel
        
        if receive_task in done:
            shutdown_task.cancel()
            await asyncio.gather(shutdown_task, return_exceptions=True)
            if receive_task.cancelled():
                return None
            try:
                return receive_task.result()
            except EndOfStream:
                return ""
            
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
    bus = _event_bus
    if bus is None:
        _log.warning("Node event bus unavailable for notifier subscription: %s", node_id)
        yield _format_sse_event("close", "server_starting")
        return
    subscription = await bus.subscribe_commands(node_id)
    client_count = await bus.command_subscription_count(node_id)
    _log.debug("Node %s subscribed to config events (clients=%d)", node_id, client_count)
    
    try:
        close_event = _format_sse_event("close", "server_shutdown")
        ping_event = _format_sse_ping()
        while True:
            result = await _race(subscription.receive_stream, shutdown_event, _KEEPALIVE_INTERVAL)
            if result == "":
                yield close_event
                break
            if result is None:
                yield ping_event
                continue
            if result.type is not NodeEventType.COMMAND or not isinstance(result.payload, NodeCommandPayload):
                continue
            yield _format_sse_event(
                event_type=_command_event_name(result.payload.command),
                data=result.payload.model_dump_json(),
            )
    except asyncio.CancelledError:
        _log.debug("SSE client cancelled for node %s", node_id)
        raise
    finally:
        try:
                await subscription.aclose()
        except asyncio.CancelledError:
            _log.debug("Cleanup cancelled for node %s", node_id)
        _log.debug("Node %s unsubscribed from config events", node_id)


def _command_event_name(db_command: str) -> str:
    """Map durable command names to SSE event names."""
    return {
        "config_changed": "config_changed",
        "restart": "restart_requested",
        "speedtest": "run_speedtest",
        "removed": "node_removed",
    }.get(db_command, db_command)


async def _queue_db_command(
    node_id: str,
    command: str,
    *,
    payload: dict[str, str] | None = None,
) -> int | None:
    """Queue a durable command in SQLite for replay-safe delivery."""
    from ..db.sqlite_runtime import close_connection, connect
    from ..db.sqlite_nodes import enqueue_node_command
    from ..utils.config import get_config

    cfg = get_config()
    try:
        def _queue():
            conn = connect(cfg.db_path)
            try:
                return enqueue_node_command(conn, node_id, command, payload=payload)
            finally:
                close_connection(conn)
        return await asyncio.to_thread(_queue)
    except Exception as exc:
        _log.warning("Failed to queue %s command for node %s: %s", command, node_id, exc)
        return None


async def _mark_db_command_delivered(node_id: str, command_id: int) -> bool:
    """Mark a queued command as delivered to a live SSE subscriber."""
    from ..db.sqlite_runtime import close_connection, connect
    from ..db.sqlite_nodes import mark_node_command_delivered
    from ..utils.config import get_config

    cfg = get_config()
    try:
        def _mark():
            conn = connect(cfg.db_path)
            try:
                return mark_node_command_delivered(conn, node_id, command_id)
            finally:
                close_connection(conn)
        return await asyncio.to_thread(_mark)
    except Exception as exc:
        _log.warning("Failed to mark command %s delivered for node %s: %s", command_id, node_id, exc)
        return False


def _command_event_data(command_id: int, db_command: str, *, config_version: str | None = None) -> str:
    """Build structured JSON command payload for SSE delivery."""
    payload: dict[str, str | int] = {
        "command_id": int(command_id),
        "command": db_command,
    }
    if config_version:
        payload["config_version"] = config_version
    return json.dumps(payload, separators=(",", ":"))


async def get_connected_nodes() -> list[str]:
    """Return list of node IDs with active SSE connections."""
    bus = _event_bus
    if bus is None:
        return []
    return await bus.active_command_nodes()


async def get_connection_count(node_id: str) -> int:
    """Return number of active SSE connections for a node."""
    bus = _event_bus
    if bus is None:
        return 0
    return await bus.command_subscription_count(node_id)


async def is_node_connected(node_id: str) -> bool:
    """Check if a node has active SSE connections (multi-worker safe via DB).
    
    Uses database timestamp instead of in-memory dict to work correctly
    with multiple uvicorn workers. Runs DB query in threadpool to avoid
    blocking the async event loop.
    """
    from ..db.sqlite_runtime import close_connection, connect
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
                close_connection(conn)
        
        return await asyncio.to_thread(_check_db)
    except Exception as exc:
        _log.debug("Failed to check SSE status for node %s: %s", node_id, exc)
        bus = _event_bus
        if bus is None:
            return False
        return await bus.command_subscription_count(node_id) > 0


def is_node_connected_sync(node_id: str) -> bool:
    """Synchronous version of is_node_connected() for non-async callers.
    
    WARNING: Blocks the calling thread. Prefer is_node_connected() in async code.
    Thread-safe: Uses threading.Lock for safe access from sync contexts.
    """
    from ..db.sqlite_runtime import close_connection, connect
    from ..db.sqlite_nodes import is_node_sse_connected
    from ..utils.config import get_config
    
    cfg = get_config()
    try:
        conn = connect(cfg.db_path)
        try:
            return is_node_sse_connected(conn, node_id)
        finally:
            close_connection(conn)
    except Exception as exc:
        _log.debug("Failed to check SSE status for node %s: %s", node_id, exc)
        return False


async def _notify_or_queue(
    node_id: str,
    event_type: str,
    db_command: str,
    action_name: str,
    *,
    config_version: str | None = None,
) -> int:
    """Send SSE event to node or queue command in DB (multi-worker safe).
    
    Args:
        node_id: Target node ID
        event_type: SSE event type (e.g., "restart_requested")
        db_command: DB command to queue if SSE unavailable
        action_name: Human-readable action name for logging
        config_version: Optional config version payload for config change notifications
    
    Returns:
        Number of clients notified (>0 if delivered or queued)
    """
    node_id = _validate_node_id(node_id)
    queue_payload = {"config_version": config_version} if config_version else None
    command_id = await _queue_db_command(node_id, db_command, payload=queue_payload)
    if command_id is None:
        _log.warning("Failed to queue durable %s command for node %s", action_name, node_id)
        return 0
    payload_json = _command_event_data(command_id, db_command, config_version=config_version)
    
    # Try direct notification to SSE clients in current worker via lifecycle-scoped bus.
    bus = _event_bus
    if bus is not None:
        notified = await bus.publish_command(
            node_id,
            NodeCommandPayload(
                command_id=int(command_id),
                command=db_command,
                config_version=config_version,
            ),
        )
        if notified > 0:
            await _mark_db_command_delivered(node_id, int(command_id))
            _log.info("Sent %s signal to %d SSE client(s) for node %s (command_id=%s)", action_name, notified, node_id, command_id)
            return max(notified, 1)
    
    # No SSE clients in current worker - durable command remains queued for replay.
    if await is_node_connected(node_id):
        _log.info("Queued %s command in DB for node %s (SSE connected in other worker, command_id=%s)", action_name, node_id, command_id)
        return 1
    
    # No SSE connection anywhere; command stays durable until reconnect.
    _log.warning("No SSE clients connected for node %s — queued durable %s command_id=%s", node_id, action_name, command_id)
    return 1


async def notify_config_changed(node_id: str, config_version: str) -> int:
    """Notify all connected clients for a node that config has changed.
    
    Returns the number of clients notified or queued.
    """
    return await _notify_or_queue(
        node_id=node_id,
        event_type="config_changed",
        db_command="config_changed",
        action_name="config change",
        config_version=config_version,
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
        db_command="removed",
        action_name="removal",
    )
