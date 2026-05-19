#!/usr/bin/env python3
#
# app/node/events.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Typed node event models and ephemeral in-process event bus."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from anyio import BrokenResourceError, ClosedResourceError, Lock, WouldBlock, create_memory_object_stream
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from pydantic import BaseModel, Field


class NodeEventType(StrEnum):
	"""Ephemeral node event types delivered only inside one process."""

	COMMAND = "command"
	SPEEDTEST_PROGRESS = "speedtest_progress"


class NodeCommandType(StrEnum):
	"""Durable command types delivered to remote nodes."""

	CONFIG_CHANGED = "config_changed"
	RESTART = "restart"
	SPEEDTEST = "speedtest"
	REMOVED = "removed"


class SpeedtestProgressPayload(BaseModel):
	"""Structured speedtest progress payload sent by a node."""

	phase: str = Field(..., max_length=64)
	progress: float = Field(..., ge=0.0, le=1.0)
	message: str = Field("", max_length=256)
	detail: dict[str, object] | str | None = None


class NodeCommandPayload(BaseModel):
	"""Structured command payload sent to a node via SSE."""

	command_id: int = Field(..., ge=1)
	command: NodeCommandType
	config_version: str | None = Field(default=None, max_length=128)


class NodeEvent(BaseModel):
	"""Typed in-process event envelope for one node."""

	node_id: str = Field(..., min_length=1, max_length=64)
	type: NodeEventType
	payload: SpeedtestProgressPayload | NodeCommandPayload


@dataclass(slots=True)
class NodeEventSubscription:
	"""Active subscription to the ephemeral node event bus."""

	node_id: str
	receive_stream: MemoryObjectReceiveStream[NodeEvent]
	latest_progress: SpeedtestProgressPayload | None
	_bus: NodeEventBus
	_send_stream: MemoryObjectSendStream[NodeEvent]

	async def aclose(self) -> None:
		"""Unsubscribe and close the underlying AnyIO streams."""
		await self._bus.unsubscribe(self.node_id, self._send_stream, self.receive_stream)


class NodeEventBus:
	"""Process-local AnyIO event bus for ephemeral node runtime events."""

	def __init__(self, *, buffer_size: int = 32) -> None:
		self._buffer_size = max(1, int(buffer_size))
		self._lock = Lock()
		self._command_subscribers: dict[str, set[MemoryObjectSendStream[NodeEvent]]] = {}
		self._speedtest_subscribers: dict[str, set[MemoryObjectSendStream[NodeEvent]]] = {}
		self._latest_speedtest: dict[str, SpeedtestProgressPayload] = {}

	async def subscribe_commands(self, node_id: str) -> NodeEventSubscription:
		"""Subscribe to live ephemeral command events for one node."""
		send_stream, receive_stream = create_memory_object_stream[NodeEvent](self._buffer_size)
		async with self._lock:
			self._command_subscribers.setdefault(node_id, set()).add(send_stream)
		return NodeEventSubscription(
			node_id=node_id,
			receive_stream=receive_stream,
			latest_progress=None,
			_bus=self,
			_send_stream=send_stream,
		)

	async def subscribe_speedtest(self, node_id: str) -> NodeEventSubscription:
		"""Subscribe to ephemeral speedtest progress events for one node."""
		send_stream, receive_stream = create_memory_object_stream[NodeEvent](self._buffer_size)
		async with self._lock:
			self._speedtest_subscribers.setdefault(node_id, set()).add(send_stream)
			latest = self._latest_speedtest.get(node_id)
		return NodeEventSubscription(
			node_id=node_id,
			receive_stream=receive_stream,
			latest_progress=latest,
			_bus=self,
			_send_stream=send_stream,
		)

	async def unsubscribe(
		self,
		node_id: str,
		send_stream: MemoryObjectSendStream[NodeEvent],
		receive_stream: MemoryObjectReceiveStream[NodeEvent],
	) -> None:
		"""Remove one subscriber and close its streams."""
		async with self._lock:
			for subscribers in (self._speedtest_subscribers, self._command_subscribers):
				streams = subscribers.get(node_id)
				if streams is not None:
					streams.discard(send_stream)
					if not streams:
						del subscribers[node_id]
		await send_stream.aclose()
		await receive_stream.aclose()

	async def _publish(
		self,
		node_id: str,
		event: NodeEvent,
		*,
		subscribers: dict[str, set[MemoryObjectSendStream[NodeEvent]]],
	) -> int:
		async with self._lock:
			streams = list(subscribers.get(node_id, ()))

		stale_streams: list[MemoryObjectSendStream[NodeEvent]] = []
		delivered = 0
		for stream in streams:
			try:
				stream.send_nowait(event)
				delivered += 1
			except WouldBlock:
				continue
			except (BrokenResourceError, ClosedResourceError):
				stale_streams.append(stream)

		if stale_streams:
			async with self._lock:
				current = subscribers.get(node_id)
				if current is not None:
					for stream in stale_streams:
						current.discard(stream)
					if not current:
						del subscribers[node_id]
		return delivered

	async def publish_speedtest(self, node_id: str, payload: SpeedtestProgressPayload) -> None:
		"""Publish a speedtest progress event to all current local subscribers."""
		event = NodeEvent(node_id=node_id, type=NodeEventType.SPEEDTEST_PROGRESS, payload=payload)
		async with self._lock:
			self._latest_speedtest[node_id] = payload
		await self._publish(node_id, event, subscribers=self._speedtest_subscribers)

	async def publish_command(self, node_id: str, payload: NodeCommandPayload) -> int:
		"""Publish a live command event to current local subscribers."""
		event = NodeEvent(node_id=node_id, type=NodeEventType.COMMAND, payload=payload)
		return await self._publish(node_id, event, subscribers=self._command_subscribers)

	async def command_subscription_count(self, node_id: str) -> int:
		"""Return the number of active local command subscribers for one node."""
		async with self._lock:
			return len(self._command_subscribers.get(node_id, ()))

	async def active_command_nodes(self) -> list[str]:
		"""Return node IDs that currently have local command subscribers."""
		async with self._lock:
			return list(self._command_subscribers.keys())

	async def aclose(self) -> None:
		"""Close the bus and all subscriber streams."""
		async with self._lock:
			all_streams = [
				stream
				for subscriber_map in (self._speedtest_subscribers, self._command_subscribers)
				for streams in subscriber_map.values()
				for stream in streams
			]
			self._command_subscribers.clear()
			self._speedtest_subscribers.clear()
			self._latest_speedtest.clear()
		for stream in all_streams:
			await stream.aclose()