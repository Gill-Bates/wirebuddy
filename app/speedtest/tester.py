#!/usr/bin/env python3
#
# app/speedtest/tester.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Asynchronous bandwidth measurement using streaming downloads (no file storage).

Features:
- RTT-based server selection
- Busy-detection to avoid skewed results
- Multi-stream download test
- Multi-stream upload test
- RTT + Jitter measurement
- Median-stabilised statistics
- Only httpx + stdlib
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import statistics
import time
from typing import Any
from urllib.parse import urlparse

import httpx

_log = logging.getLogger(__name__)

# Default speed test servers (ordered by reliability)
# Using direct file hosts that don't block automated requests
DEFAULT_SERVERS = [
	"http://speedtest.tele2.net/10MB.zip",
	"http://ipv4.download.thinkbroadband.com/10MB.zip",
	"http://cachefly.cachefly.net/100mb.test",
]

# Upload endpoint - httpbin is reliable for upload testing
DEFAULT_UPLOAD_ENDPOINT = "https://httpbin.org/post"

# Browser-like User-Agent to avoid bot detection
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

_BUSY_CHECK_DURATION_SECONDS = 3.0
_DEFAULT_JITTER_THRESHOLD_MS = 50.0  # More realistic for consumer connections


class BandwidthTester:
	"""Lightweight async bandwidth tester."""

	def __init__(
		self,
		servers: list[str] | None = None,
		upload_endpoint: str | None = None,
		streams: int = 4,
		test_duration: float = 6.0,
		warmup_duration: float = 2.0,
		rtt_samples: int = 8,
		runs: int = 3,
		chunk_size: int = 65536,
		busy_check_duration: float = _BUSY_CHECK_DURATION_SECONDS,
		jitter_threshold_ms: float = _DEFAULT_JITTER_THRESHOLD_MS,
	):
		# Input validation
		if streams < 1:
			raise ValueError("streams must be >= 1")
		if test_duration <= 0:
			raise ValueError("test_duration must be positive")
		if runs < 1:
			raise ValueError("runs must be >= 1")
		if warmup_duration < 0:
			raise ValueError("warmup_duration must be non-negative")
		if rtt_samples < 1:
			raise ValueError("rtt_samples must be >= 1")
		if chunk_size < 1024:
			raise ValueError("chunk_size must be >= 1024")

		self.servers = servers or list(DEFAULT_SERVERS)
		self.upload_endpoint = upload_endpoint or DEFAULT_UPLOAD_ENDPOINT
		self.streams = streams
		self.test_duration = test_duration
		self.warmup_duration = warmup_duration
		self.rtt_samples = rtt_samples
		self.runs = runs
		self.chunk_size = chunk_size
		self.busy_check_duration = busy_check_duration
		self.jitter_threshold_ms = jitter_threshold_ms

		# Pre-generate random upload payload (incompressible)
		self._upload_payload = os.urandom(1024 * 1024)

	@staticmethod
	def _origin(url: str) -> str:
		"""Extract origin (scheme + netloc) from URL."""
		p = urlparse(url)
		return f"{p.scheme}://{p.netloc}"

	async def measure_rtt(
		self, client: httpx.AsyncClient, url: str
	) -> dict[str, float] | None:
		"""Measure round-trip time to server.
		
		Uses GET with Range header instead of HEAD because some CDNs/load balancers
		don't properly support HEAD requests and disconnect without response.
		Range: bytes=0-0 fetches only 1 byte, minimizing bandwidth while ensuring
		the server actually processes the request.
		"""
		origin = self._origin(url)
		samples: list[float] = []
		failures = 0

		for _ in range(self.rtt_samples):
			start = time.perf_counter()
			try:
				# Use GET with Range instead of HEAD for better compatibility
				# Some servers (e.g., Hetzner) disconnect on HEAD without response
				headers = {"Range": "bytes=0-0"}
				response = await client.get(origin, headers=headers)
				await response.aclose()  # Immediately close to avoid reading body
				samples.append(time.perf_counter() - start)
			except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.TimeoutException) as exc:
				failures += 1
				_log.debug("RTT probe failed for %s: %s", origin, exc)
			except Exception as exc:
				failures += 1
				_log.debug("RTT probe failed for %s: %s", origin, exc, exc_info=True)

		if not samples:
			_log.warning(
				"RTT measurement failed for %s (%d/%d probes failed)",
				origin, failures, self.rtt_samples
			)
			return None

		return {
			"median": statistics.median(samples),
			"jitter": statistics.stdev(samples) if len(samples) > 1 else 0.0,
		}

	async def select_server(
		self, client: httpx.AsyncClient
	) -> tuple[str, float, float]:
		"""Select best server based on RTT measurement.
		
		Returns:
			Tuple of (server_url, median_rtt_seconds, jitter_seconds)
			
		Raises:
			RuntimeError: If no servers are reachable
		"""
		# Probe all servers in parallel
		tasks = [self.measure_rtt(client, url) for url in self.servers]
		results_list = await asyncio.gather(*tasks, return_exceptions=True)
		
		results: list[tuple[str, float, float]] = []
		for url, rtt in zip(self.servers, results_list):
			if isinstance(rtt, Exception):
				_log.warning("Server probe failed for %s: %s", url, rtt)
			elif rtt is not None:
				results.append((url, rtt["median"], rtt["jitter"]))
				_log.debug(
					"Server probe succeeded: %s rtt=%.2fms jitter=%.2fms",
					url, rtt["median"] * 1000, rtt["jitter"] * 1000
				)
			else:
				_log.warning("Server probe returned no data for %s (all RTT probes failed)", url)

		if not results:
			failed_servers = ", ".join(self.servers)
			raise RuntimeError(
				f"No reachable speed test servers. Tried {len(self.servers)} servers: {failed_servers}"
			)

		# Sort by RTT (lowest first)
		results.sort(key=lambda x: x[1])
		best_server, best_rtt, best_jitter = results[0]
		_log.info(
			"Selected server: %s (rtt=%.2fms, jitter=%.2fms)",
			best_server, best_rtt * 1000, best_jitter * 1000
		)
		return results[0]

	async def _download_worker(
		self, client: httpx.AsyncClient, url: str, duration: float
	) -> tuple[int, float]:
		"""Download worker returns (bytes_transferred, actual_elapsed_time)."""
		total = 0
		start = time.perf_counter()
		params = {"r": random.randint(0, 10**9)}

		try:
			async with client.stream("GET", url, params=params) as r:
				# Check HTTP status before streaming
				if r.status_code >= 400:
					_log.warning("Download worker HTTP error: %s %s", r.status_code, url)
					return (0, time.perf_counter() - start)
				
				content_length = r.headers.get("content-length", "unknown")
				_log.debug("Download stream: status=%s content-length=%s", r.status_code, content_length)
				
				async for chunk in r.aiter_bytes(self.chunk_size):
					total += len(chunk)
					if time.perf_counter() - start >= duration:
						break
		except Exception as exc:
			_log.warning("Download worker failed: %s: %s", type(exc).__name__, exc)

		elapsed = time.perf_counter() - start
		_log.debug("Download worker: %d bytes in %.2fs (%.1f Mbit/s)", total, elapsed, (total * 8 / elapsed / 1_000_000) if elapsed > 0 else 0)
		return (total, elapsed)

	async def _upload_worker(
		self, client: httpx.AsyncClient, duration: float
	) -> tuple[int, float]:
		"""Upload worker returns (bytes_transferred, actual_elapsed_time)."""
		total = 0
		start = time.perf_counter()

		try:
			while time.perf_counter() - start < duration:
				await client.post(self.upload_endpoint, content=self._upload_payload)
				total += len(self._upload_payload)
		except Exception as exc:
			_log.warning("Upload worker failed for %s: %s", self.upload_endpoint, exc)

		elapsed = time.perf_counter() - start
		return (total, elapsed)

	async def warmup(self, client: httpx.AsyncClient, url: str) -> None:
		tasks = [
			self._download_worker(client, url, self.warmup_duration) for _ in range(self.streams)
		]
		await asyncio.gather(*tasks)

	async def busy_check(
		self, client: httpx.AsyncClient, url: str
	) -> bool:
		"""Check if network is busy/congested.
		
		Measures RTT before and during download to detect congestion.
		Returns True if network appears busy (test should be skipped).
		"""
		idle = await self.measure_rtt(client, url)
		if idle is None:
			_log.warning("BUSY_CHECK failed to measure idle RTT, assuming busy")
			return True

		task = asyncio.create_task(self._download_worker(client, url, self.busy_check_duration))
		loaded = await self.measure_rtt(client, url)
		await task

		if loaded is None:
			_log.warning("BUSY_CHECK failed to measure loaded RTT, assuming busy")
			return True

		rtt_factor = loaded["median"] / idle["median"]
		jitter_threshold_seconds = self.jitter_threshold_ms / 1000.0
		
		is_busy = rtt_factor > 2.0 or loaded["jitter"] > jitter_threshold_seconds
		if is_busy:
			_log.info(
				"BUSY_CHECK network appears congested (rtt_factor=%.2f, jitter=%.2fms)",
				rtt_factor, loaded["jitter"] * 1000
			)
		
		return is_busy

	async def download_test(
		self, client: httpx.AsyncClient, url: str
	) -> float:
		tasks = [
			self._download_worker(client, url, self.test_duration)
			for _ in range(self.streams)
		]
		results = await asyncio.gather(*tasks)
		total_bytes = sum(r[0] for r in results)
		max_elapsed = max(r[1] for r in results)
		return (total_bytes * 8) / max_elapsed / 1_000_000

	async def upload_test(self, client: httpx.AsyncClient) -> float:
		tasks = [
			self._upload_worker(client, self.test_duration)
			for _ in range(self.streams)
		]
		results = await asyncio.gather(*tasks)
		total_bytes = sum(r[0] for r in results)
		max_elapsed = max(r[1] for r in results)
		return (total_bytes * 8) / max_elapsed / 1_000_000

	async def run(self) -> dict[str, Any]:
		# Longer read timeout for streaming downloads
		timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
		
		# Browser-like headers to avoid bot detection
		headers = {
			"User-Agent": _USER_AGENT,
			"Accept": "*/*",
			"Accept-Encoding": "identity",  # No compression for accurate bandwidth measurement
		}

		# Disable HTTP/2 - some speed test servers have issues with it  
		# Enable redirect following for CDNs that redirect to edge servers
		async with httpx.AsyncClient(
			timeout=timeout,
			http2=False,
			verify=False,
			follow_redirects=True,
			headers=headers,
		) as client:
			server, rtt, jitter = await self.select_server(client)
			_log.info(
				"SPEEDTEST server=%s rtt=%.2fms jitter=%.2fms",
				server,
				rtt * 1000,
				jitter * 1000,
			)

			busy = await self.busy_check(client, server)
			if busy:
				_log.warning("SPEEDTEST network busy, skipping measurement")
				return {
					"status": "busy",
					"server": server,
					"rtt_ms": round(rtt * 1000, 2),
					"jitter_ms": round(jitter * 1000, 2),
				}

			await self.warmup(client, server)

			dl_runs: list[float] = []
			ul_runs: list[float] = []

			for i in range(self.runs):
				dl = await self.download_test(client, server)
				ul = await self.upload_test(client)
				dl_runs.append(dl)
				ul_runs.append(ul)
				_log.debug(
					"SPEEDTEST run=%d/%d dl=%.2f ul=%.2f Mbit/s",
					i + 1,
					self.runs,
					dl,
					ul,
				)

			return {
				"status": "ok",
				"server": server,
				"rtt_ms": round(rtt * 1000, 2),
				"jitter_ms": round(jitter * 1000, 2),
				"download_mbit": round(statistics.median(dl_runs), 2),
				"upload_mbit": round(statistics.median(ul_runs), 2),
			}
