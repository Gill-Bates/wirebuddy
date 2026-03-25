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
- Multi-stream upload test (chunked transfer encoding)
- RTT + Jitter measurement
- Median-stabilised statistics
- Only httpx + stdlib
"""

from __future__ import annotations

import asyncio
import itertools
import ipaddress
import logging
import os
import random
import statistics
import time
from typing import Any, AsyncGenerator, AsyncIterator, Callable, TypedDict
from urllib.parse import urlparse

import httpx

_log = logging.getLogger(__name__)


class ProgressEvent(TypedDict, total=False):
	"""Progress event emitted during speedtest execution."""
	phase: str  # Current phase name
	progress: float  # 0.0 - 1.0
	message: str  # Human-readable status
	detail: dict[str, Any] | None  # Optional extra data


# Type alias for progress callback
ProgressCallback = Callable[[ProgressEvent], None]

# Default speed test servers (ordered by reliability)
# Using large files to support Gbit+ connections (1 Gbit/s × 6s = 750 MB needed)
DEFAULT_SERVERS = [
	"http://speedtest.tele2.net/1GB.zip",  # 1 GB
	"http://cachefly.cachefly.net/100mb.test",  # 100 MB
	"http://ipv4.download.thinkbroadband.com/100MB.zip",  # 100 MB
]

# Fixed upload test targets. These are intentionally not user-configurable.
# The endpoints below are public throwaway/speedtest upload sinks intended for
# high-volume POST traffic rather than generic echo services.
# Each target specifies its HTTP method: POST (default) or PUT (e.g., Tele2).
# probe_url is used for RTT measurement (GET-able path, since upload endpoints reject GET).
DEFAULT_UPLOAD_TARGETS = [
	{"name": "Serverius (Netherlands)", "url": "http://speedtest.serverius.net/upload", "method": "POST", "probe_url": "http://speedtest.serverius.net/"},
	{"name": "Tele2 (Anycast Europe)", "url": "http://speedtest.tele2.net/upload.php", "method": "PUT", "probe_url": "http://speedtest.tele2.net/100KB.zip"},
]

# Browser-like User-Agent to avoid bot detection
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

_BUSY_CHECK_DURATION_SECONDS = 3.0
_DEFAULT_JITTER_THRESHOLD_MS = 50.0  # More realistic for consumer connections

# Documented constants (previously magic numbers)
# FIX: Relaxed thresholds to avoid false positives on consumer connections with bufferbloat
_RTT_BUSY_FACTOR = 4.0  # RTT increase factor to consider network "busy" (was 2.0)
_JITTER_BUSY_FACTOR = 3.0  # Jitter increase factor threshold (was 1.5)
_JITTER_RTT_CORRELATION = 1.5  # Minimum RTT increase when jitter triggers (was 1.2)
_CACHE_BUST_MAX = 10**9  # Upper bound for random cache-busting parameter
_UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB upload chunks (incompressible random data)
_UPLOAD_PAYLOAD_VARIANTS = 4  # Rotate payloads to reduce repeated-block bias
_DEFAULT_CHUNK_SIZE = 262_144  # 256 KB - better throughput for Gbit+ connections
_REQUEST_TIMEOUT_BUFFER_SECONDS = 10.0
_BUSY_CHECK_PROBE_BUDGET_SECONDS = 0.5
_CONNECT_TIMEOUT_SECONDS = 5.0  # TCP+TLS connection timeout
_BUSY_CHECK_START_TIMEOUT_SECONDS = 8.0  # Must exceed connect timeout + response time


class SpeedtestTarget(TypedDict, total=False):
	"""Download/upload target description."""
	name: str
	url: str
	probe_url: str


class RTTResult(TypedDict):
	"""RTT probe result."""
	median: float
	jitter: float
	success_ratio: float
	successes: int


class BandwidthTester:
	"""Lightweight async bandwidth tester."""

	def __init__(
		self,
		servers: list[str] | None = None,
		streams: int = 4,
		test_duration: float = 6.0,
		warmup_duration: float = 2.0,
		rtt_samples: int = 8,
		runs: int = 3,
		chunk_size: int = _DEFAULT_CHUNK_SIZE,
		busy_check_duration: float = _BUSY_CHECK_DURATION_SECONDS,
		jitter_threshold_ms: float = _DEFAULT_JITTER_THRESHOLD_MS,
		progress_callback: ProgressCallback | None = None,
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
		# Validate server URLs
		for url in self.servers:
			if not url or not isinstance(url, str):
				raise ValueError(f"Invalid server URL: {url!r}")
			parsed = urlparse(url)
			if parsed.scheme not in ("http", "https"):
				raise ValueError(f"Server URL must use http:// or https://: {url}")
			if not parsed.netloc:
				raise ValueError(f"Server URL missing hostname: {url}")
		self.upload_targets = [dict(target) for target in DEFAULT_UPLOAD_TARGETS]
		self.streams = streams
		self.test_duration = test_duration
		self.warmup_duration = warmup_duration
		self.rtt_samples = rtt_samples
		self.runs = runs
		self.chunk_size = chunk_size
		self.busy_check_duration = busy_check_duration
		self.jitter_threshold_ms = jitter_threshold_ms
		self._progress_callback = progress_callback

		# Pre-generate random upload payloads (incompressible) and rotate them
		# to avoid repeating a single 1 MiB block for the entire test.
		self._upload_payloads = [
			os.urandom(_UPLOAD_CHUNK_SIZE) for _ in range(_UPLOAD_PAYLOAD_VARIANTS)
		]

	def _emit_progress(self, phase: str, progress: float, message: str, detail: dict[str, Any] | None = None) -> None:
		"""Emit progress event if callback is registered."""
		if self._progress_callback is not None:
			event: ProgressEvent = {
				"phase": phase,
				"progress": progress,
				"message": message,
			}
			if detail:
				event["detail"] = detail
			try:
				self._progress_callback(event)
			except Exception as exc:
				_log.debug("Progress callback failed: %s", exc)

	@staticmethod
	def _target_label(target: SpeedtestTarget) -> str:
		"""Return a human-readable label for a download/upload target."""
		return target.get("name") or target.get("url") or "unknown"

	@staticmethod
	def _is_dynamic_endpoint(url: str) -> bool:
		"""Detect dynamic endpoints that don't support Range requests.
		
		Dynamic endpoints (PHP scripts, query-string-driven generators) typically
		return 404 or ignore Range headers when probed with GET + Range: bytes=0-0.
		For these, we probe the origin instead of the full path.
		"""
		parsed = urlparse(url)
		# Query parameters indicate a dynamic endpoint
		if parsed.query:
			return True
		# Common script extensions that generate content dynamically
		path_lower = parsed.path.lower()
		dynamic_extensions = (".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl")
		return any(path_lower.endswith(ext) for ext in dynamic_extensions)

	@staticmethod
	def _origin(url: str) -> str:
		"""Extract origin (scheme + netloc) from URL."""
		p = urlparse(url)
		return f"{p.scheme}://{p.netloc}"

	def _target_probe_url(self, target: SpeedtestTarget) -> str:
		"""Return the URL used for RTT probing for a target.

		For static files (CDN-hosted .zip, .bin, .test), probes the full URL so
		CDN routing for the specific content path is measured.
		
		For dynamic endpoints (PHP scripts, query-string URLs), probes the origin
		only, since these don't support Range requests on the actual endpoint.
		"""
		probe_url = str(target.get("probe_url") or "").strip()
		if probe_url:
			return probe_url
		url = str(target.get("url") or "")
		if self._is_dynamic_endpoint(url):
			return self._origin(url)
		return url

	def _busy_check_load_duration(self) -> float:
		"""Keep synthetic load active long enough for RTT probing to overlap."""
		return self.busy_check_duration + (self.rtt_samples * _BUSY_CHECK_PROBE_BUDGET_SECONDS)

	def _is_congested(
		self,
		idle: RTTResult,
		loaded: RTTResult,
		*,
		log_prefix: str,
		subject: str,
	) -> bool:
		"""Compare idle vs loaded RTT/jitter and decide if the path is congested.
		
		FIX: Relaxed thresholds to reduce false positives on consumer connections.
		Typical home DSL/cable connections show 2-3x RTT increase during saturation
		due to bufferbloat, which is normal behavior, not pre-existing congestion.
		"""
		rtt_factor = loaded["median"] / idle["median"]
		jitter_threshold_seconds = self.jitter_threshold_ms / 1000.0
		idle_jitter = float(idle.get("jitter", 0.0))
		loaded_jitter = float(loaded.get("jitter", 0.0))
		jitter_factor = (loaded_jitter / idle_jitter) if idle_jitter > 0 else float("inf")

		busy_by_rtt = rtt_factor > _RTT_BUSY_FACTOR
		busy_by_jitter = (
			loaded_jitter > max(jitter_threshold_seconds, idle_jitter * 2.0)
			and rtt_factor > _JITTER_RTT_CORRELATION
			and jitter_factor > _JITTER_BUSY_FACTOR
		)
		is_busy = busy_by_rtt or busy_by_jitter
		if is_busy:
			_log.info(
				"%s %s appears congested (idle_rtt=%.2fms, loaded_rtt=%.2fms, "
				"rtt_factor=%.2f, idle_jitter=%.2fms, loaded_jitter=%.2fms, jitter_factor=%.2f)",
				log_prefix,
				subject,
				idle["median"] * 1000,
				loaded["median"] * 1000,
				rtt_factor,
				idle_jitter * 1000,
				loaded_jitter * 1000,
				jitter_factor,
			)
		return is_busy


	async def measure_rtt(
		self, client: httpx.AsyncClient, url: str
	) -> RTTResult | None:
		"""Measure round-trip time to server.

		Probes the exact URL (not just the origin) so CDN routing for the content
		path is reflected in the result. Uses GET with Range: bytes=0-0 instead of
		HEAD because some CDNs/load balancers disconnect on HEAD without a response.
		
		For 206 responses the 1-byte body is fully drained, allowing connection
		reuse across samples (stable jitter). For 200 responses (server ignores
		Range) the connection is closed early; those servers contribute a slightly
		higher first-probe cost but are still usable for server selection.
		"""
		samples: list[float] = []
		failures = 0

		for _ in range(self.rtt_samples):
			start = time.perf_counter()
			try:
				# Use GET with Range instead of HEAD for better compatibility
				# Some servers (e.g., Hetzner) disconnect on HEAD without response
				headers = {"Range": "bytes=0-0"}
				async with client.stream("GET", url, headers=headers) as response:
					if response.status_code >= 400:
						failures += 1
						_log.debug("RTT probe HTTP error for %s: %s", url, response.status_code)
						continue
					async for _chunk in response.aiter_bytes(1):
						break
					if response.status_code != 206:
					# Range header was ignored (200 OK with full body) — close early
					# to prevent httpx from draining the entire response, which would
					# block this probe and skew RTT. The context manager will no-op
					# since we already closed it.
						await response.aclose()
				samples.append(time.perf_counter() - start)
			except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.TimeoutException) as exc:
				failures += 1
				_log.debug("RTT probe failed for %s: %s", url, exc)
			except Exception as exc:
				failures += 1
				_log.debug("RTT probe failed for %s: %s", url, exc, exc_info=True)

		if not samples:
			_log.warning(
				"RTT measurement failed for %s (%d/%d probes failed)",
				url, failures, self.rtt_samples
			)
			return None

		return {
			"median": statistics.median(samples),
			"jitter": statistics.stdev(samples) if len(samples) > 1 else 0.0,
			"success_ratio": len(samples) / self.rtt_samples,
			"successes": len(samples),  # Keep as int, no conversion needed
		}

	async def _select_best_target(
		self,
		targets: list[SpeedtestTarget],
		verified_client: httpx.AsyncClient,
		unverified_client: httpx.AsyncClient,
		*,
		kind: str,
	) -> tuple[SpeedtestTarget, float, float]:
		"""Select best target based on RTT measurement.
		
		Returns:
			Tuple of (target, median_rtt_seconds, jitter_seconds)
			
		Raises:
			RuntimeError: If no targets are reachable
		"""
		# Require at least half of RTT probes to succeed before trusting a server.
		min_successes = max(2, (self.rtt_samples + 1) // 2)

		# Probe all candidate targets in parallel.
		# Use unverified_client for all speedtest probes - we only measure bandwidth,
		# not transferring sensitive data, so expired/invalid certs shouldn't block tests.
		tasks = [
			self.measure_rtt(
				unverified_client,
				self._target_probe_url(target),
			)
			for target in targets
		]
		results_list = await asyncio.gather(*tasks, return_exceptions=True)
		
		results: list[tuple[SpeedtestTarget, float, float, float]] = []
		for target, rtt in zip(targets, results_list):
			label = self._target_label(target)
			if isinstance(rtt, Exception):
				_log.warning("%s probe failed for %s: %s", kind, label, rtt)
			elif rtt is not None:
				successes = rtt.get("successes", 0)
				success_ratio = float(rtt.get("success_ratio", 0.0))
				if successes < min_successes:
					_log.warning(
						"%s probe rejected: %s only %d/%d RTT probes succeeded",
						kind,
						label,
						successes,
						self.rtt_samples,
					)
					continue
				results.append((target, success_ratio, rtt["median"], rtt["jitter"]))
				_log.debug(
					"%s probe succeeded: %s success=%.0f%% rtt=%.2fms jitter=%.2fms",
					kind,
					label,
					success_ratio * 100,
					rtt["median"] * 1000,
					rtt["jitter"] * 1000,
				)
			else:
				_log.warning("%s probe returned no data for %s (all RTT probes failed)", kind, label)

		if not results:
			failed_targets = ", ".join(self._target_label(target) for target in targets)
			raise RuntimeError(
				f"No reachable {kind} targets. Tried {len(targets)} targets: {failed_targets}"
			)

		# Prefer targets with better probe success ratio, then lower RTT, then lower jitter.
		results.sort(key=lambda x: (-x[1], x[2], x[3]))
		best_target, best_success_ratio, best_rtt, best_jitter = results[0]
		_log.info(
			"Selected %s target: %s (success=%.0f%%, rtt=%.2fms, jitter=%.2fms)",
			kind,
			self._target_label(best_target),
			best_success_ratio * 100,
			best_rtt * 1000,
			best_jitter * 1000
		)
		return best_target, best_rtt, best_jitter

	async def select_server(
		self,
		verified_client: httpx.AsyncClient,
		unverified_client: httpx.AsyncClient,
	) -> tuple[str, float, float]:
		"""Select best download server based on RTT measurement."""
		targets = [{"url": url, "name": url} for url in self.servers]
		best_target, best_rtt, best_jitter = await self._select_best_target(
			targets,
			verified_client,
			unverified_client,
			kind="download",
		)
		return str(best_target["url"]), best_rtt, best_jitter

	async def select_upload_target(
		self,
		verified_client: httpx.AsyncClient,
		unverified_client: httpx.AsyncClient,
	) -> tuple[SpeedtestTarget, float, float]:
		"""Select best fixed upload target based on RTT measurement."""
		return await self._select_best_target(
			self.upload_targets,
			verified_client,
			unverified_client,
			kind="upload",
		)

	async def _download_worker(
		self,
		client: httpx.AsyncClient,
		url: str,
		duration: float,
		started_event: asyncio.Event | None = None,
	) -> tuple[int, float]:
		"""Download worker with retry loop for when file ends early.
		
		Re-requests the file if stream ends before duration expires,
		ensuring accurate measurements even with smaller test files.
		
		Uses wall-clock time (not active stream time) to match upload worker
		behavior and avoid inflating download speeds relative to upload.
		"""
		total = 0
		start = time.perf_counter()
		download_timeout = httpx.Timeout(
			connect=_CONNECT_TIMEOUT_SECONDS,
			read=duration + _REQUEST_TIMEOUT_BUFFER_SECONDS,
			write=_CONNECT_TIMEOUT_SECONDS,
			pool=_CONNECT_TIMEOUT_SECONDS,
		)

		while time.perf_counter() - start < duration:
			# Cache-busting parameter to avoid CDN caching issues
			params = {"r": random.randint(0, _CACHE_BUST_MAX)}
			try:
				async with client.stream("GET", url, params=params, timeout=download_timeout) as r:
					# Check HTTP status before streaming
					if r.status_code >= 400:
						if started_event is not None:
							started_event.set()
						_log.warning("Download worker HTTP error: %s %s", r.status_code, url)
						break

					async for chunk in r.aiter_bytes(self.chunk_size):
						if started_event is not None and not started_event.is_set():
							started_event.set()
						total += len(chunk)
						if time.perf_counter() - start >= duration:
							break
			except (httpx.HTTPError, OSError, asyncio.TimeoutError) as exc:
				if started_event is not None and not started_event.is_set():
					started_event.set()
				_log.warning("Download worker failed: %s: %s", type(exc).__name__, exc)
				break  # Don't retry on errors

		if started_event is not None and not started_event.is_set():
			started_event.set()
		elapsed = time.perf_counter() - start
		throughput_mbit = (total * 8 / elapsed / 1_000_000) if total > 0 and elapsed > 0 else 0.0
		_log.debug("Download worker: %d bytes in %.2fs (%.1f Mbit/s)", total, elapsed, throughput_mbit)
		return (total, elapsed)

	async def _upload_stream(self, duration: float) -> AsyncGenerator[bytes, None]:
		"""Yield upload chunks until duration expires."""
		start = time.perf_counter()
		for payload in itertools.cycle(self._upload_payloads):
			if time.perf_counter() - start >= duration:
				break
			yield payload

	async def _upload_worker(
		self,
		client: httpx.AsyncClient,
		upload_url: str,
		duration: float,
		started_event: asyncio.Event | None = None,
		method: str = "POST",
	) -> tuple[int, float]:
		"""Upload worker using streaming (chunked transfer encoding).
		
		Single request with async generator eliminates RTT overhead per chunk,
		resulting in accurate bandwidth measurement regardless of latency.
		
		Args:
			method: HTTP method - "POST" (default) or "PUT" (e.g., Tele2).
		"""
		total = 0
		start = time.perf_counter()
		first_chunk = True

		async def counting_stream() -> AsyncIterator[bytes]:
			nonlocal total, first_chunk
			async for chunk in self._upload_stream(duration):
				if first_chunk and started_event is not None:
					started_event.set()
					first_chunk = False
				total += len(chunk)
				yield chunk

		try:
			# Use dedicated timeout: total duration + buffer for connection/response
			upload_timeout = httpx.Timeout(
				connect=_CONNECT_TIMEOUT_SECONDS,
				read=duration + _REQUEST_TIMEOUT_BUFFER_SECONDS,
				write=duration + _REQUEST_TIMEOUT_BUFFER_SECONDS,
				pool=_CONNECT_TIMEOUT_SECONDS,
			)
			response = await client.request(
				method,
				upload_url,
				content=counting_stream(),
				headers={"Content-Type": "application/octet-stream"},
				timeout=upload_timeout,
			)
			if response.status_code >= 400:
				_log.warning(
					"Upload worker HTTP error: %s %s",
					response.status_code,
					upload_url,
				)
		except (httpx.HTTPError, OSError, asyncio.TimeoutError) as exc:
			_log.warning("Upload worker failed for %s: %s", upload_url, exc)
		finally:
			# Ensure event is set even on failure
			if started_event is not None and not started_event.is_set():
				started_event.set()

		elapsed = time.perf_counter() - start
		throughput_mbit = (total * 8 / elapsed / 1_000_000) if total > 0 and elapsed > 0 else 0.0
		_log.debug("Upload worker: %d bytes in %.2fs (%.1f Mbit/s)", total, elapsed, throughput_mbit)
		return (total, elapsed)

	async def warmup(self, client: httpx.AsyncClient, url: str) -> None:
		"""Warm up download connections (TCP slow start)."""
		tasks = [
			self._download_worker(client, url, self.warmup_duration) for _ in range(self.streams)
		]
		await asyncio.gather(*tasks)

	async def upload_warmup(self, client: httpx.AsyncClient, upload_url: str, method: str = "POST") -> None:
		"""Warm up upload connections (TCP slow start affects upload too)."""
		tasks = [
			self._upload_worker(client, upload_url, self.warmup_duration, method=method)
			for _ in range(self.streams)
		]
		await asyncio.gather(*tasks)

	@staticmethod
	def _calculate_throughput(results: list[tuple[int, float]], *, label: str) -> float:
		"""Calculate throughput from successful workers only."""
		successful = [(byte_count, elapsed) for byte_count, elapsed in results if byte_count > 0 and elapsed > 0]
		if not successful:
			_log.warning("%s test produced no usable data", label)
			return 0.0
		total_bytes = sum(byte_count for byte_count, _ in successful)
		max_elapsed = max(elapsed for _, elapsed in successful)
		if total_bytes <= 0 or max_elapsed <= 0:
			_log.warning("%s test produced invalid timing data", label)
			return 0.0
		return (total_bytes * 8) / max_elapsed / 1_000_000

	async def download_busy_check(
		self, client: httpx.AsyncClient, url: str
	) -> bool:
		"""Check if download path is busy/congested.
		
		Measures RTT before and during download to detect congestion.
		Returns True if network appears busy (test should be skipped).
		"""
		idle = await self.measure_rtt(client, url)
		if idle is None:
			_log.warning("DOWNLOAD_BUSY_CHECK failed to measure idle RTT, assuming busy")
			return True
		if idle["median"] <= 0:
			_log.warning("DOWNLOAD_BUSY_CHECK measured non-positive idle RTT, skipping busy detection")
			return False

		load_started = asyncio.Event()
		load_duration = self._busy_check_load_duration()
		task = asyncio.create_task(
			self._download_worker(client, url, load_duration, started_event=load_started)
		)
		try:
			# Timeout must exceed connect timeout (5s) + initial response time
			await asyncio.wait_for(load_started.wait(), timeout=_BUSY_CHECK_START_TIMEOUT_SECONDS)
		except asyncio.TimeoutError:
			task.cancel()
			try:
				await task
			except asyncio.CancelledError:
				pass
			_log.warning("DOWNLOAD_BUSY_CHECK load generation never started, assuming busy")
			return True
		loaded = await self.measure_rtt(client, url)
		try:
			await task
		except BaseException:
			# Catch all exceptions including CancelledError (BaseException in 3.9+)
			# Worker errors are already logged internally
			pass

		if loaded is None:
			_log.warning("DOWNLOAD_BUSY_CHECK failed to measure loaded RTT, assuming busy")
			return True

		return self._is_congested(
			idle,
			loaded,
			log_prefix="DOWNLOAD_BUSY_CHECK",
			subject="network",
		)

	async def upload_busy_check(
		self, client: httpx.AsyncClient, upload_url: str, method: str = "POST"
	) -> bool:
		"""Check if upload path is busy/congested.
		
		Measures RTT before and during upload to detect uplink congestion.
		Upload congestion fills the outbound buffer (router/modem), which
		increases RTT for all outgoing packets including RTT probes.
		
		Returns True if upload path appears busy (upload test should be skipped).
		"""
		idle = await self.measure_rtt(client, upload_url)
		if idle is None:
			_log.warning("UPLOAD_BUSY_CHECK failed to measure idle RTT, assuming busy")
			return True
		if idle["median"] <= 0:
			_log.warning("UPLOAD_BUSY_CHECK measured non-positive idle RTT, skipping busy detection")
			return False

		load_started = asyncio.Event()
		load_duration = self._busy_check_load_duration()
		task = asyncio.create_task(
			self._upload_worker(
				client, upload_url, load_duration, started_event=load_started, method=method
			)
		)
		try:
			# Timeout must exceed connect timeout (5s) + initial response time
			await asyncio.wait_for(load_started.wait(), timeout=_BUSY_CHECK_START_TIMEOUT_SECONDS)
		except asyncio.TimeoutError:
			task.cancel()
			try:
				await task
			except asyncio.CancelledError:
				pass
			_log.warning("UPLOAD_BUSY_CHECK load generation never started, assuming busy")
			return True

		# Measure RTT while upload is saturating the uplink
		loaded = await self.measure_rtt(client, upload_url)
		
		# Wait for upload task to complete
		try:
			await task
		except BaseException:
			# Catch all exceptions including CancelledError (BaseException in 3.9+)
			# Worker errors are already logged internally
			pass

		if loaded is None:
			_log.warning("UPLOAD_BUSY_CHECK failed to measure loaded RTT, assuming busy")
			return True

		return self._is_congested(
			idle,
			loaded,
			log_prefix="UPLOAD_BUSY_CHECK",
			subject="uplink",
		)

	async def download_test(
		self, client: httpx.AsyncClient, url: str
	) -> float:
		tasks = [
			self._download_worker(client, url, self.test_duration)
			for _ in range(self.streams)
		]
		results = await asyncio.gather(*tasks)
		return self._calculate_throughput(results, label="Download")

	async def upload_test(self, client: httpx.AsyncClient, upload_url: str, method: str = "POST") -> float:
		tasks = [
			self._upload_worker(client, upload_url, self.test_duration, method=method)
			for _ in range(self.streams)
		]
		results = await asyncio.gather(*tasks)
		return self._calculate_throughput(results, label="Upload")

	async def run(self) -> dict[str, Any]:
		self._emit_progress("init", 0.0, "Initializing speedtest...")

		# Longer read timeout for streaming downloads
		timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)

		# Connection pool tuning: ensure enough connections for parallel streams
		limits = httpx.Limits(
			max_connections=self.streams + 4,
			max_keepalive_connections=self.streams + 4,
		)

		# Browser-like headers to avoid bot detection
		headers = {
			"User-Agent": _USER_AGENT,
			"Accept": "*/*",
			"Accept-Encoding": "identity",  # No compression for accurate bandwidth measurement
		}

		# Disable HTTP/2 - some speed test servers have issues with it.
		# Use verify=False for all speedtest traffic - we're only measuring bandwidth,
		# not handling sensitive data, so expired/self-signed certs shouldn't block tests.
		async with httpx.AsyncClient(
			timeout=timeout,
			limits=limits,
			http2=False,
			verify=False,
			follow_redirects=True,
			headers=headers,
		) as client:
			# Phase 1: Select download server (0-5%)
			self._emit_progress("server_selection", 0.02, "Selecting download server...")
			server, rtt, jitter = await self.select_server(client, client)
			self._emit_progress(
				"server_selection", 0.05,
				f"Download server: {server}",
				{"server": server, "rtt_ms": round(rtt * 1000, 2), "jitter_ms": round(jitter * 1000, 2)}
			)

			# Phase 2: Select upload server (5-10%)
			self._emit_progress("server_selection", 0.07, "Selecting upload server...")
			upload_target, upload_rtt, upload_jitter = await self.select_upload_target(
				client,
				client,
			)
			upload_url = str(upload_target["url"])
			upload_method = str(upload_target.get("method", "POST")).upper()
			self._emit_progress(
				"server_selection", 0.10,
				f"Upload server: {self._target_label(upload_target)}",
				{"server": self._target_label(upload_target), "rtt_ms": round(upload_rtt * 1000, 2)}
			)
			_log.info(
				"SPEEDTEST download_server=%s rtt=%.2fms jitter=%.2fms upload_server=%s upload_rtt=%.2fms upload_jitter=%.2fms",
				server,
				rtt * 1000,
				jitter * 1000,
				self._target_label(upload_target),
				upload_rtt * 1000,
				upload_jitter * 1000,
			)

			# Phase 3: Busy check (10-20%)
			self._emit_progress("busy_check", 0.12, "Checking download path congestion...")
			download_busy = await self.download_busy_check(client, server)
			self._emit_progress("busy_check", 0.16, "Checking upload path congestion...")
			upload_busy = await self.upload_busy_check(client, upload_url, upload_method)

			if download_busy or upload_busy:
				busy_direction = (
					"both directions" if download_busy and upload_busy
					else "download" if download_busy
					else "upload"
				)
				self._emit_progress(
					"busy_check", 0.20,
					f"Network busy ({busy_direction}), aborting",
					{"busy_download": download_busy, "busy_upload": upload_busy}
				)
				_log.warning("SPEEDTEST network busy (%s), skipping measurement", busy_direction)
				return {
					"status": "busy",
					"busy_download": download_busy,
					"busy_upload": upload_busy,
					"server": server,
					"upload_server": self._target_label(upload_target),
					"rtt_ms": round(rtt * 1000, 2),
					"jitter_ms": round(jitter * 1000, 2),
					"upload_rtt_ms": round(upload_rtt * 1000, 2),
					"upload_jitter_ms": round(upload_jitter * 1000, 2),
				}

			# Phase 4: Warmup (20-30%)
			self._emit_progress("warmup", 0.22, "Warming up download and upload connections...")
			await asyncio.gather(
				self.warmup(client, server),
				self.upload_warmup(client, upload_url, upload_method),
			)
			self._emit_progress("warmup", 0.30, "Warmup complete")

			# Phase 5: Test runs (30-100%)
			# Progress distribution: 70% for runs, split evenly among self.runs
			# Each run has download (50%) and upload (50%) phases
			dl_runs: list[float] = []
			ul_runs: list[float] = []
			run_progress_share = 0.70 / self.runs  # Progress per run

			for i in range(self.runs):
				run_base = 0.30 + (i * run_progress_share)

				# Download test
				self._emit_progress(
					"testing", run_base,
					f"Run {i + 1}/{self.runs}: Testing download – {server}",
					{"run": i + 1, "total_runs": self.runs, "phase": "download"}
				)
			dl = await self.download_test(client, server)

			# Upload test
			upload_server_label = self._target_label(upload_target)
			self._emit_progress(
				"testing", run_base + (run_progress_share * 0.5),
				f"Run {i + 1}/{self.runs}: Testing upload – {upload_server_label}",
				{"run": i + 1, "total_runs": self.runs, "phase": "upload"}
			)
			ul = await self.upload_test(client, upload_url, upload_method)

			# Exclude failed runs (0.0) from median calculation to avoid skewing results
			if dl > 0:
				dl_runs.append(dl)
			else:
				_log.warning("Run %d: download test failed, excluding from results", i + 1)

			if ul > 0:
				ul_runs.append(ul)
			else:
				_log.warning("Run %d: upload test failed, excluding from results", i + 1)

				run_end_progress = run_base + run_progress_share
				self._emit_progress(
					"testing", run_end_progress,
					f"Run {i + 1}/{self.runs}: DL {dl:.1f} / UL {ul:.1f} Mbit/s",
					{"run": i + 1, "download_mbit": round(dl, 2), "upload_mbit": round(ul, 2)}
				)
				_log.info(
					"SPEEDTEST run=%d/%d dl=%.2f ul=%.2f Mbit/s",
					i + 1,
					self.runs,
					dl,
					ul,
				)

			# Handle complete test failure
			if not dl_runs and not ul_runs:
				self._emit_progress("error", 1.0, "All runs failed")
				_log.error("SPEEDTEST all runs failed")
				return {
					"status": "error",
					"reason": "All download and upload runs failed",
					"server": server,
					"upload_server": self._target_label(upload_target),
					"rtt_ms": round(rtt * 1000, 2),
					"jitter_ms": round(jitter * 1000, 2),
					"upload_rtt_ms": round(upload_rtt * 1000, 2),
					"upload_jitter_ms": round(upload_jitter * 1000, 2),
				}

			# Final result
			final_dl = round(statistics.median(dl_runs), 2) if dl_runs else None
			final_ul = round(statistics.median(ul_runs), 2) if ul_runs else None
			self._emit_progress(
				"complete", 1.0,
				f"Complete: DL {final_dl} / UL {final_ul} Mbit/s",
				{"download_mbit": final_dl, "upload_mbit": final_ul}
			)

			return {
				"status": "ok",
				"server": server,
				"upload_server": self._target_label(upload_target),
				"rtt_ms": round(rtt * 1000, 2),
				"jitter_ms": round(jitter * 1000, 2),
				"upload_rtt_ms": round(upload_rtt * 1000, 2),
				"upload_jitter_ms": round(upload_jitter * 1000, 2),
				"download_mbit": final_dl,
				"upload_mbit": final_ul,
			}
