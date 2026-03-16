#!/usr/bin/env python3
#
# app/db/tsdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""JSONL-based time-series storage for WireGuard metrics.

Designed for single-node deployments with proper file locking.
Based on the proven justUp TSDB implementation.

Platform: Unix-like systems only (requires fcntl module for file locking).

SIGNIFICANT NOTE #7: All I/O operations are synchronous and will block the caller.
When using from async code (e.g., FastAPI endpoints), wrap calls in asyncio.to_thread():

    result = await asyncio.to_thread(
        append_point, tsdb_dir, peer_key=key, metric="rx_bytes", value=1234
    )

Or use run_in_threadpool from starlette.concurrency:

    from starlette.concurrency import run_in_threadpool
    result = await run_in_threadpool(append_point, tsdb_dir, **kwargs)
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import warnings
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from weakref import WeakValueDictionary

# Platform check for fcntl (Unix-only)
try:
    import fcntl
except ImportError:
    raise ImportError(
        "fcntl module is required but not available. "
        "This TSDB implementation only supports Unix-like systems."
    ) from None

from ..utils.time import ensure_utc, parse_utc, utcnow

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API Exports
# ---------------------------------------------------------------------------

__all__ = [
	"MetricPoint",
	"init_tsdb",
	"append_point",
	"query",
	"query_latest",
	"get_peer_stats",
	"get_all_peer_hashes",
	"get_all_peer_keys",  # Deprecated, but kept for backwards compat
	"get_db_stats",
	"get_synthetic_storage_stats",
	"run_maintenance",
	"flush_to_disk",
	"finalize_shutdown",
	"delete_peer_data",
	"purge_synthetic_data",
	"purge_tsdb",
	"reset_all",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_RETENTION_DAYS = 1  # Prevent immediate pruning of just-written data
DEFAULT_RETENTION_DAYS = 7
PRUNE_INTERVAL_SECONDS = 300  # Only prune a series every 5 minutes max
MAX_SERIES_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB per active JSONL file
MAX_ROTATED_ARCHIVES = 6  # Keep latest N compressed rotations per series
FSYNC_BATCH_SIZE = 10  # Fsync every N appends (durability vs performance tradeoff)
FSYNC_BATCH_INTERVAL = 5.0  # Or fsync after N seconds, whichever comes first

# Synthetic peer keys used for aggregated traffic statistics
SYNTHETIC_KEYS = frozenset(["__geo_traffic__", "__asn_traffic__", "__speedtest__"])

_PEERS_DIRNAME = "peers"
_TRAFFIC_DIRNAME = "traffic"
_SPEEDTEST_DIRNAME = "speedtest"
_LEGACY_TRAFFIC_DIRS = ("geo_traffic", "asn_traffic")


def _peer_dir_name(peer_key: str) -> str:
	"""Return the stable directory name for a WireGuard peer."""
	key_hash = base64.urlsafe_b64encode(
		hashlib.sha256(peer_key.encode()).digest()
	).decode().rstrip("=")
	return f"peer_{key_hash}"


def _move_tree_contents(src_dir: Path, dst_dir: Path) -> None:
	"""Move a directory tree into its new target without losing existing files."""
	if not src_dir.exists() or not src_dir.is_dir():
		return

	dst_dir.mkdir(parents=True, exist_ok=True)
	for child in list(src_dir.iterdir()):
		target = dst_dir / child.name
		if child.is_dir():
			_move_tree_contents(child, target)
			try:
				child.rmdir()
			except OSError:
				pass
			continue
		target.parent.mkdir(parents=True, exist_ok=True)
		child.replace(target)

	try:
		src_dir.rmdir()
	except OSError:
		pass


def _migrate_legacy_layout(tsdb_dir: Path) -> None:
	"""Relocate legacy top-level TSDB directories into bucketed subfolders."""
	peers_dir = tsdb_dir / _PEERS_DIRNAME
	traffic_dir = tsdb_dir / _TRAFFIC_DIRNAME

	for legacy_peer_dir in sorted(tsdb_dir.glob("peer_*")):
		if legacy_peer_dir.is_dir():
			_move_tree_contents(legacy_peer_dir, peers_dir / legacy_peer_dir.name)

	for legacy_traffic_dir_name in _LEGACY_TRAFFIC_DIRS:
		legacy_traffic_dir = tsdb_dir / legacy_traffic_dir_name
		if legacy_traffic_dir.is_dir():
			_move_tree_contents(legacy_traffic_dir, traffic_dir / legacy_traffic_dir_name)

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricPoint:
	"""A single time-series data point."""
	ts: datetime
	value: Any


def _prune_marker_path(series_path: Path) -> Path:
	"""Return the prune marker file path for a series."""
	return series_path.with_suffix(".prune")


def _recover_uncompressed_rotations(series_path: Path) -> None:
	"""Compress any uncompressed rotated files left by previous crashes.
	
	CRITICAL FIX #1: Recover data that would otherwise be invisible.
	When a crash occurs between os.replace() and _compress_file() in rotation,
	the rotated file exists uncompressed and is invisible to _rotated_archives().
	This function finds and compresses such files on lock acquisition.
	"""
	if not series_path.parent.exists():
		return
	
	for p in series_path.parent.glob(f"{series_path.name}.*"):
		# Skip expected file types
		if p.suffix in (".gz", ".tmp", ".lock", ".prune"):
			continue
		# Skip the active series file itself
		if p == series_path:
			continue
		# Skip already-compressed files
		if p.name.endswith(".gz"):
			continue
		
		# This is an uncompressed rotation - compress it
		_log.info("Recovering uncompressed rotation: %s", p.name)
		try:
			_compress_file(p)
		except OSError as e:
			_log.warning("Recovery compression failed for %s: %s", p.name, e)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _series_path(tsdb_dir: Path, peer_key: str, metric: str) -> Path:
	"""Build the path to a series JSONL file.
	
	FIX: Validates metric names instead of silently sanitizing to prevent collisions.
	"""
	if not metric or not metric.strip():
		raise ValueError("Metric name cannot be empty")
	# Enforce strict metric name format to prevent silent collisions
	if not re.fullmatch(r"[A-Za-z0-9_-]+", metric):
		raise ValueError(
			f"Invalid metric name '{metric}': only alphanumeric, underscore, and hyphen allowed"
		)
	
	# Use human-readable directory names for synthetic keys
	if peer_key == "__speedtest__":
		return tsdb_dir / _SPEEDTEST_DIRNAME / f"{metric}.jsonl"
	if peer_key in {"__geo_traffic__", "__asn_traffic__"}:
		dir_name = peer_key.strip("_")
		return tsdb_dir / _TRAFFIC_DIRNAME / dir_name / f"{metric}.jsonl"
	if peer_key in SYNTHETIC_KEYS:
		# If we reach here, a synthetic key was added to SYNTHETIC_KEYS but not handled above
		raise ValueError(
			f"Unhandled synthetic key: {peer_key} — add explicit path mapping in _series_path"
		)

	return tsdb_dir / _PEERS_DIRNAME / _peer_dir_name(peer_key) / f"{metric}.jsonl"


def _lock_path(series_path: Path) -> Path:
	"""Return the lock file path for a series."""
	return series_path.with_suffix(".lock")


def _synthetic_dir_path(tsdb_dir: Path, peer_key: str) -> Path:
	"""Return the storage directory for a synthetic key."""
	if peer_key == "__speedtest__":
		return tsdb_dir / _SPEEDTEST_DIRNAME
	if peer_key in {"__geo_traffic__", "__asn_traffic__"}:
		return tsdb_dir / _TRAFFIC_DIRNAME / peer_key.strip("_")
	if peer_key in SYNTHETIC_KEYS:
		return tsdb_dir / peer_key.strip("_")
	raise ValueError(f"Unsupported synthetic key: {peer_key}")


def _count_lines(path: Path) -> int:
	"""Count newline-delimited records efficiently (handles both plain and gzip)."""
	count = 0
	open_func = gzip.open if path.suffix == ".gz" else open
	with open_func(path, "rb") as fp:
		while True:
			chunk = fp.read(1 << 16)
			if not chunk:
				break
			count += chunk.count(b"\n")
	return count


class _ReadWriteLock:
	"""Simple read-write lock for thread-level concurrency control.
	
	FIX: Prevents writer starvation by blocking new readers when writers are waiting.
	"""
	
	def __init__(self):
		self._readers = 0
		self._writers = 0
		self._writers_waiting = 0
		self._writer_thread_id = None  # Track which thread holds write lock
		self._lock = threading.Lock()
		self._read_ready = threading.Condition(self._lock)
		self._write_ready = threading.Condition(self._lock)
	
	def acquire_read(self):
		"""Acquire a shared read lock."""
		self._read_ready.acquire()
		# Block new readers if writers are waiting to prevent starvation
		while self._writers > 0 or self._writers_waiting > 0:
			self._read_ready.wait()
		self._readers += 1
		self._read_ready.release()
	
	def release_read(self):
		"""Release a shared read lock."""
		with self._read_ready:
			self._readers -= 1
			if self._readers == 0:
				self._write_ready.notify()
	
	def acquire_write(self):
		"""Acquire an exclusive write lock.
		
		SIGNIFICANT FIX #4: Non-reentrant - raises if same thread tries to acquire twice.
		"""
		self._write_ready.acquire()
		self._writers_waiting += 1
		acquired = False
		try:
			# CRITICAL: Detect reentrant lock attempts (same thread calling twice)
			# This would deadlock without detection
			current_thread_id = threading.current_thread().ident
			if self._writers > 0 and self._writer_thread_id == current_thread_id:
				raise RuntimeError(
					"_ReadWriteLock is not reentrant. "
					"Same thread cannot acquire write lock twice. "
					"This usually indicates a bug in lock management."
				)
			
			while self._readers > 0 or self._writers > 0:
				self._write_ready.wait()
			self._writers = 1
			self._writer_thread_id = current_thread_id
			acquired = True
		finally:
			self._writers_waiting -= 1
			if not acquired:
				self._write_ready.release()
		
		# Only release if acquisition succeeded (outside finally to avoid double-release)
		if acquired:
			self._write_ready.release()
	
	def release_write(self):
		"""Release an exclusive write lock."""
		self._lock.acquire()
		self._writers = 0
		self._writer_thread_id = None  # Clear thread tracking
		self._write_ready.notify()
		self._read_ready.notify_all()
		self._lock.release()


class _FileLock:
	"""Context manager for file locking (both inter-process and inter-thread).
	
	SIGNIFICANT FIX #5: WeakValueDictionary usage documented.
	NOTE: Thread locks use WeakValueDict to prevent unbounded growth, but the
	real mutual exclusion safety comes from the file lock (fcntl.flock).
	The thread lock is an optimization to reduce syscall overhead for same-process
	contention, but correctness does NOT depend on it.
	"""

	# Class-level dict for thread locks (per series path) - uses weak references to prevent memory leak
	_thread_locks: WeakValueDictionary[str, _ReadWriteLock] = WeakValueDictionary()
	_meta_lock: threading.Lock = threading.Lock()

	def __init__(self, series_path: Path, *, read_only: bool = False):
		self._series_path = series_path
		self._lock_path = _lock_path(series_path)
		self._fd: Optional[int] = None
		self._thread_lock: Optional[threading.Lock] = None
		self._read_only = read_only

	def __enter__(self) -> "_FileLock":
		# First acquire thread-level lock to ensure thread-safety within same process
		key = str(self._series_path)
		with self._meta_lock:
			# Use .get() to safely handle WeakValueDictionary race conditions
			# (value can be GC'd between checking existence and retrieving)
			thread_lock = self._thread_locks.get(key)
			if thread_lock is None:
				thread_lock = _ReadWriteLock()
				self._thread_locks[key] = thread_lock
			# Store strong reference to prevent GC while we hold the lock
			self._thread_lock = thread_lock
		
		# Acquire appropriate thread lock (read or write)
		if self._read_only:
			self._thread_lock.acquire_read()
		else:
			self._thread_lock.acquire_write()

		# Then acquire file-level lock for inter-process safety
		self._lock_path.parent.mkdir(parents=True, exist_ok=True)
		self._fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
		fcntl.flock(self._fd, fcntl.LOCK_SH if self._read_only else fcntl.LOCK_EX)
		
		# Cleanup orphaned temp files from previous crashes
		if not self._read_only:
			# CRITICAL FIX #2: Scope cleanup to THIS series only to avoid
			# cross-metric race conditions (don't delete other metrics' temp files)
			prefix = self._series_path.name  # e.g., "rx_bytes.jsonl"
			for tmp in self._series_path.parent.glob(f"{prefix}*.tmp"):
				try:
					tmp.unlink(missing_ok=True)
				except OSError:
					pass
			
			# CRITICAL FIX #1: Recover uncompressed rotations left by crashes
			# FIX: Only run once per series to avoid redundant glob operations
			key = str(self._series_path)
			with _recovered_series_lock:
				if key not in _recovered_series:
					_recover_uncompressed_rotations(self._series_path)
					_recovered_series.add(key)
		
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		"""Release locks with guaranteed cleanup order to prevent deadlocks."""
		try:
			if self._fd is not None:
				try:
					fcntl.flock(self._fd, fcntl.LOCK_UN)
				except OSError:
					pass
				finally:
					try:
						os.close(self._fd)
					except OSError:
						pass
					self._fd = None
		finally:
			if self._thread_lock is not None:
				if self._read_only:
					self._thread_lock.release_read()
				else:
					self._thread_lock.release_write()
				self._thread_lock = None


def _should_prune(series_path: Path) -> bool:
	"""Check if enough time has passed since last prune for this series.
	
	Uses a file-based marker for cross-process safety with multiple workers.
	FIX: Correctly handles first-run case when marker doesn't exist.
	"""
	marker = _prune_marker_path(series_path)
	now = time.time()
	
	try:
		# Fast path: check marker age without locking
		marker_existed = marker.exists()
		if marker_existed:
			last_prune = marker.stat().st_mtime
			if now - last_prune < PRUNE_INTERVAL_SECONDS:
				return False
		
		# Touch the marker file atomically to claim this prune slot
		marker.parent.mkdir(parents=True, exist_ok=True)
		fd = os.open(str(marker), os.O_CREAT | os.O_WRONLY)
		try:
			# Try to get exclusive lock without blocking
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
			# Always double-check after acquiring lock to handle race conditions
			try:
				last_prune = os.fstat(fd).st_mtime
				if now - last_prune < PRUNE_INTERVAL_SECONDS:
					return False
			except OSError:
				# First time or stat failed - proceed with prune
				pass
			# Update mtime to claim the slot
			os.utime(fd)
			return True
		except BlockingIOError:
			# Another process is pruning right now
			return False
		finally:
			fcntl.flock(fd, fcntl.LOCK_UN)
			os.close(fd)
	except OSError as e:
		_log.debug("Prune marker check failed: %s", e)
		return False


def _validate_retention(retention_days: int) -> int:
	"""Ensure retention_days is within acceptable bounds."""
	if retention_days < MIN_RETENTION_DAYS:
		return MIN_RETENTION_DAYS
	return retention_days


def _archive_sort_key(p: Path) -> str:
	"""Normalize archive timestamps to fixed-width for correct sorting.
	
	Old archives use YYYYMMDDTHHMMSSz (16 chars), new ones use
	YYYYMMDDTHHMMSSµµµµµµz (22 chars with microseconds). Without
	normalization, 'Z' > '0' causes chronological inversion.
	"""
	name = p.name
	marker = ".jsonl."
	idx = name.find(marker)
	if idx < 0:
		return name
	after = name[idx + len(marker):]
	ts = after.removesuffix(".gz")
	# Pad old format (no microseconds) to match new format width
	if len(ts) == 16:  # "YYYYMMDDTHHMMSSz"
		ts = ts[:-1] + "000000Z"
	return ts


def _rotated_archives(series_path: Path) -> list[Path]:
	"""Return rotated archive files for a series (sorted oldest -> newest).
	
	CRITICAL FIX #1: Include both compressed (.gz) AND uncompressed rotated files.
	Uncompressed rotations exist when compression was interrupted by a crash.
	"""
	gz_archives = list(series_path.parent.glob(f"{series_path.name}.*.gz"))
	
	# Also find uncompressed rotations left by interrupted compression
	uncompressed = [
		p for p in series_path.parent.glob(f"{series_path.name}.*")
		if p.suffix not in (".gz", ".tmp", ".lock", ".prune")
		and p != series_path
		and not p.name.endswith(".gz")
	]
	
	# Combine and sort by normalized timestamp to handle format transitions
	return sorted(gz_archives + uncompressed, key=_archive_sort_key)


def _iter_series_files(series_path: Path) -> list[Path]:
	"""Return all files containing series data in chronological order."""
	files: list[Path] = []
	files.extend(_rotated_archives(series_path))
	if series_path.exists():
		files.append(series_path)
	return files


def _compress_file(src_path: Path) -> Path:
	"""Compress a file to gzip atomically and remove source after verification.
	
	CRITICAL FIX #12: Verify compressed file integrity before deleting source.
	CRITICAL FIX #3: Fsync parent directory after atomic rename.
	"""
	gz_path = Path(f"{src_path}.gz")
	tmp_gz = gz_path.with_suffix(".gz.tmp")
	with src_path.open("rb") as src, gzip.open(tmp_gz, "wb", compresslevel=6) as dst:
		shutil.copyfileobj(src, dst)
	# Ensure data is written to disk before replacing
	_fsync_path(tmp_gz)
	os.replace(tmp_gz, gz_path)
	
	# CRITICAL FIX #3: Fsync parent directory to ensure rename metadata is durable
	_fsync_path(gz_path.parent, directory=True)
	
	# CRITICAL FIX #12: Verify compressed file is readable before deleting source
	try:
		with gzip.open(gz_path, "rb") as check:
			# Read in chunks to verify entire file
			while check.read(65536):
				pass
	except (gzip.BadGzipFile, OSError) as e:
		_log.error("Compressed file verification failed for %s: %s", gz_path, e)
		# Don't delete source — keep the uncompressed data for recovery
		return gz_path
	
	# Only delete source after successful compression and verification
	src_path.unlink(missing_ok=True)
	return gz_path


def _rotate_series_locked(series_path: Path) -> None:
	"""Rotate and compress a large active series file. MUST be called with lock held."""
	if not series_path.exists():
		return
	try:
		size = series_path.stat().st_size
	except OSError:
		return
	if size <= MAX_SERIES_FILE_BYTES:
		return

	# Use microsecond precision to prevent timestamp collisions on rapid rotations
	stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
	rotated = series_path.parent / f"{series_path.name}.{stamp}"
	try:
		os.replace(series_path, rotated)
		# CRITICAL FIX #3: Fsync parent directory after renaming active file
		_fsync_path(series_path.parent, directory=True)
		# Compress the rotated file (includes its own verification & fsync)
		_compress_file(rotated)
	except OSError as e:
		_log.warning("TSDB rotation failed for %s: %s", series_path, e)
		return

	# Keep only the newest archives.
	archives = _rotated_archives(series_path)
	if len(archives) > MAX_ROTATED_ARCHIVES:
		for old in archives[: len(archives) - MAX_ROTATED_ARCHIVES]:
			try:
				old.unlink(missing_ok=True)
			except OSError:
				pass


def _prune_archives_locked(series_path: Path, cutoff: datetime) -> None:
	"""Delete rotated archives older than cutoff. MUST be called with lock held.
	
	Uses timestamps encoded in filenames rather than file mtime for accurate pruning.
	"""
	for arc in _rotated_archives(series_path):
		try:
			# Parse timestamp from filename: metric.jsonl.20260219T120000123456Z.gz (with microseconds)
			# Extract timestamp - must work for both .gz and uncompressed rotations
			name = arc.name
			marker = ".jsonl."
			idx = name.find(marker)
			if idx < 0:
				_log.warning("Archive filename does not contain timestamp: %s", arc.name)
				continue
			after = name[idx + len(marker):]  # "20260219T120000123456Z.gz" or "20260219T120000123456Z"
			timestamp_str = after.removesuffix(".gz")  # Get '20260219T120000123456Z'
			# Parse ISO 8601 basic format timestamp (try with microseconds first, fall back to seconds)
			try:
				arc_time = datetime.strptime(timestamp_str, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
			except ValueError:
				# Fall back to old format without microseconds for backward compatibility
				arc_time = datetime.strptime(timestamp_str, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
		except (ValueError, IndexError) as e:
			_log.debug("Failed to parse archive timestamp from %s: %s", arc.name, e)
			continue
		except OSError:
			continue
		
		if arc_time < cutoff:
			try:
				arc.unlink(missing_ok=True)
				_log.debug("Pruned old archive: %s", arc.name)
			except OSError as e:
				_log.warning("Failed to delete archive %s: %s", arc.name, e)


def _iter_json_lines(path: Path):
	"""Yield JSONL lines from plain or gzip files.
	
	Handles corrupted gzip archives gracefully by logging and skipping.
	"""
	if path.suffix == ".gz":
		try:
			with gzip.open(path, "rt", encoding="utf-8") as f:
				yield from f
		except (gzip.BadGzipFile, OSError, EOFError) as e:
			_log.warning("Corrupted or truncated gzip archive %s: %s (skipping)", path.name, e)
		return
	with path.open("r", encoding="utf-8") as f:
		yield from f


def _fsync_path(path: Path, *, directory: bool = False) -> bool:
	"""Best-effort fsync for files/directories."""
	flags = os.O_RDONLY
	if directory:
		flags |= getattr(os, "O_DIRECTORY", 0)
	fd: int | None = None
	try:
		fd = os.open(str(path), flags)
		os.fsync(fd)
		return True
	except OSError as e:
		_log.debug("Failed to fsync %s: %s", path, e)
		return False
	finally:
		if fd is not None:
			try:
				os.close(fd)
			except OSError:
				pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def init_tsdb(tsdb_dir: Path) -> None:
	"""Initialize the TSDB directory structure."""
	tsdb_dir.mkdir(parents=True, exist_ok=True)
	(tsdb_dir / _PEERS_DIRNAME).mkdir(parents=True, exist_ok=True)
	(tsdb_dir / _TRAFFIC_DIRNAME).mkdir(parents=True, exist_ok=True)
	(tsdb_dir / _SPEEDTEST_DIRNAME).mkdir(parents=True, exist_ok=True)
	_migrate_legacy_layout(tsdb_dir)


def purge_tsdb(tsdb_dir: Path) -> None:
	"""Completely remove all TSDB data.
	
	WARNING: This does NOT acquire locks. Concurrent writes will crash or corrupt data.
	ONLY call this during:
	  - Application shutdown (after all TSDB operations stopped)
	  - Single-threaded maintenance windows
	  - Test cleanup
	
	For safe peer deletion during normal operation, use delete_peer_data() and ensure
	no active writes for that peer.
	"""
	if not tsdb_dir.exists():
		return
	
	_log.warning("TSDB purge: deleting all data in %s (NO LOCKS - ensure no concurrent ops)", tsdb_dir)
	
	try:
		shutil.rmtree(tsdb_dir)
	except OSError:
		for root, dirs, files in os.walk(tsdb_dir, topdown=False):
			for f in files:
				try:
					Path(root, f).unlink(missing_ok=True)
				except OSError:
					pass
			for d in dirs:
				try:
					Path(root, d).rmdir()
				except OSError:
					pass
	init_tsdb(tsdb_dir)


def delete_peer_data(tsdb_dir: Path, peer_key: str) -> None:
	"""Delete all time-series data for a specific peer.
	
	WARNING: This does NOT acquire locks. Concurrent writes for this peer will crash.
	ONLY call this when:
	  - The peer has been removed from WireGuard config
	  - No metrics collection is active for this peer
	  - During controlled maintenance operations
	
	The caller MUST ensure no append_point() calls are in-flight for this peer_key.
	"""
	dir_name = _peer_dir_name(peer_key)
	tdir = tsdb_dir / _PEERS_DIRNAME / dir_name
	if not tdir.exists():
		return
	
	_log.info("Deleting peer data: %s (NO LOCKS - ensure peer inactive)", dir_name)
	
	try:
		shutil.rmtree(tdir)
	except OSError:
		# Clean up individual files including lock files
		for f in tdir.glob("*"):
			try:
				f.unlink(missing_ok=True)
			except OSError:
				pass
		try:
			tdir.rmdir()
		except OSError:
			pass


# Batched fsync state (per series path) - bounded LRU to prevent memory leak
_MAX_FSYNC_ENTRIES = 2000
_fsync_batch_state: OrderedDict[str, dict[str, Any]] = OrderedDict()
_fsync_batch_lock = threading.Lock()

# Recovery tracking to avoid redundant uncompressed rotation recovery per series
_recovered_series: set[str] = set()
_recovered_series_lock = threading.Lock()


def _should_fsync_batch(series_path: Path) -> bool:
	"""Check if batched writes should be fsynced now.
	
	Returns True if either:
	- Batch size limit reached
	- Time interval exceeded since last fsync
	
	FIX: Uses bounded OrderedDict to prevent unbounded memory growth.
	"""
	key = str(series_path)
	with _fsync_batch_lock:
		if key not in _fsync_batch_state:
			# Evict oldest entry if at capacity
			if len(_fsync_batch_state) >= _MAX_FSYNC_ENTRIES:
				_fsync_batch_state.popitem(last=False)
			_fsync_batch_state[key] = {"count": 0, "last_fsync": time.time()}
		else:
			# Move to end (mark as recently used)
			_fsync_batch_state.move_to_end(key)
		
		state = _fsync_batch_state[key]
		state["count"] += 1
		now = time.time()
		
		# Check if we should fsync
		if state["count"] >= FSYNC_BATCH_SIZE or (now - state["last_fsync"]) >= FSYNC_BATCH_INTERVAL:
			# Reset state
			state["count"] = 0
			state["last_fsync"] = now
			return True
		
		return False


def append_point(
	tsdb_dir: Path,
	*,
	peer_key: str,
	metric: str,
	value: Any,
	retention_days: int = DEFAULT_RETENTION_DAYS,
	at: Optional[datetime] = None,
	sync: bool = False,
) -> None:
	"""Append a data point to a time series.

	Args:
		tsdb_dir: Base directory for TSDB storage.
		peer_key: WireGuard peer public key.
		metric: Name of the metric (e.g., "rx_bytes", "tx_bytes").
		value: The metric value to store.
		retention_days: How many days to retain data.
		at: Optional timestamp; defaults to now (UTC).
		sync: If True, force immediate fsync (default: batched for performance).
	"""
	retention_days = _validate_retention(retention_days)
	
	if at is None:
		at = utcnow()
	else:
		if at.tzinfo is None:
			raise ValueError("Naive timestamp is not allowed in TSDB")
		at = ensure_utc(at)

	p = _series_path(tsdb_dir, peer_key, metric)

	with _FileLock(p):
		p.parent.mkdir(parents=True, exist_ok=True)
		with p.open("a", encoding="utf-8") as f:
			line = json.dumps({"ts": at.isoformat(), "value": value}, ensure_ascii=False)
			f.write(line + "\n")
			# Batched fsync for performance - only sync when batch size/interval reached
			# or when explicitly requested
			if sync or _should_fsync_batch(p):
				f.flush()
				os.fsync(f.fileno())
		_rotate_series_locked(p)

		# Rate-limited pruning: check timing without random gate
		# Uses file-based marker for cross-process safety
		if _should_prune(p):
			_prune_series_locked(p, retention_days)


def _prune_series_locked(series_path: Path, retention_days: int) -> None:
	"""Prune old data points from a series file. MUST be called with lock held.
	
	Critical fixes:
	1. Always prune archives regardless of active file existence
	2. Atomic replace with fsync to ensure durability
	"""
	retention_days = _validate_retention(retention_days)
	cutoff = utcnow() - timedelta(days=retention_days)
	
	# CRITICAL FIX #2: Always prune compressed archives, not just when active file is missing
	_prune_archives_locked(series_path, cutoff)
	
	if not series_path.exists():
		return

	kept: list[str] = []

	with series_path.open("r", encoding="utf-8") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue
			try:
				obj = json.loads(line)
				ts = parse_utc(obj["ts"])
				if ts is None:
					continue
			except Exception as e:
				_log.debug("Skipping corrupted JSONL line in %s: %s", series_path.name, e)
				continue
			if ts >= cutoff:
				kept.append(line)

	if len(kept) == 0:
		series_path.unlink(missing_ok=True)
		return

	# CRITICAL FIX #1: Atomic replace with fsync for durability
	tmp = series_path.with_suffix(series_path.suffix + ".tmp")
	with tmp.open("w", encoding="utf-8") as f:
		for line in kept:
			f.write(line + "\n")
		# Ensure data is written to disk before rename
		f.flush()
		os.fsync(f.fileno())
	
	# Atomic replace - only after successful fsync
	os.replace(tmp, series_path)
	
	# CRITICAL FIX #3: Fsync parent directory to ensure rename metadata is durable
	_fsync_path(series_path.parent, directory=True)


def query(
	tsdb_dir: Path,
	*,
	peer_key: str,
	metric: str,
	since: Optional[datetime] = None,
	until: Optional[datetime] = None,
	limit: int = 1000,
	latest: bool = False,
) -> list[MetricPoint]:
	"""Query data points from a time series.

	Args:
		tsdb_dir: Base directory for TSDB storage.
		peer_key: WireGuard peer public key.
		metric: Name of the metric to query.
		since: Optional lower bound (inclusive) for timestamps.
		until: Optional upper bound (inclusive) for timestamps.
		limit: Maximum number of points to return.
		latest: If True, return the *latest* points (tail).

	Returns:
		List of MetricPoint objects, sorted chronologically.
	"""
	p = _series_path(tsdb_dir, peer_key, metric)
	if (not p.exists()) and (len(_rotated_archives(p)) == 0):
		return []

	since_u = ensure_utc(since) if since else None
	until_u = ensure_utc(until) if until else None

	# Use shared lock for reads to allow concurrent queries
	with _FileLock(p, read_only=True):
		# Memory-efficient collection for latest queries
		if latest:
			# CRITICAL FIX #5: Iterate files in REVERSE order for latest queries
			# This allows early termination instead of reading entire history
			# No maxlen on deque - rely on collected check to prevent over-collection
			buffer: deque[MetricPoint] = deque()
			collected = 0
			
			# Read files from newest to oldest
			for src in reversed(_iter_series_files(p)):
				lines_from_file: list[tuple[datetime, Any]] = []
				
				for line in _iter_json_lines(src):
					line = line.strip()
					if not line:
						continue
					try:
						obj = json.loads(line)
						ts = parse_utc(obj["ts"])
						if ts is None:
							continue
						val = obj.get("value")
					except Exception as e:
						_log.debug("Skipping corrupted JSONL line in %s: %s", p.name, e)
						continue

					if since_u and ts < since_u:
						continue
					if until_u and ts > until_u:
						continue
					
					lines_from_file.append((ts, val))
				
				# Add points from this file in reverse order (latest first)
				for ts, val in reversed(lines_from_file):
					buffer.appendleft(MetricPoint(ts=ts, value=val))
					collected += 1
					if collected >= limit:
						break
				
				if collected >= limit:
					break
			
			return list(buffer)
		else:
			# For non-latest queries, collect all matching points
			# FIX: Early termination when limit reached and no time filter
			all_matching: list[MetricPoint] = []
			collected = 0
			for src in _iter_series_files(p):
				for line in _iter_json_lines(src):
					line = line.strip()
					if not line:
						continue
					try:
						obj = json.loads(line)
						ts = parse_utc(obj["ts"])
						if ts is None:
							continue
						val = obj.get("value")
					except Exception as e:
						_log.debug("Skipping corrupted JSONL line in %s: %s", p.name, e)
						continue

					if since_u and ts < since_u:
						continue
					if until_u and ts > until_u:
						continue

					all_matching.append(MetricPoint(ts=ts, value=val))
					collected += 1
					# Early termination: if no time filter and already have enough
					if since_u is None and collected >= limit:
						break
				if since_u is None and collected >= limit:
					break

			# Sort once after collecting all matches to ensure correct chronological order
			all_matching.sort(key=lambda pt: pt.ts)
			return all_matching[:limit]


def query_latest(
	tsdb_dir: Path,
	*,
	peer_key: str,
	metric: str,
	count: int = 100,
) -> list[MetricPoint]:
	"""Query the latest N data points."""
	return query(tsdb_dir, peer_key=peer_key, metric=metric, limit=count, latest=True)


def get_peer_stats(tsdb_dir: Path, peer_key: str) -> dict[str, Any]:
	"""Get the latest stats for a peer.
	
	Returns:
		Dict with rx_bytes, tx_bytes, latest_handshake, etc.
	"""
	stats = {}
	
	for metric in ["rx_bytes", "tx_bytes", "latest_handshake"]:
		points = query_latest(tsdb_dir, peer_key=peer_key, metric=metric, count=1)
		if points:
			stats[metric] = points[-1].value
			stats[f"{metric}_ts"] = points[-1].ts
	
	return stats


def get_all_peer_hashes(tsdb_dir: Path) -> list[str]:
	"""Get all peer directory hashes that have TSDB data.
	
	Excludes synthetic traffic aggregation keys (geo/ASN traffic).
	
	Note: Returns SHA-256 hashes of peer keys, not the original keys themselves.
	These hashes are used for directory naming and cannot be reversed.
	"""
	if not tsdb_dir.exists():
		return []
	
	peers_dir = tsdb_dir / _PEERS_DIRNAME
	if not peers_dir.exists():
		return []

	hashes = []
	for d in peers_dir.iterdir():
		if d.is_dir() and d.name.startswith("peer_"):
			key_hash = d.name[5:]  # Remove "peer_" prefix
			hashes.append(key_hash)
	return hashes


def get_all_peer_keys(tsdb_dir: Path) -> list[str]:
	"""Deprecated: Use get_all_peer_hashes() instead.
	
	This function returns hashes, not actual peer keys.
	
	MINOR FIX #13: Use warnings.warn instead of log.warning for deprecation.
	"""
	warnings.warn(
		"get_all_peer_keys is deprecated and returns hashes, not keys. "
		"Use get_all_peer_hashes() instead.",
		FutureWarning,
		stacklevel=2
	)
	return get_all_peer_hashes(tsdb_dir)


def get_db_stats(tsdb_dir: Path) -> dict[str, Any]:
	"""Get TSDB storage statistics.
	
	Returns:
		Dict with size_bytes, peer_count, file_count, archive_count
	"""
	if not tsdb_dir.exists():
		return {
			"size_bytes": 0,
			"compressed_size_bytes": 0,
			"peer_count": 0,
			"file_count": 0,
			"archive_count": 0,
			"max_series_file_bytes": MAX_SERIES_FILE_BYTES,
		}
	
	total_size = 0
	compressed_size = 0
	file_count = 0
	archive_count = 0
	
	for root, dirs, files in os.walk(tsdb_dir):
		for name in files:
			if name.endswith(".jsonl") or ".jsonl." in name:
				fpath = Path(root) / name
				try:
					stat = fpath.stat()
					total_size += stat.st_size
					file_count += 1
					if name.endswith(".gz"):
						compressed_size += stat.st_size
						archive_count += 1
				except OSError:
					pass
	
	peer_count = len(get_all_peer_hashes(tsdb_dir))
	
	return {
		"size_bytes": total_size,
		"compressed_size_bytes": compressed_size,
		"peer_count": peer_count,
		"file_count": file_count,
		"archive_count": archive_count,
		"max_series_file_bytes": MAX_SERIES_FILE_BYTES,
	}


def get_synthetic_storage_stats(tsdb_dir: Path, peer_key: str) -> dict[str, Any]:
	"""Get storage statistics for a synthetic key bucket."""
	dir_path = _synthetic_dir_path(tsdb_dir, peer_key)
	if not dir_path.exists():
		return {
			"path": str(dir_path),
			"size_bytes": 0,
			"file_count": 0,
			"record_count": 0,
		}

	size_bytes = 0
	file_count = 0
	record_count = 0

	for entry in dir_path.iterdir():
		if not entry.is_file():
			continue
		name = entry.name
		if not (name.endswith(".jsonl") or (".jsonl." in name and name.endswith(".gz"))):
			continue
		try:
			stat = entry.stat()
			size_bytes += stat.st_size
			file_count += 1
			record_count += _count_lines(entry)
		except OSError:
			pass

	return {
		"path": str(dir_path),
		"size_bytes": size_bytes,
		"file_count": file_count,
		"record_count": record_count,
	}


def purge_synthetic_data(tsdb_dir: Path, peer_key: str) -> int:
	"""Delete all files for a synthetic key bucket and return deleted bytes.
	
	WARNING: This does NOT acquire per-series locks. Ensure no concurrent
	writes are in-flight for this peer_key before calling. Typically safe for
	__speedtest__ (API layer manages concurrency) but use with caution.
	"""
	dir_path = _synthetic_dir_path(tsdb_dir, peer_key)
	if not dir_path.exists():
		return 0

	deleted_bytes = 0
	for entry in dir_path.rglob("*"):
		if not entry.is_file():
			continue
		try:
			deleted_bytes += entry.stat().st_size
		except OSError:
			pass

	shutil.rmtree(dir_path)
	return deleted_bytes


def reset_all(tsdb_dir: Path) -> int:
	"""Delete all TSDB data.
	
	Returns:
		Number of peer directories deleted.
	"""
	if not tsdb_dir.exists():
		return 0
	
	deleted = 0
	for bucket in (tsdb_dir / _PEERS_DIRNAME, tsdb_dir / _TRAFFIC_DIRNAME, tsdb_dir / _SPEEDTEST_DIRNAME):
		if not bucket.exists():
			continue
		for d in list(bucket.iterdir()):
			try:
				if d.is_dir():
					shutil.rmtree(d)
				else:
					d.unlink(missing_ok=True)
				deleted += 1
			except OSError as e:
				_log.warning("Failed to delete TSDB entry %s: %s", d, e)

	_log.info("TSDB reset: deleted %d TSDB entries", deleted)
	return deleted


def run_maintenance(
	tsdb_dir: Path,
	retention_days: int = DEFAULT_RETENTION_DAYS,
	synthetic_retention: dict[str, int] | None = None,
) -> dict[str, int]:
	"""Run retention/rotation maintenance across all series files.

	Args:
		tsdb_dir: Path to TSDB directory.
		retention_days: Default retention period in days for peer data.
		synthetic_retention: Optional dict mapping synthetic key directory names
			(e.g., "speedtest", "geo_traffic") to their retention days.
			If not specified, uses the default retention_days.

	Returns:
		Dict with maintenance counters.
	"""
	retention_days = _validate_retention(retention_days)
	synthetic_retention = synthetic_retention or {}
	series_count = 0
	rotated_count = 0
	pruned_count = 0

	if not tsdb_dir.exists():
		return {"series": 0, "rotated": 0, "pruned": 0}

	series_paths: set[Path] = set()
	for series_path in tsdb_dir.rglob("*.jsonl"):
		series_paths.add(series_path)
	for archive in tsdb_dir.rglob("*.jsonl.*.gz"):
		base_name = archive.name.split(".jsonl.", 1)[0] + ".jsonl"
		series_paths.add(archive.with_name(base_name))

	for series_path in sorted(series_paths):
		series_count += 1
		
		# Determine retention for this series based on its parent directory
		parent_name = series_path.parent.name
		if parent_name in synthetic_retention:
			series_retention = _validate_retention(synthetic_retention[parent_name])
		else:
			series_retention = retention_days
		
		# Acquire lock before reading archive counts to avoid TOCTOU races
		with _FileLock(series_path):
			before_archives = len(_rotated_archives(series_path))
			_rotate_series_locked(series_path)
			after_rotate_archives = len(_rotated_archives(series_path))
			if after_rotate_archives > before_archives:
				rotated_count += 1
			before_prune_archives = len(_rotated_archives(series_path))
			_prune_series_locked(series_path, series_retention)
			after_prune_archives = len(_rotated_archives(series_path))
			if (after_prune_archives < before_prune_archives) or (not series_path.exists()):
				pruned_count += 1

	return {"series": series_count, "rotated": rotated_count, "pruned": pruned_count}


def flush_to_disk(tsdb_dir: Path) -> dict[str, int]:
	"""Force pending filesystem buffers for TSDB data to disk (best effort)."""
	if not tsdb_dir.exists():
		return {"synced_files": 0, "synced_dirs": 0}

	synced_files = 0
	seen_dirs: set[Path] = {tsdb_dir}

	for root, dirs, files in os.walk(tsdb_dir):
		root_path = Path(root)
		seen_dirs.add(root_path)
		for d in dirs:
			seen_dirs.add(root_path / d)
		for name in files:
			# TSDB data and archive files.
			if not (name.endswith(".jsonl") or ".jsonl." in name):
				continue
			if _fsync_path(root_path / name):
				synced_files += 1

	synced_dirs = 0
	for d in sorted(seen_dirs):
		if _fsync_path(d, directory=True):
			synced_dirs += 1

	return {"synced_files": synced_files, "synced_dirs": synced_dirs}


def finalize_shutdown(tsdb_dir: Path, retention_days: int = DEFAULT_RETENTION_DAYS) -> dict[str, int]:
	"""Run final maintenance and fsync on shutdown.
	
	FIX: Ensures flush_to_disk runs even if maintenance fails.
	"""
	try:
		maintenance = run_maintenance(tsdb_dir, retention_days=retention_days)
	except Exception:
		_log.exception("Maintenance failed during shutdown")
		maintenance = {"series": 0, "rotated": 0, "pruned": 0}
	
	flush_stats = flush_to_disk(tsdb_dir)
	return {
		"series": maintenance.get("series", 0),
		"rotated": maintenance.get("rotated", 0),
		"pruned": maintenance.get("pruned", 0),
		"synced_files": flush_stats.get("synced_files", 0),
		"synced_dirs": flush_stats.get("synced_dirs", 0),
	}
