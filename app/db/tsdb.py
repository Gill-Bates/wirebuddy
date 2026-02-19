#!/usr/bin/env python3
#
# app/db/tsdb.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""JSONL-based time-series storage for WireGuard metrics.

Designed for single-node deployments with proper file locking.
Based on the proven justUp TSDB implementation.
"""

from __future__ import annotations

import base64
import fcntl
import gzip
import hashlib
import json
import logging
import os
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..utils.time import ensure_utc, parse_utc, utcnow

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_RETENTION_DAYS = 1
DEFAULT_RETENTION_DAYS = 365
PRUNE_INTERVAL_SECONDS = 300  # Only prune a series every 5 minutes max
MAX_SERIES_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB per active JSONL file
MAX_ROTATED_ARCHIVES = 6  # Keep latest N compressed rotations per series

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _series_path(tsdb_dir: Path, peer_key: str, metric: str) -> Path:
	"""Build the path to a series JSONL file."""
	# Use full SHA-256 hash to ensure zero collision risk
	# WireGuard keys are base64, but we want predictable, collision-resistant names
	key_hash = base64.urlsafe_b64encode(
		hashlib.sha256(peer_key.encode()).digest()
	).decode().rstrip("=")  # Remove padding for cleaner filenames
	safe_metric = "".join(c for c in metric if c.isalnum() or c in ("_", "-"))
	return tsdb_dir / f"peer_{key_hash}" / f"{safe_metric}.jsonl"


def _lock_path(series_path: Path) -> Path:
	"""Return the lock file path for a series."""
	return series_path.with_suffix(".lock")


class _FileLock:
	"""Context manager for file locking (both inter-process and inter-thread)."""

	# Class-level dict for thread locks (per series path)
	_thread_locks: dict[str, threading.Lock] = {}
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
			if key not in self._thread_locks:
				self._thread_locks[key] = threading.Lock()
			self._thread_lock = self._thread_locks[key]
		self._thread_lock.acquire()

		# Then acquire file-level lock for inter-process safety
		self._lock_path.parent.mkdir(parents=True, exist_ok=True)
		self._fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
		fcntl.flock(self._fd, fcntl.LOCK_SH if self._read_only else fcntl.LOCK_EX)
		
		# Cleanup only this series' orphaned .tmp file from previous crashes
		if not self._read_only:
			stale_tmp = self._series_path.with_suffix(self._series_path.suffix + ".tmp")
			if stale_tmp.exists():
				try:
					stale_tmp.unlink(missing_ok=True)
				except OSError:
					pass
		
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		if self._fd is not None:
			fcntl.flock(self._fd, fcntl.LOCK_UN)
			os.close(self._fd)
			self._fd = None
		if self._thread_lock is not None:
			self._thread_lock.release()
			self._thread_lock = None


def _should_prune(series_path: Path) -> bool:
	"""Check if enough time has passed since last prune for this series.
	
	Uses a file-based marker for cross-process safety with multiple workers.
	"""
	marker = _prune_marker_path(series_path)
	now = time.time()
	
	try:
		if marker.exists():
			last_prune = marker.stat().st_mtime
			if now - last_prune < PRUNE_INTERVAL_SECONDS:
				return False
		
		# Touch the marker file atomically to claim this prune slot
		marker.parent.mkdir(parents=True, exist_ok=True)
		fd = os.open(str(marker), os.O_CREAT | os.O_WRONLY)
		try:
			# Try to get exclusive lock without blocking
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
			# Double-check after acquiring lock
			try:
				last_prune = os.fstat(fd).st_mtime
				if now - last_prune < PRUNE_INTERVAL_SECONDS:
					return False
			except OSError:
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


def _rotated_archives(series_path: Path) -> list[Path]:
	"""Return rotated archive files for a series (sorted oldest -> newest)."""
	pattern = f"{series_path.name}.*.gz"
	return sorted(series_path.parent.glob(pattern))


def _iter_series_files(series_path: Path) -> list[Path]:
	"""Return all files containing series data in chronological order."""
	files: list[Path] = []
	files.extend(_rotated_archives(series_path))
	if series_path.exists():
		files.append(series_path)
	return files


def _compress_file(src_path: Path) -> Path:
	"""Compress a file to gzip atomically and remove source after verification."""
	gz_path = Path(f"{src_path}.gz")
	tmp_gz = gz_path.with_suffix(".gz.tmp")
	with src_path.open("rb") as src, gzip.open(tmp_gz, "wb", compresslevel=6) as dst:
		shutil.copyfileobj(src, dst)
	# Ensure data is written to disk before replacing
	_fsync_path(tmp_gz)
	os.replace(tmp_gz, gz_path)
	# Only delete source after successful compression and rename
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

	stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
	rotated = series_path.parent / f"{series_path.name}.{stamp}"
	try:
		os.replace(series_path, rotated)
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
			# Parse timestamp from filename: metric.jsonl.20260219T120000Z.gz
			# Extract the timestamp part (before .gz)
			parts = arc.stem.split(".")  # Remove .gz, get ['metric', 'jsonl', '20260219T120000Z']
			if len(parts) < 3:
				_log.warning("Archive filename does not contain timestamp: %s", arc.name)
				continue
			timestamp_str = parts[-1]  # Get '20260219T120000Z'
			# Parse ISO 8601 basic format timestamp
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
	"""Yield JSONL lines from plain or gzip files."""
	if path.suffix == ".gz":
		with gzip.open(path, "rt", encoding="utf-8") as f:
			yield from f
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


def purge_tsdb(tsdb_dir: Path) -> None:
	"""Completely remove all TSDB data."""
	if not tsdb_dir.exists():
		return
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
	tsdb_dir.mkdir(parents=True, exist_ok=True)


def delete_peer_data(tsdb_dir: Path, peer_key: str) -> None:
	"""Delete all time-series data for a specific peer."""
	# Use same hash as _series_path to find the correct directory
	key_hash = base64.urlsafe_b64encode(
		hashlib.sha256(peer_key.encode()).digest()
	).decode().rstrip("=")
	tdir = tsdb_dir / f"peer_{key_hash}"
	if not tdir.exists():
		return
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


def append_point(
	tsdb_dir: Path,
	*,
	peer_key: str,
	metric: str,
	value: Any,
	retention_days: int = DEFAULT_RETENTION_DAYS,
	at: Optional[datetime] = None,
) -> None:
	"""Append a data point to a time series.

	Args:
		tsdb_dir: Base directory for TSDB storage.
		peer_key: WireGuard peer public key.
		metric: Name of the metric (e.g., "rx_bytes", "tx_bytes").
		value: The metric value to store.
		retention_days: How many days to retain data.
		at: Optional timestamp; defaults to now (UTC).
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
			# Ensure data is fsynced to disk for durability
			f.flush()
			os.fsync(f.fileno())
		_rotate_series_locked(p)

		# Rate-limited pruning: check timing without random gate
		# Uses file-based marker for cross-process safety
		if _should_prune(p):
			_prune_series_locked(p, retention_days)


def _prune_series_locked(series_path: Path, retention_days: int) -> None:
	"""Prune old data points from a series file. MUST be called with lock held."""
	retention_days = _validate_retention(retention_days)
	cutoff = utcnow() - timedelta(days=retention_days)
	
	if not series_path.exists():
		# Still prune archive set if active file has already rotated away.
		_prune_archives_locked(series_path, cutoff)
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

	tmp = series_path.with_suffix(series_path.suffix + ".tmp")
	with tmp.open("w", encoding="utf-8") as f:
		for line in kept:
			f.write(line + "\n")


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
			from collections import deque
			buffer: deque[MetricPoint] = deque(maxlen=limit)
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

					buffer.append(MetricPoint(ts=ts, value=val))
			return list(buffer)
		else:
			# For non-latest queries, collect up to limit
			all_matching: list[MetricPoint] = []
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

					if len(all_matching) >= limit:
						return all_matching[:limit]

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
	
	Note: Returns SHA-256 hashes of peer keys, not the original keys themselves.
	These hashes are used for directory naming and cannot be reversed.
	"""
	if not tsdb_dir.exists():
		return []
	
	hashes = []
	for d in tsdb_dir.iterdir():
		if d.is_dir() and d.name.startswith("peer_"):
			key_hash = d.name[5:]  # Remove "peer_" prefix
			hashes.append(key_hash)
	return hashes


def get_all_peer_keys(tsdb_dir: Path) -> list[str]:
	"""Deprecated: Use get_all_peer_hashes() instead.
	
	This function returns hashes, not actual peer keys.
	"""
	_log.warning("get_all_peer_keys is deprecated and returns hashes, not keys. Use get_all_peer_hashes() instead.")
	return get_all_peer_hashes(tsdb_dir)


def get_db_stats(tsdb_dir: Path) -> dict[str, Any]:
	"""Get TSDB storage statistics.
	
	Returns:
		Dict with size_bytes, created_at (ISO timestamp), peer_count, file_count
	"""
	if not tsdb_dir.exists():
		return {
			"size_bytes": 0,
			"compressed_size_bytes": 0,
			"created_at": None,
			"peer_count": 0,
			"file_count": 0,
			"archive_count": 0,
			"retention_days": DEFAULT_RETENTION_DAYS,
			"max_series_file_bytes": MAX_SERIES_FILE_BYTES,
		}
	
	total_size = 0
	compressed_size = 0
	file_count = 0
	archive_count = 0
	oldest_mtime: float | None = None
	
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
					# Track oldest file (creation approximated by earliest mtime)
					if oldest_mtime is None or stat.st_mtime < oldest_mtime:
						oldest_mtime = stat.st_mtime
				except OSError:
					pass
	
	peer_count = len(get_all_peer_hashes(tsdb_dir))
	created_at = None
	if oldest_mtime is not None:
		created_at = datetime.fromtimestamp(oldest_mtime, tz=timezone.utc).isoformat()
	
	return {
		"size_bytes": total_size,
		"compressed_size_bytes": compressed_size,
		"created_at": created_at,
		"peer_count": peer_count,
		"file_count": file_count,
		"archive_count": archive_count,
		"retention_days": DEFAULT_RETENTION_DAYS,
		"max_series_file_bytes": MAX_SERIES_FILE_BYTES,
	}


def reset_all(tsdb_dir: Path) -> int:
	"""Delete all TSDB data.
	
	Returns:
		Number of files deleted.
	"""
	if not tsdb_dir.exists():
		return 0
	
	deleted = 0
	for d in list(tsdb_dir.iterdir()):
		if d.is_dir() and d.name.startswith("peer_"):
			try:
				shutil.rmtree(d)
				deleted += 1
			except OSError as e:
				_log.warning("Failed to delete TSDB directory %s: %s", d, e)
	
	_log.info("TSDB reset: deleted %d peer directories", deleted)
	return deleted


def run_maintenance(tsdb_dir: Path, retention_days: int = DEFAULT_RETENTION_DAYS) -> dict[str, int]:
	"""Run retention/rotation maintenance across all series files.

	Returns:
		Dict with maintenance counters.
	"""
	retention_days = _validate_retention(retention_days)
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
		before_archives = len(_rotated_archives(series_path))
		with _FileLock(series_path):
			_rotate_series_locked(series_path)
			after_rotate_archives = len(_rotated_archives(series_path))
			if after_rotate_archives > before_archives:
				rotated_count += 1
			before_prune_archives = len(_rotated_archives(series_path))
			_prune_series_locked(series_path, retention_days)
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
	"""Run final maintenance and fsync on shutdown."""
	maintenance = run_maintenance(tsdb_dir, retention_days=retention_days)
	flush_stats = flush_to_disk(tsdb_dir)
	return {
		"series": maintenance.get("series", 0),
		"rotated": maintenance.get("rotated", 0),
		"pruned": maintenance.get("pruned", 0),
		"synced_files": flush_stats.get("synced_files", 0),
		"synced_dirs": flush_stats.get("synced_dirs", 0),
	}
