#!/usr/bin/env python3
#
# app/node/cert.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Self-signed certificate management for node identity."""

from __future__ import annotations

import fcntl
import logging
import os
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..utils.node_token import generate_node_cert, get_cert_fingerprint

_log = logging.getLogger(__name__)

CERT_FILE = "node.crt"
KEY_FILE = "node.key"
_CERT_LOCK = threading.Lock()


def clear_node_cert(data_dir: Path) -> None:
	"""Remove existing node certificate and key files.

	Used when re-enrolling with a different enrollment token.
	"""
	with _cert_lock(data_dir):
		_clear_node_cert_unlocked(data_dir)


def _clear_node_cert_unlocked(data_dir: Path) -> None:
	"""Remove certificate files while already holding the certificate lock."""
	cert_path = data_dir / CERT_FILE
	key_path = data_dir / KEY_FILE

	for path in (cert_path, key_path):
		if path.is_symlink():
			path.unlink()
			_log.warning("Removed unexpected certificate symlink: %s", path.name)
		elif path.is_file():
			path.unlink()
			_log.info("Removed old certificate file: %s", path.name)

	_fsync_dir(data_dir)


def ensure_node_cert(data_dir: Path, node_id: str) -> tuple[bytes, bytes]:
	"""Ensure a self-signed certificate exists for this node.

	Generates a new EC P-256 certificate if one doesn't exist.

	Returns:
		(cert_pem, key_pem) as bytes
	"""
	with _cert_lock(data_dir):
		return _ensure_node_cert_unlocked(data_dir, node_id)


def _ensure_node_cert_unlocked(data_dir: Path, node_id: str) -> tuple[bytes, bytes]:
	"""Read or generate the node certificate while holding the cert lock."""
	cert_path = data_dir / CERT_FILE
	key_path = data_dir / KEY_FILE
	_ensure_private_dir(data_dir)

	# Attempt to read existing cert/key directly (avoid TOCTOU race)
	try:
		if cert_path.is_symlink() or key_path.is_symlink():
			raise ValueError("Certificate files must not be symlinks")
		cert_pem = cert_path.read_bytes()
		key_pem = key_path.read_bytes()
		_validate_cert_key_pair(cert_pem, key_pem)
		fp = get_cert_fingerprint(cert_pem)
		_log.info("Using existing node certificate (fingerprint=%s...)", fp[:16])
		return cert_pem, key_pem
	except FileNotFoundError:
		# One or both files missing, regenerate
		if any(path.exists() or path.is_symlink() for path in (cert_path, key_path)):
			_log.warning("Incomplete certificate state detected, regenerating both cert and key")
			_clear_node_cert_unlocked(data_dir)
	except PermissionError:
		_log.exception("Insufficient permissions to read node certificate files")
		raise
	except Exception as exc:
		_log.warning("Invalid existing certificate state (%s), regenerating", exc)
		_clear_node_cert_unlocked(data_dir)

	_log.info("Generating new self-signed node certificate...")
	cert_pem, key_pem = generate_node_cert(node_id)

	# Atomic write with restrictive permissions
	_write_file(cert_path, cert_pem, mode=0o600)  # Stricter: keep cert private too
	_write_file(key_path, key_pem, mode=0o600)

	fp = get_cert_fingerprint(cert_pem)
	_log.info("Node certificate created (fingerprint=%s...)", fp[:16])
	return cert_pem, key_pem


def _ensure_private_dir(path: Path) -> None:
	"""Ensure the certificate directory exists with restrictive permissions."""
	try:
		st = path.lstat()
	except FileNotFoundError:
		path.mkdir(parents=True, mode=0o700)
		st = path.lstat()
	if stat.S_ISLNK(st.st_mode):
		raise RuntimeError(f"Certificate directory must not be a symlink: {path}")
	if not stat.S_ISDIR(st.st_mode):
		raise RuntimeError(f"Certificate directory is not a directory: {path}")
	path.chmod(0o700)


@contextmanager
def _cert_lock(data_dir: Path) -> Iterator[None]:
	"""Serialize certificate generation across threads and processes."""
	_ensure_private_dir(data_dir)
	lock_path = data_dir / ".node-cert.lock"
	fd = -1
	flags = os.O_RDWR | os.O_CREAT
	if hasattr(os, "O_CLOEXEC"):
		flags |= os.O_CLOEXEC
	fd = os.open(lock_path, flags, 0o600)
	try:
		os.fchmod(fd, 0o600)
		with _CERT_LOCK:
			fcntl.flock(fd, fcntl.LOCK_EX)
			try:
				yield
			finally:
				fcntl.flock(fd, fcntl.LOCK_UN)
	finally:
		if fd != -1:
			os.close(fd)


def _validate_cert_key_pair(cert_pem: bytes, key_pem: bytes) -> None:
	"""Ensure the certificate and private key belong to the same keypair."""
	cert = x509.load_pem_x509_certificate(cert_pem)
	private_key = serialization.load_pem_private_key(key_pem, password=None)
	if cert.public_key().public_numbers() != private_key.public_key().public_numbers():
		raise ValueError("Certificate and private key do not match")


def _fsync_dir(path: Path) -> None:
	"""Fsync the containing directory so renames are durable across crashes."""
	flags = os.O_RDONLY
	if hasattr(os, "O_DIRECTORY"):
		flags |= os.O_DIRECTORY
	dir_fd = os.open(path, flags)
	try:
		os.fsync(dir_fd)
	finally:
		os.close(dir_fd)


def _write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
	"""Write data to file atomically with specified permissions.
	
	Uses fsync for durability and a unique temp filename to avoid collisions.
	"""
	fd = -1
	tmp_path: Path | None = None
	try:
		fd, tmp_name = tempfile.mkstemp(
			prefix=f".{path.name}.",
			suffix=".tmp",
			dir=path.parent,
		)
		tmp_path = Path(tmp_name)
		os.fchmod(fd, mode)
		with os.fdopen(fd, "wb") as handle:
			fd = -1
			handle.write(data)
			handle.flush()
			os.fsync(handle.fileno())
		os.replace(tmp_path, path)
		_fsync_dir(path.parent)
	except Exception:
		if fd != -1:
			os.close(fd)
		if tmp_path is not None:
			tmp_path.unlink(missing_ok=True)
		raise
