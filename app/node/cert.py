#!/usr/bin/env python3
#
# app/node/cert.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Self-signed certificate management for node identity."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..utils.node_token import generate_node_cert, get_cert_fingerprint

_log = logging.getLogger(__name__)

CERT_FILE = "node.crt"
KEY_FILE = "node.key"


def clear_node_cert(data_dir: Path) -> None:
	"""Remove existing node certificate and key files.

	Used when re-enrolling with a different enrollment token.
	"""
	cert_path = data_dir / CERT_FILE
	key_path = data_dir / KEY_FILE

	for path in (cert_path, key_path):
		# Only unlink regular files (not symlinks or directories for safety)
		if path.is_file():
			path.unlink()
			_log.info("Removed old certificate file: %s", path.name)


def ensure_node_cert(data_dir: Path, node_id: str) -> tuple[bytes, bytes]:
	"""Ensure a self-signed certificate exists for this node.

	Generates a new EC P-256 certificate if one doesn't exist.

	Returns:
		(cert_pem, key_pem) as bytes
	"""
	cert_path = data_dir / CERT_FILE
	key_path = data_dir / KEY_FILE

	# Attempt to read existing cert/key directly (avoid TOCTOU race)
	try:
		cert_pem = cert_path.read_bytes()
		key_pem = key_path.read_bytes()
		fp = get_cert_fingerprint(cert_pem)
		_log.info("Using existing node certificate (fingerprint=%s...)", fp[:16])
		return cert_pem, key_pem
	except FileNotFoundError:
		# One or both files missing, regenerate
		if cert_path.exists() or key_path.exists():
			_log.warning("Incomplete certificate state detected, regenerating both cert and key")
			# Clean up partial state
			cert_path.unlink(missing_ok=True)
			key_path.unlink(missing_ok=True)
	except Exception as exc:
		# Corrupted files or permission issues
		_log.warning("Failed to read existing certificate (%s), regenerating", exc)
		cert_path.unlink(missing_ok=True)
		key_path.unlink(missing_ok=True)

	_log.info("Generating new self-signed node certificate...")
	cert_pem, key_pem = generate_node_cert(node_id)

	# Create data directory with restrictive permissions (0o700)
	data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

	# Atomic write with restrictive permissions
	_write_file(cert_path, cert_pem, mode=0o600)  # Stricter: keep cert private too
	_write_file(key_path, key_pem, mode=0o600)

	fp = get_cert_fingerprint(cert_pem)
	_log.info("Node certificate created (fingerprint=%s...)", fp[:16])
	return cert_pem, key_pem


def _write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
	"""Write data to file atomically with specified permissions.
	
	Uses fsync for durability and unique temp filename to avoid collisions.
	"""
	# Use PID in temp filename to avoid collisions from concurrent writers
	tmp = path.with_suffix(f".{os.getpid()}.tmp")
	try:
		# Write with fsync for durability
		with open(tmp, "wb") as f:
			f.write(data)
			f.flush()
			os.fsync(f.fileno())
		os.chmod(tmp, mode)
		os.replace(tmp, path)
	except Exception:
		# Don't catch SystemExit/KeyboardInterrupt (was BaseException)
		tmp.unlink(missing_ok=True)
		raise
