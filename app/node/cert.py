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


def ensure_node_cert(data_dir: Path, node_id: str) -> tuple[bytes, bytes]:
	"""Ensure a self-signed certificate exists for this node.

	Generates a new EC P-256 certificate if one doesn't exist.

	Returns:
		(cert_pem, key_pem) as bytes
	"""
	cert_path = data_dir / CERT_FILE
	key_path = data_dir / KEY_FILE

	if cert_path.exists() and key_path.exists():
		cert_pem = cert_path.read_bytes()
		key_pem = key_path.read_bytes()
		fp = get_cert_fingerprint(cert_pem)
		_log.info("Using existing node certificate (fingerprint=%s...)", fp[:16])
		return cert_pem, key_pem

	_log.info("Generating new self-signed node certificate...")
	cert_pem, key_pem = generate_node_cert(node_id)

	data_dir.mkdir(parents=True, exist_ok=True)

	# Atomic write with restrictive permissions
	_write_file(cert_path, cert_pem, mode=0o644)
	_write_file(key_path, key_pem, mode=0o600)

	fp = get_cert_fingerprint(cert_pem)
	_log.info("Node certificate created (fingerprint=%s...)", fp[:16])
	return cert_pem, key_pem


def _write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
	"""Write data to file atomically with specified permissions."""
	tmp = path.with_suffix(".tmp")
	try:
		tmp.write_bytes(data)
		os.chmod(tmp, mode)
		os.replace(tmp, path)
	except BaseException:
		tmp.unlink(missing_ok=True)
		raise
