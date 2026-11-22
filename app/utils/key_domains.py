#!/usr/bin/env python3
#
# app/utils/key_domains.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

r"""Key-domain separation for ``WIREBUDDY_SECRET_KEY``.

Inventory of how the master key is used (each purpose gets its own derivation
context, so a value computed for one purpose can never be replayed for another):

- Vault encryption (``utils/vault.py``): PBKDF2 + HKDF with ``wirebuddy-vault-v2``
  (and ``vault:1`` per-row PBKDF2 for legacy rows). Already domain separated.
- Backup HMAC: ``SHA256(wirebuddy-backup-hmac\\0 || key)`` (unchanged format).
- Enrollment-token HMAC: ``SHA256(wirebuddy-enrollment-hmac-v1\\0 || key)``.
- Passkey user handle: no longer derived from the master key.

The derived keys are short-lived values; the raw master key is never used as an
HMAC key directly.
"""

from __future__ import annotations

import hashlib

__all__ = [
	"BACKUP_HMAC_CONTEXT",
	"ENROLLMENT_HMAC_CONTEXT",
	"derive_backup_hmac_key",
	"derive_enrollment_hmac_key",
]

BACKUP_HMAC_CONTEXT = b"wirebuddy-backup-hmac\0"
ENROLLMENT_HMAC_CONTEXT = b"wirebuddy-enrollment-hmac-v1\0"


def _derive(context: bytes, master_secret: str) -> bytes:
	secret = str(master_secret or "")
	if not secret:
		raise RuntimeError("WIREBUDDY_SECRET_KEY is required")
	return hashlib.sha256(context + secret.encode("utf-8")).digest()


def derive_backup_hmac_key(master_secret: str) -> bytes:
	"""Return the backup-integrity HMAC key for ``master_secret``."""
	return _derive(BACKUP_HMAC_CONTEXT, master_secret)


def derive_enrollment_hmac_key(master_secret: str) -> bytes:
	"""Return the node enrollment-token HMAC key for ``master_secret``."""
	return _derive(ENROLLMENT_HMAC_CONTEXT, master_secret)
