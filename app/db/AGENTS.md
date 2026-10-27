<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-10-27 -->

# db

## Purpose
Persistence layer. SQLite access is split into `sqlite_*.py` modules by domain (connections/transactions, schema and migrations, settings, users, auth tokens, passkeys, interfaces, peers, nodes), all operating on a passed-in connection. `tsdb.py` implements a file-based JSONL time-series database with file locking, rotation/compression and retention for peer metrics and DNS query logs.

## Key Files
| File | Description |
|------|-------------|
| `sqlite_runtime.py` | Connection factory, per-thread connections, `db_call()`/`db_call_or()` one-shot call wrappers, datetime adapters, WAL checkpoint, `transaction()` context manager with savepoints |
| `sqlite_schema.py` | `init_schema` (tables: users, dashboard_layouts, passkeys, passkey_challenges, auth_tokens, settings, schema_version, login_attempts, peers, interfaces, nodes, node_commands, node_interfaces), migrations, default settings, `ensure_default_admin` (first boot only: password from `_generate_pronounceable_password` (6 letters + 2 digits + 1 special character), `must_change_password=1`, printed once to stdout by `_print_bootstrap_credentials`; never logged and never written to a file) |
| `sqlite_settings.py` | Key/value settings, typed helpers (bool/JSON/retention), validation, missing-setting recovery, blocklist and DNS upstream settings |
| `sqlite_dashboard.py` | Per-user dashboard layout in the `dashboard_layouts` table (one row per widget, CHECK bounds, FK cascade to users): get/set (atomic replace)/delete plus the one-time migration of legacy `dashboard_layout:user:<id>` settings keys (run from `_run_migrations`; invalid/orphaned blobs are logged and dropped) |
| `sqlite_users.py` | User CRUD, OTP secret encryption, recovery codes, auth method, passkey onboarding, last-admin protection |
| `sqlite_auth.py` | Auth token lifecycle and login-attempt lockout policy |
| `sqlite_passkeys.py` | WebAuthn credential rows and challenge store |
| `sqlite_interfaces.py` | WireGuard interface CRUD with validation |
| `sqlite_peers.py` | Peer reads, pagination, last-seen/cumulative transfer updates, IP allocation |
| `sqlite_peers_mutations.py` | Peer create/update/delete with validation and secret encryption |
| `sqlite_nodes.py` | Node CRUD, enrollment, secret rotation, heartbeat, tunnel peer, per-interface node keypairs (`create_node_interface`/`delete_node_interfaces`), metric sequence tracking |
| `tsdb.py` | JSONL TSDB: `MetricPoint`, append/query, read-write and file locks, rotation/gzip archives, retention pruning, legacy layout migration |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Functions take a `sqlite3.Connection` (or use `sqlite_runtime`); do not open ad-hoc connections elsewhere.
- Schema changes need an idempotent step in `_run_migrations` in `sqlite_schema.py`; backup/restore (`app/api/backup.py`) must remain compatible.
- `tsdb.py` is synchronous and Unix-only (`fcntl`); call it from async code via `asyncio.to_thread`.

### Testing Requirements
- `pytest` in `/opt/wirebuddy/tests` (`test_node_db.py`, `test_login_lockout.py`, `test_user_security.py`, `test_backup_schema_only.py`).
- Use temporary SQLite files/directories; never touch `data/`.

### Common Patterns
- Writes go through `transaction()`; secrets (private keys, PSKs, OTP secrets) are encrypted before storage.
- Validation helpers (`_validate_*`) raise `ValueError` before any SQL runs.
- Parameterised SQL only; column additions use `_add_column_if_missing`.

## Dependencies

### Internal
- `app/utils` (crypto, config, time), `app/models` (validation types).

### External
- sqlite3, cryptography, stdlib `fcntl`, `gzip`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
