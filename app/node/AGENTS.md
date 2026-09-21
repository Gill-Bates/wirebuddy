<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# node

## Purpose
Minimal WireGuard runtime for remote cluster nodes plus the master-side helpers that talk to them. `daemon.py` is the standalone node process: it enrolls with a master using an enrollment token, polls/pulls config, pushes heartbeats with queued metrics, listens to master SSE events and runs speedtests. `wg_manager.py` applies received config diffs to local WireGuard. The master side uses `notifier.py` and `events.py` to push config/commands to nodes over SSE.

## Key Files
| File | Description |
|------|-------------|
| `daemon.py` | Node entry point (`run()`/`main()`): enrollment via `WIREBUDDY_ENROLLMENT_TOKEN`, persisted node state, config pull, heartbeat push, SSE listener with bounded reconnect, nightly and on-demand speedtests, durable command ACKs |
| `wg_manager.py` | Validates and applies master config: renders interface configs, phased write/start/reload/orphan removal, diff-based peer sync with rollback, PSK temp files, route handling, `wg show all dump` parsing |
| `metrics_queue.py` | Local SQLite queue giving at-least-once delivery of peer traffic metrics to the master, idempotent via sequence numbers, size-capped |
| `notifier.py` | Master-side delivery of config-change, restart, speedtest and node-removed commands: persisted in SQLite (durable, ACK-based, replayable) with SSE as low-latency path; connection tracking |
| `events.py` | Typed node event/command models and the process-local AnyIO `NodeEventBus` for ephemeral events (e.g. speedtest progress) |
| `cert.py` | Self-signed node identity certificate: locked, atomic, symlink-safe creation, key/cert pair validation |
| `firewall.py` | `check_firewall_dns_rules`: verifies (and fixes if possible) DNS is allowed on the WireGuard interface |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- `daemon.py`, `wg_manager.py`, `cert.py` and `metrics_queue.py` run on the node; `notifier.py` and `events.py` run on the master. Keep that split.
- Security-sensitive: node IDs, config versions, SSE values and interface names are validated to prevent injection; WireGuard keys are redacted in errors; state and key files use restrictive permissions and atomic write plus fsync. Never log secrets or tokens.
- Master URL must be HTTPS unless explicitly overridden; the enrollment token HMAC is verified locally by default.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). Relevant: `test_node_db.py`, `test_tls_material.py`, `test_audit_hardening.py`.
- Add tests for new validation or queue behaviour; avoid tests that require real WireGuard or root.

### Common Patterns
- Commands are persisted first (`node_commands` table) then pushed over SSE; nodes ACK by command ID and unacked commands are replayed on reconnect.
- Config application is phased (parse/validate, write, sync interfaces, sync peers, remove orphans) with rollback on failure.
- File writes: temp file, chmod, rename, fsync of the parent directory.

## Dependencies

### Internal
- `app/utils/` (`config`, `node_token`, `subprocess`-style helpers, `speedtest_window`, `version`, `banner`, `async_utils`), `app/db/sqlite_nodes` and `sqlite_runtime`, `app/speedtest/` (`tester`, `guard`).

### External
- `httpx`, `anyio`, `pydantic`, `cryptography`, stdlib `sqlite3`/`ssl`/`fcntl`; `wg`, `wg-quick`, `ip` binaries.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
