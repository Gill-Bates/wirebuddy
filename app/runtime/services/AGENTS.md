<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# services

## Purpose
Concrete `RuntimeService` implementations that each own the lifecycle of one domain. They are registered in the `ServiceContainer` and started in dependency order: `sqlite` and `tsdb` first (no dependencies), then `wireguard` (needs sqlite), `dns` (needs sqlite and wireguard) and `scheduler` (needs sqlite and tsdb).

## Key Files
| File | Description |
|------|-------------|
| `sqlite.py` | `SQLiteService`: schema initialisation, secret key validation, WAL checkpointing, connection cleanup, integrity-safe shutdown |
| `tsdb.py` | `TSDBService`: time-series DB init, retention enforcement, fsync on shutdown |
| `wireguard.py` | `WireGuardService`: `wg-quick up/down`, stale interface cleanup, bounded-parallel startup, health via `wg show` |
| `dns.py` | `DNSService`: Unbound configuration and process supervision, query-log ingestion, blocklist updates, peer tag generation for ad-blocking |
| `scheduler.py` | `SchedulerService`: registers jobs (via `app/tasks/scheduler_config`), supervises them and shuts down gracefully |
| `__init__.py` | Exports the five service classes |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- Subclass `RuntimeService`, set `name` and `dependencies`, and export the class in `__init__.py`.
- Keep `dependencies` accurate: it drives startup order and parallelism.
- External commands must go through `app/utils/subprocess` (timeouts, output limits), never bare `subprocess` calls.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). Related: `test_dns_listen_preflight.py`, `test_backup_schema_only.py`.
- Mock processes and binaries; do not start real Unbound or WireGuard in tests.

### Common Patterns
- Each service implements start/stop/health from the base class and reads settings via `app/db/sqlite_settings` and `sqlite_runtime`.
- Long-running startup work is bounded (semaphore/timeouts) and failures degrade health rather than crash the app where possible.

## Dependencies

### Internal
- `../service.py` and `../container.py`, `app/dns/` (Unbound config, blocklists), `app/db/` (`sqlite_settings`, `sqlite_runtime`, `sqlite_peers`, `sqlite_interfaces`), `app/utils/` (`config`, `subprocess`, `scheduler`), `app/tasks/scheduler_config`.

### External
- `unbound`, `wg`/`wg-quick` binaries; stdlib `asyncio`, `sqlite3`, `ipaddress`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
