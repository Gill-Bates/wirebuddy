<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# tasks

## Purpose
Background jobs run by the app scheduler (`app/utils/scheduler.py`). Task bodies were extracted from the main lifespan closure for testability; `scheduler_config.py` registers them with intervals and conditions, and `maintenance.py` holds database housekeeping jobs.

## Key Files
| File | Description |
|------|-------------|
| `scheduler_config.py` | `register_all_tasks(ctx, ...)`: registers every job via `_bind(ctx, fn)`; computes backup wall-clock delay (03:00 in configured timezone); one-shot conntrack accounting init |
| `scheduled.py` | Task implementations: blocklist updates, TSDB maintenance and sampling (WireGuard counters, country/ASN traffic, network stats), GeoIP updates, DNS watchdog, ad-blocker timer, nightly speedtest, scheduled backup, node health monitoring |
| `db_inputs.py` | Sync DB/input readers shared by `app/main.py` and the tasks, run via `asyncio.to_thread`: settings and retention readers, `parse_wg_dump_counters`, peer identity map, ad-blocker timer check and Unbound reload (moved out of `main.py`). The connection wrapper itself lives in `app/db/sqlite_runtime.py` (`db_call`/`db_call_or`) |
| `maintenance.py` | SQLite maintenance (WAL checkpoint/analyze/optimize), weekly integrity check, TSDB retention cleanup, expired session/login-attempt purge, acked `node_commands` cleanup |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- Context-aware tasks take the `LifespanContext` (from `app/main.py`) as first argument and are bound in `scheduler_config.py`; add new tasks there, not inline in `main.py`.
- Tasks must be cancellation-safe (use `sleep_with_cancellation_check`) and must not raise out of the scheduler; log and continue.
- Speedtests must go through the `app/speedtest/guard` lease; the nightly window comes from `utils/speedtest_window`.
- Resolve WireGuard binaries via `_resolve_wg_binary` (wraps `utils.binaries.first_executable`), not PATH lookup.
- Keep DB/input readers in `db_inputs.py`; `scheduled.py` imports them.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). Related: `test_login_lockout.py`, `test_node_db.py`, `test_backup_schema_only.py`.

### Common Patterns
- DB access via `_db_call` (managed `thread_connection`; defined in `scheduled.py` and `db_inputs.py`) or `aiosqlite`; settings read from `app/db/sqlite_settings`.
- Peer state caches are bounded (`_evict_peer_state_entries` drops the oldest 10%).

## Dependencies

### Internal
- `app/main` (`LifespanContext`), `app/dns/`, `app/db/`, `app/speedtest/`, `app/utils/` (`scheduler`, `conntrack`, `geoip`, `subprocess`, `config`, `speedtest_window`, `binaries`). Registered by `app/tasks/scheduler_config.py`.

### External
- `aiosqlite`, stdlib `zoneinfo`, `asyncio`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
