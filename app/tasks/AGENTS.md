<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# tasks

## Purpose
Background jobs run by the app scheduler (`app/utils/scheduler.py`). `scheduler_config.py` registers them with intervals and conditions, `scheduled.py` holds the context-bound job bodies, `maintenance.py` the database housekeeping jobs.

## Key Files
| File | Description |
|------|-------------|
| `scheduler_config.py` | `register_all_tasks(scheduler, ctx)`: registers every job via `_bind(ctx, fn)`; computes the backup wall-clock delay (next 03:00 UTC) and registers the backup and speedtest with `next_delay` so each run is rescheduled to the next calendar slot; one-shot conntrack accounting init |
| `scheduled.py` | Job bodies: blocklist updates, TSDB maintenance and sampling (WireGuard counters, country/ASN traffic, network stats), GeoIP updates, DNS watchdog, ad-blocker timer, nightly speedtest, scheduled backup, node health monitoring |
| `db_inputs.py` | Sync DB/input readers shared by `app/main.py` and the tasks, run via `asyncio.to_thread`: settings and retention readers, `parse_wg_dump_counters`, peer identity map, ad-blocker timer check and Unbound reload |
| `maintenance.py` | SQLite maintenance (WAL checkpoint/analyze/optimize), weekly integrity check, TSDB retention cleanup, expired session, passkey-challenge and login-attempt purge, acked `node_commands` cleanup |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Context-aware tasks take the `LifespanContext` (from `app/main.py`) as first argument and are bound in `scheduler_config.py`; add new tasks there, not inline in `main.py`.
- Let `asyncio.CancelledError` propagate. The scheduler logs any other exception and reschedules with failure jitter, so a task handles and logs its expected failures itself.
- Speedtests must go through a `gillbates_speedtest` run-guard lease (`acquire_speedtest_run_lease_async`) and on the master pass `country_resolver=resolve_speedtest_server_country` (nodes pass none); the nightly window comes from `utils/speedtest_window`.
- Resolve WireGuard binaries via `_resolve_wg_binary` (wraps `utils.binaries.first_executable`), not PATH lookup.
- Keep DB/input readers in `db_inputs.py`; `scheduled.py` imports them.

### Testing Requirements
- Run `pytest` from the repo root. Tests that import this package: `test_backup_schema_only.py` (backup schedule in `scheduler_config`), `test_retention_options.py` and `test_session_revocation.py` (`maintenance`, `db_inputs`), `test_coerce.py` (`db_inputs`), `test_speedtest_api.py`, `test_conntrack_baseline_commit.py` and `test_utils_hardening.py` (`scheduled`).

### Common Patterns
- Sync DB access goes through `db_call`/`db_call_or` from `app/db/sqlite_runtime.py`; `maintenance.py` uses `aiosqlite` directly. Settings come from `app/db/sqlite_settings`.
- Peer state caches are bounded (`_evict_peer_state_entries` drops the oldest 10%).

## Dependencies

### Internal
- `app/main` (`LifespanContext`), `app/api/` (backup, speedtest, network stats, peer tags), `app/dns/`, `app/db/`, `app/models/peers`, `app/utils/` (`scheduler`, `conntrack`, `geoip`, `subprocess`, `config`, `speedtest_window`, `binaries`, `time`).

### External
- `gillbates-speedtest`, `aiosqlite`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
