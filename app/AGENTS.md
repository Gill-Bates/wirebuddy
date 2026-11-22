<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->

# app

## Purpose
The `wirebuddy` Python package: the FastAPI application factory (`create_app` in `main.py`) and everything it wires together: middleware, routers, the SQLite/TSDB layer, the Unbound DNS integration, master/node synchronisation, background tasks and the server-rendered UI.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package docstring; exposes `create_app` lazily for `uvicorn app:create_app` |
| `server.py` | Web server start (`main()`): bind settings from the DB with optional `--host`/`--port` overrides, HTTP vs built-in HTTPS from `gui_https_enabled`, certificate resolution and the plaintext ACME listener; the single start path, used by the Docker entrypoint (`python -m app.server`); forwarded headers are applied by `create_served_app()` and uvicorn runs with `proxy_headers=False` |
| `main.py` | Application factory and lifespan (single-instance lock, stale interface cleanup, bootstrap, scheduler): registers `TrustedHostMiddleware`, `RequestIDMiddleware`, `CSRFMiddleware`, mounts all routers (`/api/...`, `/api/wireguard`, `/api/dns`, `/api/nodes`, frontend pages), starts scheduler/DNS/tasks, shutdown-signal hooks via `gillbates_shutdown_handler.chain_signal_handlers`, trusted `ip`/`wg`/`wg-quick` resolution (`utils.binaries.first_executable`), `/health`, `/ready`, `/swagger`, static assets served with `Cache-Control: no-cache` (`_RevalidatingStaticFiles`), `_bind_is_loopback` for the Host-header decision; the scheduled-task DB/input readers live in `tasks/db_inputs.py`, not here |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `api/` | HTTP routers (REST + UI pages), one module per feature (see `api/AGENTS.md`) |
| `db/` | SQLite access layer, schema/migrations and the JSONL time-series DB (see `db/AGENTS.md`) |
| `dns/` | Unbound config generation, process supervision, blocklists, custom rules, query-log ingestion (see `dns/AGENTS.md`) |
| `middleware/` | Starlette middleware (CSRF) (see `middleware/AGENTS.md`) |
| `models/` | Pydantic request/response models for users and peers (see `models/AGENTS.md`) |
| `node/` | Master/node clustering: event bus, notifier, node-side agent (see `node/AGENTS.md`) |
| `static/` | CSS design system, vanilla JS, images (see `static/AGENTS.md`) |
| `tasks/` | Scheduled/background jobs registered with the scheduler (see `tasks/AGENTS.md`) |
| `templates/` | Jinja2 templates for the UI (see `templates/AGENTS.md`) |
| `utils/` | Cross-cutting helpers: config, version, rate limiting, scheduler, request ID, subprocess, migration, etc. (see `utils/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- The header block under `app/` is `#!/usr/bin/env python3`, `#`, `# app/<path>.py`, `# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates`, `#` (see `main.py`); tabs and `ruff format` as in the root `AGENTS.md`. This applies to every package below `app/`.
- Routers are mounted only in `main.py`; a new router module must be added to the `include_router` block there with the right prefix (note `speedtest_api` shares `/api/wireguard`).
- `main.py` assumes a single uvicorn worker (in-process MFA/recovery caches, application lock); do not introduce multi-worker assumptions.

### Testing Requirements
- `pytest` as in `tests/AGENTS.md`; `python -c 'import app.main'` is a quick import sanity check.
- Startup changes: verify `python -m app.server` boots (requires `WIREBUDDY_SECRET_KEY`).

### Common Patterns
- Startup lifecycle and the application lock belong in `main.py`; logging is configured by `utils/logging_setup.py` over `gillbates-logging`.
- Blocking work (SQLite, subprocess, TSDB) is run via `asyncio.to_thread` / `run_in_threadpool`; keep the event loop free.
- Lifespan wiring uses helpers prefixed `_` in `main.py`; heavy startup data loads are `*_sync` functions run in a thread.

## Dependencies

### Internal
- `app/api`, `app/db`, `app/dns`, `app/middleware`, `app/models`, `app/node`, `app/tasks`, `app/utils`.

### External
- `gillbates-country-flags`, `gillbates-geoip`, `gillbates-logging`, `gillbates-public-ip`, `gillbates-shutdown-handler`, `gillbates-speedtest` (private shared packages), FastAPI, Starlette, uvicorn, Jinja2 (rate limiting is the in-tree `utils.rate_limit`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
