<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# app

## Purpose
The `wirebuddy` Python package: a FastAPI application factory (`create_app` in `main.py`) that wires middleware, routers, the SQLite/TSDB layer, the Unbound DNS integration, node (master/node) synchronisation, background tasks and the server-rendered UI. `main.py` also owns the startup lifecycle (single-instance lock, stale interface cleanup, bootstrap, scheduler and shutdown signal handling), `/health`, `/ready` and the Swagger UI.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package docstring; exposes `create_app` lazily for `uvicorn app:create_app` |
| `main.py` | Application factory and lifespan: registers `TrustedHostMiddleware`, `RequestIDMiddleware`, `CSRFMiddleware`, mounts all routers (`/api/...`, `/api/wireguard`, `/api/dns`, `/api/nodes`, frontend pages), starts scheduler/DNS/tasks, log formatters, `/health`, `/ready`, `/swagger` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `api/` | HTTP routers (REST + UI pages), one module per feature (see `api/AGENTS.md`) |
| `db/` | SQLite access layer, schema/migrations and the JSONL time-series DB (see `db/AGENTS.md`) |
| `dns/` | Unbound config generation, process supervision, blocklists, custom rules, query-log ingestion (see `dns/AGENTS.md`) |
| `middleware/` | Starlette middleware (CSRF) (see `middleware/AGENTS.md`) |
| `models/` | Pydantic request/response models for users and peers (see `models/AGENTS.md`) |
| `node/` | Master/node clustering: event bus, notifier, node-side agent (see `node/AGENTS.md`) |
| `speedtest/` | Speedtest engine used by the API and scheduled tasks (see `speedtest/AGENTS.md`) |
| `static/` | CSS design system, vanilla JS, images (see `static/AGENTS.md`) |
| `tasks/` | Scheduled/background jobs registered with the scheduler (see `tasks/AGENTS.md`) |
| `templates/` | Jinja2 templates for the UI (see `templates/AGENTS.md`) |
| `utils/` | Cross-cutting helpers: config, version, rate limiting, scheduler, request ID, subprocess, migration, etc. (see `utils/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Routers are mounted only in `main.py`; a new router module must be added to the `include_router` block there with the right prefix (note `speedtest_api` shares `/api/wireguard`).
- `main.py` assumes a single uvicorn worker (in-process MFA/recovery caches, application lock); do not introduce multi-worker assumptions.
- Sub-directory documentation: see `api/AGENTS.md`, `db/AGENTS.md`, `dns/AGENTS.md`, `middleware/AGENTS.md`, `models/AGENTS.md`, `node/AGENTS.md`, `speedtest/AGENTS.md`, `static/AGENTS.md`, `tasks/AGENTS.md`, `templates/AGENTS.md`, `utils/AGENTS.md`.

### Testing Requirements
- Run `pytest` from the repo root (tests in `/opt/wirebuddy/tests`); `python -c 'import app.main'` is a quick import sanity check.
- Startup changes: verify `python run.py` boots (requires `WIREBUDDY_SECRET_KEY`).

### Common Patterns
- Blocking work (SQLite, subprocess, TSDB) is run via `asyncio.to_thread` / `run_in_threadpool`; keep the event loop free.
- Lifespan wiring uses helpers prefixed `_` in `main.py`; heavy startup data loads are `*_sync` functions run in a thread.

## Dependencies

### Internal
- `app/api`, `app/db`, `app/dns`, `app/middleware`, `app/models`, `app/node`, `app/tasks`, `app/utils`, `app/speedtest`.

### External
- FastAPI, Starlette, uvicorn, Jinja2, slowapi (via `utils.rate_limit`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
