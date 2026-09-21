<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime

## Purpose
Application kernel infrastructure: a dependency-aware service container, the `RuntimeService` base class and health types, startup/shutdown lifecycle coordination, signal handling that cooperates with Uvicorn, and unified logging setup. Concrete services (SQLite, DNS, WireGuard, TSDB, scheduler) live in `services/`.

## Key Files
| File | Description |
|------|-------------|
| `service.py` | `ServiceState`, `ServiceHealth` and the `RuntimeService` base class (`name`, `dependencies`, start/stop/health lifecycle) |
| `container.py` | `ServiceContainer`: registers services, topologically sorts by `dependencies`, starts independent services in parallel, aggregates `ContainerHealth`, coordinates shutdown |
| `lifecycle.py` | `LifecycleContext` and `LifecycleManager`: ordered startup and shutdown phases across services |
| `signals.py` | `SignalManager`: installs/restores signal handlers preserving Uvicorn's, and sets a shutdown event for long-lived connections (SSE, WebSockets) |
| `logging.py` | `setup_logging`, `ColoredFormatter` (TTY level colours) and `HumanizedFormatter` (rewrites noisy aiosqlite debug messages) |
| `__init__.py` | Package docstring describing the layers (web, control plane, data plane) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `services/` | Concrete `RuntimeService` implementations; see `services/AGENTS.md` |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- A service declares its `name` and `dependencies` (tuple of service names); unknown dependencies raise at start. Avoid dependency cycles.
- Shutdown must be graceful and idempotent; do not replace Uvicorn's signal handlers, only chain to them.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). No dedicated runtime tests exist yet; add async tests for ordering, health aggregation and failure handling when changing the container.

### Common Patterns
- Async lifecycle with explicit state enum and health reporting; structured log tags such as `SERVICE_REGISTERED name=... dependencies=...`.
- Classes are wired up in the FastAPI lifespan in `app/main.py`.

## Dependencies

### Internal
- `app/utils/config` (logging and config); `services/` subclasses `service.RuntimeService`.

### External
- stdlib `asyncio`, `signal`, `logging`; `fastapi` (lifespan typing).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
