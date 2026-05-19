# Runtime Architecture Migration Guide

## Overview

This document describes the incremental migration from the monolithic `main.py` kernel to the modular `runtime/` package architecture.

## Current State (main.py)

The current `main.py` combines:
- Application factory (`create_app()`)
- Lifecycle orchestration (`_lifespan()`, `LifespanContext`)
- Bootstrap (`_bootstrap_sync()`, `_phase_bootstrap()`)
- DNS runtime (`_phase_dns_config()`, `_phase_dns_start()`, `_phase_dns_ingestion()`)
- WireGuard runtime (`_phase_wireguard_start()`)
- Scheduler (`_phase_scheduler()`)
- Signal handling (`_install_shutdown_signal_handlers()`)
- Logging (`_setup_logging()`)
- Shutdown coordination (`_do_shutdown()`)

## Target Architecture

```
app/
├── main.py                    # Thin orchestrator only
└── runtime/
    ├── __init__.py            # Package exports
    ├── service.py             # RuntimeService base class
    ├── container.py           # ServiceContainer (DI)
    ├── lifecycle.py           # LifecycleManager
    ├── signals.py             # SignalManager
    ├── logging.py             # Logging setup
    └── services/
        ├── __init__.py
        ├── sqlite.py          # Database lifecycle
        ├── dns.py             # DNS + Unbound supervision
        ├── wireguard.py       # Interface management
        ├── tsdb.py            # Time-series storage
        └── scheduler.py       # Background task coordination
```

## Migration Phases

### Phase 1: Foundation (COMPLETED)

Created the runtime package structure with:
- `RuntimeService` base class with lifecycle hooks
- `ServiceContainer` for dependency injection
- `LifecycleManager` for startup/shutdown coordination
- `SignalManager` for graceful shutdown signals
- `SQLiteService` as reference implementation

### Phase 2: Parallel Operation

The next step is to run both architectures in parallel:

```python
# main.py - transitional
from app.runtime import LifecycleManager
from app.runtime.services import SQLiteService

lifecycle = LifecycleManager(cfg)
lifecycle.register_service(SQLiteService(cfg))

@asynccontextmanager
async def _lifespan(app: FastAPI):
    async with lifecycle.managed(app):
        # Legacy phases still run here during migration
        await _phase_dns_config(ctx)
        await _phase_wireguard_start(ctx)
        ...
        yield
```

### Phase 3: Service Extraction

Extract each domain into a RuntimeService:

#### 3.1 DNSService

```python
class DNSService(RuntimeService):
    name = "dns"
    dependencies = ["sqlite", "wireguard"]  # Needs interfaces to bind to

    async def _do_start(self):
        # From _phase_dns_config() and _phase_dns_start()
        await self._write_config()
        await self._start_unbound()
        self.create_background_task(self._run_ingestion())

    async def _do_stop(self):
        # Stop ingestion task (handled by base class)
        await self._stop_unbound()
```

#### 3.2 WireGuardService

```python
class WireGuardService(RuntimeService):
    name = "wireguard"
    dependencies = ["sqlite"]

    async def _do_start(self):
        # From _phase_wireguard_start()
        await self._cleanup_stale_interfaces()
        await self._start_enabled_interfaces()

    async def _do_stop(self):
        for iface in self._started_interfaces:
            await self._stop_interface(iface)
```

#### 3.3 TSDBService

```python
class TSDBService(RuntimeService):
    name = "tsdb"
    dependencies = []  # Standalone

    async def _do_start(self):
        await asyncio.to_thread(tsdb.init_tsdb, self._config.tsdb_dir)

    async def _do_stop(self):
        stats = tsdb.finalize_shutdown(self._config.tsdb_dir)
        _log.info("TSDB_SHUTDOWN %s", stats)
```

#### 3.4 SchedulerService

```python
class SchedulerService(RuntimeService):
    name = "scheduler"
    dependencies = ["sqlite", "tsdb"]  # Needs DB and metrics storage

    async def _do_start(self):
        self._scheduler = Scheduler()
        await register_all_tasks(self._scheduler, self._container)
        await self._scheduler.start()

    async def _do_stop(self):
        await self._scheduler.stop_graceful(timeout=5.0)
```

### Phase 4: Final main.py

After all services are extracted:

```python
# main.py - final form

from app.runtime import LifecycleManager
from app.runtime.logging import setup_logging
from app.runtime.services import (
    SQLiteService,
    DNSService,
    WireGuardService,
    TSDBService,
    SchedulerService,
)

def create_app() -> FastAPI:
    print_banner_once()
    cfg = load_config()
    setup_logging(cfg.log_level)

    lifecycle = LifecycleManager(cfg)

    # Register services in dependency order (container handles actual ordering)
    lifecycle.register_service(SQLiteService(cfg))
    lifecycle.register_service(TSDBService(cfg))
    lifecycle.register_service(WireGuardService(cfg))
    lifecycle.register_service(DNSService(cfg))
    lifecycle.register_service(SchedulerService(cfg))

    app = FastAPI(
        title="WireBuddy",
        version=VERSION,
        lifespan=lifecycle.lifespan,  # Delegate entirely
    )

    # Wire routes and middleware
    _configure_middleware(app)
    _register_routes(app)

    return app
```

## Benefits

1. **Testability**: Each service can be unit tested in isolation
2. **Observability**: Service health exposed via `container.check_health()`
3. **Maintainability**: Domain logic contained in single files
4. **Extensibility**: New services follow established pattern
5. **Reliability**: Dependency-aware startup/shutdown ordering

## API Endpoints (Future)

The container enables runtime introspection:

```python
@app.get("/api/runtime/health")
async def runtime_health(services = Depends(get_services)):
    return await services.check_health()

@app.get("/api/runtime/services")
async def list_services(services = Depends(get_services)):
    return services.get_service_states()
```

## Backward Compatibility

During migration:
- `app.state.shutdown_signal_event` remains available
- `app.state.scheduler` accessible via `app.state.services["scheduler"]`
- Legacy `LifespanContext` fields available in `LifecycleContext`
