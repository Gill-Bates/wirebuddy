<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# development

## Purpose
Developer-facing documentation: system architecture, local development environment, contribution rules and the planned migration of `app/main.py` into the modular `runtime/` package.

## Key Files
| File | Description |
|------|-------------|
| `architecture.md` | High-level and multi-node architecture, technology stack, application structure with code excerpts (`app/main.py`, static files, templates, routers) |
| `setup.md` | Prerequisites, cloning, Python environment (editable install with dev extras: pytest, ruff), required and development configuration, dev database |
| `contributing.md` | Code of conduct, how to contribute, code style (typing conventions), running tests (all / specific file) |
| `runtime-migration.md` | Incremental migration plan from the monolithic `main.py` (app factory, lifespan phases, DNS/WireGuard/scheduler startup, signal handling, shutdown) to a thin orchestrator plus `app/runtime/` modules; phases, benefits, future endpoints |

## For AI Agents

### Working In This Directory
- Keep `architecture.md` and `runtime-migration.md` aligned with the real layout of `app/` (check `app/AGENTS.md`); mark migration status accurately, since these describe a moving target.
- Setup steps must not embed credentials (dev secrets belong in a local `.env`).

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict`; commands documented here (`pytest`, `ruff`) should actually run.

### Common Patterns
- Long-form guides with fenced Python/shell snippets and directory trees.

## Dependencies

### Internal
- `app/`, `tests/`, `pyproject.toml`, `../features/multi-node.md`.

### External
- pytest, ruff, uvicorn/FastAPI as referenced in the guides.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
