<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# WireBuddy

## Purpose
WireBuddy is a self-hosted WireGuard management platform ("Use WireGuard with ease!"). It is a FastAPI application (Python 3.13, MIT) with a server-rendered Bootstrap 5 UI. It manages multiple WireGuard interfaces and peers, provides an integrated Unbound DNS ad-blocker (blocklists, DoT, DNSSEC, query log), multi-node clustering, a built-in time-series DB for traffic metrics, GeoIP/ASN analysis, HTTPS/Let's Encrypt handling, and multi-user auth (roles, passkeys, TOTP). It ships as a Docker image (linux/amd64, linux/arm64).

## Key Files
| File | Description |
|------|-------------|
| `run.py` | Dev/production entry point: loads `.env`, config, initialises the DB schema, starts uvicorn |
| `pyproject.toml` | Single source of truth for the release version and Python dependencies (runtime + `dev`/`docs` extras); also read by the Docker build |
| `setup.conf` | Personal dev/deploy cheat sheet (venv setup, dev server, docker buildx). Contains secrets/credentials: never copy its values into docs, commits or output |
| `Caddyfile` | Reverse-proxy/HTTPS configuration |
| `CHANGELOG.md` | Release notes; update for user-visible changes |
| `README.md` | Public project overview and feature list |
| `LICENSE` | MIT |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `app/` | The application: API, DB layer, DNS, node sync, runtime services, UI assets (see `app/AGENTS.md`) |
| `docker/` | Dockerfile, entrypoint and compose files (see `docker/AGENTS.md`) |
| `docs/` | User/developer documentation site sources (see `docs/AGENTS.md`) |
| `tests/` | pytest suite for the backend (see `tests/AGENTS.md`) |
| `tools/` | Developer tooling: the Playwright-based UI linter plus two CI helpers, `pyproject-deps.py` and `ci-seed-admin.py` (see `tools/AGENTS.md`) |
| `.github/` | CI workflows (PR gate, release, docs, UI audit), screenshots and agent prompt files (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Python files are indented with **tabs** and start with the standard header block (file path, copyright, SPDX `MIT`); keep that style.
- Persistent data lives in `data/` (SQLite + TSDB, git-ignored). Never commit `*.db`, `*.mmdb`, `.env` or `BUILD_INFO`.
- Backup/restore (v2, since 1.5.2) includes schema **and** configuration (+ optional TSDB metrics); an empty restore is a bug.
- Do not add Claude co-author / "Generated with Claude Code" attribution to commits or PR descriptions (user preference).
- Start the dev server with `python run.py` inside the venv (see `setup.conf` for the exact steps); requires `WIREBUDDY_SECRET_KEY`.

### Testing Requirements
- Backend: `pytest` from the repo root (tests in `tests/`). Gated on every PR by `.github/workflows/ci.yml`.
- Lint: `ruff check .`. The **full** configured rule set gates every PR and the tree is at zero findings. Deliberate exemptions live in `pyproject.toml` with the reasoning beside each one; narrower cases carry a per-line `# noqa` naming the reason. Fix rather than exempt, and if a rule genuinely does not apply, annotate the line instead of widening the ignore list.
- Container: `bash -n docker/entrypoint.sh` and `docker build --check -f docker/Dockerfile .`. Both gate PRs, because the image itself is only built from a release tag.
- Frontend/UI: the Playwright audit needs a running instance, its own `npm install` and credentials from the environment — `cd tools/ui-lint && npm install && npm run install:browsers`, then `UI_LINT_USERNAME=... UI_LINT_PASSWORD=... npm run audit`. `run-ui-lint.mjs` aborts if either variable is unset; never hard-code them. On a fresh database seed the account first with `tools/ci-seed-admin.py`, or the first-boot bootstrap gate leaves every view unreachable — `tools/AGENTS.md` has the full recipe. See `tools/ui-lint/AGENTS.md` for the `UI_LINT_*` list. `.github/workflows/ui-audit.yml` runs this in CI but deliberately never blocks a PR.

### Common Patterns
- FastAPI routers in `app/api/`, data access in `app/db/sqlite_*.py`, cross-cutting helpers in `app/utils/`, background jobs in `app/tasks/` and `app/runtime/`.
- Jinja2 templates in `app/templates/`, static assets (CSS design system, vanilla JS) in `app/static/`.

## Dependencies

### Internal
- `app/` is the only runtime package; `docker/` packages it, `tests/` and `tools/` verify it.

### External
- FastAPI + uvicorn, SQLite, Unbound, WireGuard tools, MaxMind GeoLite2, Bootstrap 5, Leaflet, Playwright (ui-lint only).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
