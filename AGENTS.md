<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->

# WireBuddy

## Purpose
WireBuddy is a self-hosted WireGuard management platform ("Use WireGuard with ease!"). It is a FastAPI application (Python 3.14, MIT) with a server-rendered Bootstrap 5 UI. It manages multiple WireGuard interfaces and peers, provides an integrated Unbound DNS ad-blocker (blocklists, DoT, DNSSEC, query log), multi-node clustering, a built-in time-series DB for traffic metrics, GeoIP/ASN analysis, HTTPS/Let's Encrypt handling, and multi-user auth (roles, passkeys, TOTP). It ships as a Docker image (linux/amd64, linux/arm64).

## Key Files
| File | Description |
|------|-------------|
| `pyproject.toml` | Single source of truth for the release version and Python dependencies (runtime + `dev`/`docs` extras); also read by the Docker build. It pins six private `gillbates-*` packages (`country-flags`, `geoip`, `logging`, `public-ip`, `shutdown-handler`, `speedtest`) by git tag from `Gill-Bates/python-libraries`; installing needs git plus a token (`RELEASE_TOKEN` in CI, BuildKit secret `python_libraries_token` in `docker build`; local dev: `pip install -e /opt/python-libraries/packages/<dir>`) |
| `package.json`, `package-lock.json` | Repository-local Playwright install for the browser regression suite `tests/layout/` (exact pins, `npm ci`) and the scripts `test:layout` and `test:js`; nothing here is shipped, `node_modules/` is git-ignored |
| `.env-example` | Template for the git-ignored `.env` that Docker Compose reads (`cp .env-example .env`) |
| `zensical.toml` | Zensical config of the documentation site built from `docs/` (see `docs/AGENTS.md`) |
| `.dockerignore` | Keeps local state, caches and `.git/` out of the image build context; the Dockerfile's `COPY app ./app` relies on it |
| `setup.conf` | Personal dev/deploy cheat sheet (venv setup, dev server, docker buildx). Tracked in git on purpose; never add it to `.gitignore`. May contain secrets/credentials: never copy its values into docs, commits or output |
| `.trivyignore` | Trivy exceptions for all four scans: source secrets (`ci.yml`), image (`docker-build.yml`), weekly rescan (`security.yml`) and docs dependencies (`docs-build.yml`); each entry needs a reason and an `exp:` date (file kept even when empty) |
| `Caddyfile` | Example Caddy reverse proxy for a deployment behind `localhost:8000`; its `request_body max_size` matches the 1 GiB restore limit. `docs/getting-started/installation.md` reproduces it, so change both together |
| `CHANGELOG.md` | Release notes; update for user-visible changes |
| `README.md` | Public project overview and feature list |
| `LICENSE` | MIT |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `app/` | The application: API, DB layer, DNS, node sync, scheduled tasks, UI assets (see `app/AGENTS.md`) |
| `docker/` | Dockerfile, entrypoint and compose files (see `docker/AGENTS.md`) |
| `docs/` | User/developer documentation site sources (see `docs/AGENTS.md`) |
| `tests/` | pytest suite for the backend, the `tests/layout/` Playwright regression suite (runs in CI) and the `tests/e2e/` browser drivers (see `tests/AGENTS.md`) |
| `tools/` | Developer tooling: the Playwright-based UI linter, a standalone Stylelint setup for the CSS, plus two helpers, `pyproject-deps.py` (CI) and `ci-seed-admin.py` (local audit seeding) (see `tools/AGENTS.md`) |
| `.github/` | CI workflows (PR gate, release, weekly image rescan, docs), their tested helper scripts, Renovate/actionlint/zizmor config and README images (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Python files are indented with **tabs** and start with the standard header block (file path, copyright; no SPDX line); keep that style. `ruff format` (`indent-style = "tab"`, line length 160, double quotes) produces exactly this layout and the tree is formatted with it; never re-indent with spaces.
- Persistent data lives in `data/` (SQLite + TSDB, git-ignored). Never commit `*.db`, `*.mmdb`, `.env` or `BUILD_INFO`.
- Backup/restore (format v2) includes schema **and** configuration (+ optional TSDB metrics); an empty restore is a bug.
- Do not add Claude co-author / "Generated with Claude Code" attribution to commits or PR descriptions.
- WireBuddy is run in Docker; for a local start inside the venv use `python -m app.server` (see `setup.conf`), which requires an exported `WIREBUDDY_SECRET_KEY` (a `.env` file is not loaded).

### Testing Requirements
- Backend: `pytest` from the repo root (tests in `tests/`). Gated on every PR by `.github/workflows/ci.yml`.
- Lint: `ruff check .`; format: `ruff format .`, checked by `ruff format --check .` in CI. The **full** configured rule set gates every PR and the tree is at zero findings. Deliberate exemptions live in `pyproject.toml` with the reasoning beside each one; narrower cases carry a per-line `# noqa` naming the reason. Fix rather than exempt, and if a rule genuinely does not apply, annotate the line instead of widening the ignore list.
- Browser formatting (`app/static/js/core/format.js`, locale and time zone): `npm run test:js` (`node --test "tests/js/*.test.mjs"`, Node built-ins only, no `npm ci`); gated on every push and PR by the `manifest` job of `ci.yml`.
- Container: the PR checks of `docker/` are listed in `docker/AGENTS.md`; they gate in `ci.yml` because `docker-build.yml` builds the image only from a version tag.
- Frontend/UI (preferred): browser checks run against an isolated throwaway instance with the central toolset, `PLAYWRIGHT_DIR=/opt/ux-test-tools PYTHON=.venv/bin/python node tests/e2e/<driver>.mjs <artifact-dir>` (`ui_lint_isolated.mjs`, `live_resize.mjs`, `ios_viewport_audit.mjs`; `PLAYWRIGHT_BROWSER`/`COLOR_SCHEME` select the matrix cell). See `tests/e2e/AGENTS.md`. Drivers are not part of `pytest`.
- Frontend/UI (manual): the Playwright audit in `tools/ui-lint/` needs a running instance and `UI_LINT_USERNAME`/`UI_LINT_PASSWORD` from the environment (`run-ui-lint.mjs` aborts if either is unset; never hard-code them); commands and the `UI_LINT_*` list are in `tools/ui-lint/AGENTS.md`. On a fresh database seed the account first with `tools/ci-seed-admin.py`, or the first-boot bootstrap gate leaves every view unreachable — `tools/AGENTS.md` has the full recipe. The `tools/ui-lint` audit and the `tests/e2e` drivers run only locally.
- Frontend/UI (regression suite): `tests/layout/` is the Playwright suite that CI runs (job `layout` in `ci.yml`, see `tests/layout/AGENTS.md`). Setup `npm ci && npx playwright install chromium webkit firefox`; PR profile `node tests/layout/run.mjs --profile quick --browsers chromium,webkit`; full matrix `--profile full --browsers chromium,webkit,firefox`; self-test `node tests/layout/run.mjs --self-test`. `WIREBUDDY_LAYOUT_WORKERS` sets the worker count (CI: 2). Pull requests from forks have no `RELEASE_TOKEN`, so the job cannot install the private `gillbates-*` packages there; `pull_request_target` is deliberately not used.

### Common Patterns
- FastAPI routers in `app/api/`, data access in `app/db/sqlite_*.py`, cross-cutting helpers in `app/utils/`, background jobs in `app/tasks/`.
- Jinja2 templates in `app/templates/`, static assets (CSS design system, vanilla JS) in `app/static/`.

## Dependencies

### Internal
- `app/` is the only runtime package; `docker/` packages it, `tests/` and `tools/` verify it.

### External
- FastAPI + uvicorn, SQLite, Unbound, WireGuard tools, MaxMind GeoLite2, Bootstrap 5, Leaflet, Playwright (`tools/ui-lint/` and the `tests/e2e/` drivers only).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
