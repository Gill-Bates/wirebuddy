<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# tools

## Purpose

Container for developer tooling that is not part of the WireBuddy application runtime: two small Python helpers used by CI, and `ui-lint`, a Node/Playwright-based UI linter that audits the running web frontend (layout, accessibility, overflow, tokens, console/network health).

## Key Files

| File | Purpose |
|---|---|
| `pyproject-deps.py` | Prints one dependency group from `pyproject.toml` as a flat pip requirements list (`dev`, `docs`, or the runtime set when no group is given; `--exclude NAME` is repeatable). Exists because pip's `-r` and Trivy's filesystem scanner still want a flat file, and because the same list was previously inlined as a `tomllib` one-liner in several workflow steps. Standard library only |
| `ci-seed-admin.py` | Creates a ready-to-use admin in a **fresh** database so the UI audit can log in. Run it *before* the server starts: a pre-existing user makes `ensure_default_admin()` a no-op, which is what keeps the first-boot bootstrap gate closed. Refuses to run against a database that already has admins or a mismatched secret key. CI only |

## Subdirectories

| Directory | Purpose |
|---|---|
| `ui-lint/` | Playwright-based UI lint tool: `run-ui-lint.mjs` entry point, `lib/` runtime modules, `rules/` lint rules, `tests/` Playwright specs (see `ui-lint/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- Node tools here are standalone projects with their own `package.json` and `node_modules`; they are not imported by the FastAPI app under `app/`.
- Never descend into or edit `node_modules/`.
- The Python helpers follow the app's conventions: tabs, the standard header block (path, copyright, SPDX `MIT`), standard library only where possible. `pyproject.toml` relaxes `T20` for `tools/*.py`, so printing to stdout is expected here — that is their interface.
- `ci-seed-admin.py` imports from `app/`, so it inserts the repo root on `sys.path` (`tools/` is not a package). It takes the password from an environment variable, never an argument, so it does not appear in the process list.
- The root `AGENTS.md` points frontend/UI verification at `node tools/ui-lint/run-ui-lint.mjs`.

### Testing Requirements

- Each Node tool documents its own test command; see `ui-lint/AGENTS.md`. Python tests live in `/opt/wirebuddy/tests`, not here.
- The Python helpers are covered by `ruff check .` and exercised on every CI run; there are no unit tests for them.
- Reproduce a full UI audit locally:

  ```bash
  export WIREBUDDY_SECRET_KEY="$(python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
  export WIREBUDDY_DATA_DIR=/tmp/wb-audit UI_LINT_PASSWORD='Choose!APassword1'
  mkdir -p "$WIREBUDDY_DATA_DIR"
  python tools/ci-seed-admin.py --gui-port 8099   # before starting the server
  python run.py &                                 # reads the port from the settings table
  UI_LINT_BASE_URL=http://127.0.0.1:8099 UI_LINT_USERNAME=admin \
    UI_LINT_OUTPUT_DIR=/tmp/ui-audit-out npm --prefix tools/ui-lint run audit
  ```

  `run.py` honours no `HOST`/`PORT`; the listener comes from the `settings` table, which is why the port is passed to the seeding step.

### Common Patterns

- Add a new Node tool as a sibling directory with its own `package.json`; keep it independent of `app/`.
- Keep CI-only Python helpers here rather than inlining them into workflow steps: a file can be linted, read in review and run locally.

## Dependencies

### Internal

- `app/` (the frontend under test is served by the WireBuddy app at runtime; `ci-seed-admin.py` does import `app.db` and `app.utils.config`)
- `../pyproject.toml` — the dependency and version source `pyproject-deps.py` reads
- `../.github/workflows/` — `ci.yml`, `docs-build.yml` and `ui-audit.yml` are the callers of both Python helpers

### External

- Node.js (ES modules), Playwright; Python 3.13 standard library for `pyproject-deps.py`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
