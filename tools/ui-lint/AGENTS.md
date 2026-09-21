<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# ui-lint

## Purpose

Playwright-based UI lint tool for the WireBuddy web frontend. `run-ui-lint.mjs` logs into a running instance, walks a matrix of views x devices x browsers (chromium/webkit/firefox), runs the registered lint rules and audits (axe, performance, fonts, console/network, screenshot diffs), then writes findings and a health score to an output directory. It is configured through `UI_LINT_*` environment variables and is a private ES-module package (`wirebuddy-ui-lint`).

## Key Files

| File | Description |
|---|---|
| `run-ui-lint.mjs` | Large (~5.2k lines) CLI entry point: builds the audit plan, launches browsers, logs in, runs per-view checks and rules, emits findings/summary; optional health gate via `UI_LINT_HEALTH_MIN` |
| `package.json` | Package manifest; scripts `audit`, `install:browsers`, `test`, `test:headed`, `test:ui`, `report`; deps include playwright test, axe-core, postcss, pixelmatch, pngjs, ssim.js |
| `package-lock.json` | Locked dependency tree (generated; do not hand-edit) |

## Subdirectories

| Directory | Purpose |
|---|---|
| `lib/` | Runtime, config, token, findings, DOM-snapshot, device and orchestration modules (see `lib/AGENTS.md`) |
| `rules/` | Registered lint rules grouped by category plus manifest/loader (see `rules/AGENTS.md`) |
| `tests/` | Playwright specs for rules and lib modules (see `tests/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- Run an audit: `cd tools/ui-lint && npm install && npm run install:browsers && UI_LINT_USERNAME=... UI_LINT_PASSWORD=... npm run audit`. Credentials come only from the environment; never hard-code them.
- Env vars read by `run-ui-lint.mjs`: `UI_LINT_BASE_URL` (default `http://localhost:8000`), `UI_LINT_USERNAME`, `UI_LINT_PASSWORD`, `UI_LINT_BROWSERS`, `UI_LINT_BROWSER_CONCURRENCY`, `UI_LINT_DEVICE_CONCURRENCY`, `UI_LINT_OUTPUT_DIR`, `UI_LINT_SCREENSHOT_DIR`, `UI_LINT_SPOOF_CLIENT_IP`, `UI_LINT_LOGIN_FAILURE_TESTS`, `UI_LINT_LOGIN_FAILURE_USERNAME`, `UI_LINT_HEALTH_MIN`.
- `run-ui-lint.mjs` consumes `lib/` only through facades (`constants`, `browser-utils`, `findings`, `runtime-config`, `views`, `orchestration/audit-runner`, `dom-health`, `ui-health-score`); keep those export surfaces stable.
- New checks belong in `rules/` (register in `rules/manifest.mjs`), not inline in the entry point, unless they are page-flow checks that already live there.

### Testing Requirements

- `npm test` runs the Playwright specs in `tests/` (`test:headed` / `test:ui` for debugging). No `playwright.config` exists, so defaults apply; specs mount static HTML via `page.setContent`, so no running app is needed for most of them (`tests/runtime/dom-runtime.spec.js` loads scripts from `/opt/wirebuddy/app/static/js`).
- Full audits need a running WireBuddy instance and valid credentials.

### Common Patterns

- ES modules only (`.mjs`); files carry a `//` header with the path and copyright.
- Facade modules (`lib/constants.mjs`, `lib/browser-utils.mjs`, ...) re-export from modular subdirectories for backwards compatibility.
- Rule and policy thresholds are resolved from design tokens parsed out of the app's CSS (see `lib/design-tokens/`).

## Dependencies

### Internal

- `lib/`, `rules/`, `tests/`, `/opt/wirebuddy/app/static` (CSS tokens and JS parsed/loaded at runtime)

### External

- `playwright` / `@playwright/test`, `@axe-core/playwright`, `postcss`, `pixelmatch`, `pngjs`, `ssim.js`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
