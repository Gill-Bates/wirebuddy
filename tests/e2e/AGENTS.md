<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-27 | Updated: 2026-10-27 -->
# e2e

## Purpose
Browser E2E drivers for the WireBuddy UI, same conventions as rct-manager: one central toolset in `/opt/ux-test-tools` (playwright + @axe-core/playwright, no lockfile), every driver starts its own server on a free port with a throwaway data dir, and all artifacts go to the directory passed as `argv[2]`. Not part of pytest (`python_files = test_*.py` never matches `.mjs`), not run in CI.

## Key Files
| File | Description |
|------|-------------|
| `harness.mjs` | Shared setup: Playwright from `PLAYWRIGHT_DIR`, `PLAYWRIGHT_BROWSER`/`COLOR_SCHEME` matrix, `OUT`, `check()`/`results`, `freePort()`, `startServer()` (random credentials per run, waits for `/login`, asserts the bootstrap gate is closed), `login()`, `finish()`, child cleanup on exit/signals |
| `run_server.py` | Launcher: `E2E_ADMIN_PASSWORD=... python tests/e2e/run_server.py DATA_DIR PORT`. Refuses the real `data/`, generates `WIREBUDDY_SECRET_KEY` if unset, seeds the admin with `tools/ci-seed-admin.py` BEFORE the server starts (keeps the bootstrap gate closed), then runs `app.server.main(port=...)` |
| `live_resize.mjs` | Mid-session viewport resize (desktop, tablet, phone, back) without reload on dashboard, peers, dns, settings: no horizontal overflow, structure intact, no console errors |
| `ios_viewport_audit.mjs` | iOS failure classes over a device matrix (`DEVICES=` overrides): safe-area/`viewport-fit`, vh traps, scroll locks, <16px inputs, nested scrollers, overflow, 44px touch targets. Defaults to `PLAYWRIGHT_BROWSER=webkit` |
| `ui_lint_isolated.mjs` | Full `tools/ui-lint` audit against an isolated instance; `PLAYWRIGHT_BROWSER` maps onto `UI_LINT_BROWSERS` when unset, other `UI_LINT_*` pass through |

## For AI Agents

### Working In This Directory
- `.mjs` files carry the `//` path/copyright header and use 4-space indentation like `tools/ui-lint`; `run_server.py` follows the Python rules (tabs, header block).
- Run: `PLAYWRIGHT_DIR=/opt/ux-test-tools PYTHON=/opt/wirebuddy/.venv/bin/python PLAYWRIGHT_BROWSER=chromium COLOR_SCHEME=light node tests/e2e/live_resize.mjs "$(mktemp -d /tmp/wb-ux-e2e.XXXXXX)"`. Results are `PASS`/`FAIL` lines; the exit code is non-zero on any failure. Findings are real UI defects, not harness errors, unless a `driver ran to completion` check fails.
- `PLAYWRIGHT_BROWSER=chromium|webkit|firefox` selects the engine; any other explicit value fails fast (exit 2, valid values listed). The legacy `BROWSER` is honoured only when it names an engine, because desktops often export `BROWSER=xdg-open`; prefer `PLAYWRIGHT_BROWSER`. Pass an artifact dir outside the repo: `OUT` also receives the throwaway `data-*` dirs.
- Contrast: `ui-lint` already measures contrast (rules plus axe `color-contrast`), so rct-manager's `contrast_audit.mjs` and `axe_scan.mjs` are deliberately not ported.
- Never point a driver at `data/`; always artifact dirs below the OS temp dir, never inside the repo.

### Testing Requirements
- `node --check` every driver; run them manually as above.

## Dependencies
### Internal
- `../../tools/ci-seed-admin.py`, `../../tools/ui-lint/`, `../../app/server.py`
### External
- `/opt/ux-test-tools` (playwright), the repo venv

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
