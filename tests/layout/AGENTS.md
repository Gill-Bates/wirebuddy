<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-11-22 | Updated: 2026-11-22 -->
# layout

## Purpose
Playwright regression suite for the rendered UI: every page, in a viewport and theme matrix, must load without page, console or CSP errors, without 429/5xx responses and without unintended horizontal overflow; navigation, theme toggle, login/logout, the add-user and onboarding modals work; axe-core finds no serious violation. It runs the real app through `tests/e2e/run_server.py` with a throwaway data directory and random credentials, one instance per Playwright worker. Playwright is a repository-local install (`package.json`, `package-lock.json`, `npm ci`), not the host toolset used by `tests/e2e/`. Not collected by pytest. CI job: `layout` in `.github/workflows/ci.yml`.

## Key Files
| File | Description |
|------|-------------|
| `playwright.config.mjs` | Projects per engine (`chromium`; `webkit` runs only `@mobile` cells; `firefox` skips `@device`; `a11y.spec.mjs` runs in Chromium only), `forbidOnly`, `retries: 0`, traces/screenshots on failure, validated `WIREBUDDY_LAYOUT_*` variables |
| `harness.mjs` | `startApp()`/`login()`, the page catalogue `PAGES`, `VIEWPORTS`/`themesFor()` per profile, `openPage()`/`waitSettled()`, `collectPageErrors()`, the overflow audit (`auditPage()`, `ALLOWED_SCROLL_X`), `auditSelfTest()`, and the reasoned allow-lists `EXPECTED_CONSOLE` and `KNOWN_AXE` plus the two WebKit engine quirks tolerated in `collectPageErrors()` |
| `fixtures.mjs` | Worker-scoped `app` and `adminState` (one login per worker, in-memory storage state, onboarding modal dismissed through the UI), test fixture `openContext(options, { admin, fresh })` |
| `run.mjs` | Entry point (`npm run test:layout --`): `--profile quick|full`, `--browsers`, `--pages`, `--viewports`, `--self-test`, `-- <playwright args>` |
| `layout.spec.mjs` | Audit self-test (`@audit-self-test`) and one smoke test per page x viewport x theme (`@layout`) |
| `navigation.spec.mjs` | Desktop sidebar, mobile menu, three-state theme toggle (`@nav`) |
| `auth.spec.mjs` | Wrong login, login/logout, no password or secret key in the server log; runs on its own instance (`@auth`) |
| `modal.spec.mjs` | Add-user modal (button, Escape, scroll lock) and first-visit onboarding modal (`@modal`) |
| `a11y.spec.mjs` | axe-core (wcag2a, wcag2aa) once per page at 1280x720 light; serious and critical findings fail (`@a11y`) |

## For AI Agents

### Working In This Directory
- `.mjs` files carry the `//` path/copyright header and use 4-space indentation, like `tests/e2e/`.
- Tags: `@layout` selects the suite (the CI default), `@mobile` marks the cells WebKit also runs, `@device` marks device-descriptor cells (no Firefox), `@audit-self-test` is the mandatory self-test and deliberately carries no `@layout`.
- Never `waitForTimeout`, never raise a timeout or add a retry to turn a run green, no `test.skip`. Wait on state: web-first assertions, `expect.poll`, `waitForFunction`. Transitions (Bootstrap collapse and modal) are waited on through their classes or focus, because Bootstrap ignores input during a transition.
- Every allow-list entry (`EXPECTED_CONSOLE`, `KNOWN_AXE`, `ALLOWED_SCROLL_X`, the WebKit quirks) needs a reason and stays as narrow as the observed message or node. The overflow audit also reports elements clipped by an ancestor that reaches the viewport edge (the app shell hides overflow), so a wide element cannot hide behind `overflow-x: hidden`.
- The status page is disabled by default and answers 404 with its own page; the suite checks that state and never enables it (enabling it makes the app probe the outbound network). No test creates WireGuard interfaces or peers.
- Add a page: one entry in `PAGES` (id, path, `auth`, `status`, `landmark`). Add a viewport: one entry in `VIEWPORTS.quick` or `.full`; `tablet`, `phone` and device entries run in WebKit too.
- Credentials are random per instance and only travel through the child's environment. Traces and screenshots can contain the throwaway instance's login password; they die with the instance.
- The login limit (5/minute) and the 60/minute route limit are per instance: shared tests log in once per worker, `auth.spec.mjs` has its own instance, and any 429 response fails the test instead of flaking.

### Testing Requirements
- Setup once: `npm ci`, then `npx playwright install chromium webkit firefox` (add `--with-deps` on a CI runner or a fresh host).
- PR profile: `WIREBUDDY_LAYOUT_BROWSERS=chromium,webkit node tests/layout/run.mjs --profile quick` (about 3 minutes with 2 workers); `--browsers chromium,webkit` is the same. Full matrix: `--profile full --browsers chromium,webkit,firefox`. Self-test: `node tests/layout/run.mjs --self-test --browsers chromium,webkit`. Selection check: `node tests/layout/run.mjs --browsers webkit -- --list`.
- Environment: `WIREBUDDY_LAYOUT_PROFILE`, `_BROWSERS`, `_PAGES`, `_VIEWPORTS`, `_WORKERS` (default `min(2, cpus)`, CI 2), `_OUTPUT` (traces, screenshots), `_JUNIT`, `_LOGS` (server logs), `_PYTHON` (default `.venv/bin/python`). Invalid values fail the run.
- No resource limiter wraps the run; keep it at 2 workers unless the host is idle.
- Prove a change to the audit by injecting a defect in a scratch copy of the repository (for example `.main-content { min-width: 2400px; }` in `app/static/css/style.css`); the suite must fail there.

## Dependencies

### Internal
- `../e2e/run_server.py`, `../../tools/ci-seed-admin.py`, `../../app/` (templates, static assets).

### External
- `@playwright/test` and `playwright` 1.64.1, `@axe-core/playwright` 4.14.0 (exact pins in `package.json`), Node.js 24, the repository venv (Python 3.14, runtime dependencies), `wg`, `wg-quick` and `ip` at their trusted absolute paths, or `WIREBUDDY_SKIP_NETWORK_CHECK=1` where `wireguard-tools` is not installed (as in CI).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
