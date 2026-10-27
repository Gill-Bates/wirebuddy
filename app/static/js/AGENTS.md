<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-10-27 -->
# js

## Purpose
First-party browser JavaScript, written as classic scripts (IIFEs attaching to `window`, e.g. `window.apiCall`, `window.WBShared`, `window.WBReconnect`, `window.WB`). `base.html` loads the shared runtime on every page in this order: `theme.js` (head), Bootstrap, `api.js`, `ui-state.js`, `core/design-tokens.js`, `core/dom.js`, `core/logger.js`, `core/format.js`, `components/retention-slider.js`, `modal.js`, `toast.js`, `reconnect.js`, `onboarding.js`, `base-ui.js`. Page controllers are added by each template's `extra_js` block.

## Key Files
| File | Description |
|------|-------------|
| `api.js` | Fetch wrapper `apiCall` (CSRF, error handling) used by every page |
| `theme.js` | Three-state theme (auto default, light, dark) with safe localStorage (iOS private mode); `data-bs-theme` carries the resolved value, `data-wb-theme-mode` the chosen mode; auto follows OS changes live |
| `ui-state.js` | show/hide/state helpers exposed on window |
| `modal.js`, `toast.js` | Modal and toast helpers |
| `reconnect.js` | `WBReconnect`: server-restart/connection-loss overlay and polling |
| `onboarding.js` | Lazy-loads `templates/fragments/onboarding_modal.html` |
| `base-ui.js` | Global shell behaviour (sidebar, reconnect failsafe) |
| `dashboard_traffic_shared.js` | `WBShared` helpers shared by dashboard, traffic, DNS and settings |
| `dashboard.js`, `traffic.js`, `peers.js`, `users.js`, `nodes.js`, `about.js` | Page controllers (dashboard, peers, nodes and traffic are 1400-2200 lines) |
| `dashboard_widgets.js` | Frozen dashboard widget registry (ids, labels, factory layout, order); browser global `WBDashboardRegistry` + Node `module.exports`. Mirrored by the Python allowlist in `app/api/dashboard_layout.py` (kept in sync by `tests/test_dashboard_widget_registry.py`) |
| `dashboard_grid.js` | GridStack layout layer for the dashboard: position/size/visibility and per-user layout persistence via `/api/dashboard/layout`. Owns no data (that stays in `dashboard.js`); loaded last on the dashboard |
| `dns-page.js` | DNS page controller, loaded by `dns.html` |
| `settings.js` | Monolithic Settings controller (`window.WBSettings`), loaded by `settings.html` together with `settings/components.js` and `settings/speedtest.js` |
| `login.js`, `mfa.js`, `passkeys.js`, `otp-setup.js`, `passkey-setup.js`, `change-password.js` | Auth flows: login, TOTP/MFA, WebAuthn passkeys, forced setup pages |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `core/` | Runtime infrastructure (DOM builder, tokens, logger); see `core/AGENTS.md` |
| `components/` | Reusable widgets; see `components/AGENTS.md` |
| `settings/` | Settings sub-modules; see `settings/AGENTS.md` |

## For AI Agents
### Working In This Directory
- No imports/exports: expose APIs on `window` and add a `<script>` tag in the right template. Order matters (dependencies first).
- Build DOM with `el()` from `core/dom.js` or `textContent`; escape any HTML string interpolation (XSS). Client-side checks are UX only; the backend enforces authorization.
- Call the backend through `apiCall`, log through `WBLogger`, read colours from `DesignTokens`.
- Toggle visibility with classes (`is-hidden`/`d-none`), not inline styles.

### Testing Requirements
No JS unit tests here. Run `node tools/ui-lint/run-ui-lint.mjs` (also scans for inline-style patterns) and exercise the page manually.

### Common Patterns
- IIFE wrapper, guard against double load, header with file path and copyright.

## Dependencies
### Internal
- `../css/`, `../../templates/`, backend API under `app/api/`.
### External
- Bootstrap JS, Chart.js (dashboard/traffic/DNS), Leaflet (maps) from `../vendor/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
