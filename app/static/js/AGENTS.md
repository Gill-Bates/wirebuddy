<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# js

## Purpose
First-party browser JavaScript, written as classic scripts. Most files are IIFEs that attach their API to `window` (`window.WBShared`, `window.WBReconnect`, `window.WB.*`); `api.js`, `modal.js`, `toast.js`, `theme.js`, `base-ui.js`, `peers.js`, `mfa.js` and `passkeys.js` declare top-level globals instead (`api`/`apiCall`, `wbAlert`/`wbConfirm`/`wbPrompt`, `wbToast`). `base.html` loads the shared runtime on every page in this order: `theme.js` (head), Bootstrap, `api.js`, `ui-state.js`, `core/dom.js`, `core/flags.js`, `core/format.js`, `modal.js`, `toast.js`, `reconnect.js`, `onboarding.js`, `base-ui.js`. Page controllers are added by each template's `extra_js` block. Pages on `auth_base.html` get none of this runtime and load what they need themselves (e.g. `api.js`, `ui-state.js`).

## Key Files
| File | Description |
|------|-------------|
| `api.js` | Fetch wrapper `api` (also `window.apiCall`): CSRF header, error normalisation, `{status: "ok", data}` envelope unwrapping, logout |
| `theme.js` | Three-state theme (auto default, light, dark) with safe localStorage (iOS private mode); `data-bs-theme` carries the resolved value, `data-wb-theme-mode` the chosen mode; auto follows OS changes live |
| `ui-state.js` | show/hide/state helpers exposed on window |
| `modal.js`, `toast.js` | Modal and toast helpers |
| `reconnect.js` | `WBReconnect`: server-restart/connection-loss overlay and polling |
| `onboarding.js` | Lazy-loads `templates/fragments/onboarding_modal.html` |
| `base-ui.js` | Global shell behaviour (sidebar, reconnect failsafe) |
| `dashboard_traffic_shared.js` | `WBShared` helpers shared by dashboard, traffic, DNS and settings |
| `dashboard.js`, `traffic.js`, `peers.js`, `users.js`, `nodes.js`, `about.js` | Page controllers |
| `dashboard_widgets.js` | Frozen dashboard widget registry (ids, labels, factory layout, order); browser global `WBDashboardRegistry` + Node `module.exports`. Mirrored by the Python allowlist in `app/api/dashboard_layout.py` (kept in sync by `tests/test_dashboard_widget_registry.py`) |
| `dashboard_grid.js` | GridStack layout layer for the dashboard: position/size/visibility and per-user layout persistence via `/api/dashboard/layout`. Owns no data (that stays in `dashboard.js`); loaded last on the dashboard |
| `dns-page.js` | DNS page controller, loaded by `dns.html` |
| `settings.js` | Monolithic Settings controller (`window.WBSettings`), loaded by `settings.html` together with `settings/components.js` and `settings/speedtest.js` |
| `login.js`, `mfa.js`, `passkeys.js`, `otp-setup.js`, `passkey-setup.js`, `change-password.js` | Auth flows: login, TOTP/MFA, WebAuthn passkeys, forced setup pages |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `core/` | Runtime infrastructure (DOM builder, flags, formatting); see `core/AGENTS.md` |
| `settings/` | Settings sub-modules; see `settings/AGENTS.md` |

## For AI Agents
### Working In This Directory
- No imports/exports: expose APIs on `window` and add a `<script>` tag in the right template. Order matters (dependencies first).
- Build DOM with `el()` from `core/dom.js` or `textContent`; escape any HTML string interpolation (XSS). Client-side checks are UX only; the backend enforces authorization.
- Call the backend through `api()` from `api.js` (`window.apiCall` is the same function); read chart colours through `WBShared.getChartColors()`.
- Toggle visibility with classes (`is-hidden`/`d-none`), not inline styles.

### Testing Requirements
See `../AGENTS.md`, which lists the pytest and ui-lint specs that load files from here; exercise the changed page in the browser.

### Common Patterns
- New files: IIFE wrapper with `'use strict'`, API attached to `window`.

## Dependencies
### Internal
- `../css/`, `../../templates/`, backend API under `app/api/`.
### External
- Bootstrap JS, Chart.js (dashboard/traffic/DNS), GridStack (dashboard), Leaflet (dashboard map, lazy-loaded by `dashboard.js`) from `../vendor/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
