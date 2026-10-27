<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-10-27 -->
# runtime

## Purpose

Specs for runtime modules: browser runtime, DOM runtime/snapshots, runtime config and view planning, plus contract specs that load the app's own dashboard and modal scripts.

## Key Files

| File | Description |
|---|---|
| `browser-runtime.spec.js` | CLS helpers, console telemetry, stable screenshot diffs, `disableMotion` |
| `dom-runtime.spec.js` | Loads the app's `core/dom.js` and `settings/components.js` from `/opt/wirebuddy/app/static/js` (`el`, `clearChildren`, `fragment`, delegated click handlers, settings component helpers) |
| `dom-snapshot.spec.js` | Deterministic snapshot incl. shadow DOM |
| `runtime-config-orchestration.spec.js` | Profiles, runtime context, legacy helpers |
| `views-orchestration.spec.js` | Legacy matrices, plugin views, adaptive coverage |
| `dashboard-grid.spec.js` | Dashboard GridStack contract: loads vendored `gridstack-all.js`, `dashboard_widgets.js` and `dashboard_grid.js` against fixture markup; a hero KPI resizes to half width and survives saving while the mobile layout stays stacked |
| `modal-keyboard.spec.js` | Modal keyboard contract: loads Bootstrap, `base-ui.js` and `modal.js` with the real `settings/_modals.html`; Enter/Escape, focus return and top-most-dialog-only close |

## For AI Agents

### Working In This Directory

- `dom-runtime.spec.js`, `dashboard-grid.spec.js` and `modal-keyboard.spec.js` load the application's own frontend scripts and templates, so app JS/template renames break them.

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/runtime/`; requires installed Playwright browsers.

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../../lib/`, `/opt/wirebuddy/app/static/js`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
