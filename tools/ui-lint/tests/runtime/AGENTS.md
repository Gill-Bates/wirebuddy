<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime

## Purpose

Specs for runtime modules: browser runtime, DOM runtime/snapshots, runtime config and view planning.

## Key Files

| File | Description |
|---|---|
| `browser-runtime.spec.js` | CLS helpers, console telemetry, stable screenshot diffs, `disableMotion` |
| `dom-runtime.spec.js` | Loads the app's `core/dom.js` and `settings/components.js` from `/opt/wirebuddy/app/static/js` (XSS-safe element helper, render batching, delegated events) |
| `dom-snapshot.spec.js` | Deterministic snapshot incl. shadow DOM |
| `runtime-config-orchestration.spec.js` | Profiles, runtime context, legacy helpers |
| `views-orchestration.spec.js` | Legacy matrices, plugin views, adaptive coverage |

## For AI Agents

### Working In This Directory

- `dom-runtime.spec.js` tests the application's own frontend scripts, so app JS renames break it.

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
