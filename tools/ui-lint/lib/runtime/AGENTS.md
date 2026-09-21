<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime

## Purpose

Modular browser runtime behind `lib/browser-utils.mjs`: login and session bootstrap, browser/context creation, motion disabling, performance observers, stable screenshots, console/network telemetry, KPI capture and screenshot visual diffing.

## Key Files

| File | Description |
|---|---|
| (none) | No barrel: consumers import the leaf modules, mostly through `lib/browser-utils.mjs` |

## Subdirectories

| Directory | Purpose |
|---|---|
| `auth/` | Login flow and auth state (see `auth/AGENTS.md`) |
| `browser/` | Launcher, context, navigation, session (see `browser/AGENTS.md`) |
| `components/` | KPI capture/diffing (see `components/AGENTS.md`) |
| `motion/` | Motion suppression (see `motion/AGENTS.md`) |
| `observers/` | CLS/INP/LCP/mutation observers (see `observers/AGENTS.md`) |
| `runtime/` | Lifecycle and cleanup (see `runtime/AGENTS.md`) |
| `screenshots/` | Stable capture pipeline (see `screenshots/AGENTS.md`) |
| `telemetry/` | Console/network buffers (see `telemetry/AGENTS.md`) |
| `visual-diff/` | Pixel and SSIM diffing (see `visual-diff/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- Do not confuse `lib/runtime/` (browser runtime) with `lib/runtime-orchestration/` (profiles/context) or `lib/config/runtime/`.

### Testing Requirements

- Covered by `tests/runtime/browser-runtime.spec.js`, `tests/run-ui-lint.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Functions take a Playwright `page`/`context` and return plain data.

## Dependencies

### Internal

- `../browser-utils.mjs`, `../config/`

### External

- `playwright`, `pixelmatch`, `pngjs`, `ssim.js`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
