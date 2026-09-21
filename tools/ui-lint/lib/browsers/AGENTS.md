<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# browsers

## Purpose

Per-engine browser launcher adapters and the browser capability matrix (which of memory API, LCP, INP, visual viewport each engine supports).

## Key Files

| File | Description |
|---|---|
| `launcher.mjs` | `BrowserAdapters` (chromium/webkit/firefox) and `getBrowserLauncher` |
| `matrix.mjs` | `BROWSER_CONFIGS`, `getBrowserCapabilityProfile` |
| `capabilities.mjs` | `supportsMemoryAPI`, `supportsLCP`, `supportsINP`, `supportsVisualViewport` (WebKit/Safari treated as limited) |

## For AI Agents

### Working In This Directory

- `runtime/browser/launcher.mjs` duplicates `BrowserAdapters`; keep both in sync.

### Testing Requirements

- Covered by `tests/audit-helpers.spec.js`, `tests/orchestration/audit-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

### External

- `playwright`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
