<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# tests

## Purpose

Playwright test specs for the linter itself (`npm test`). Most specs mount fixture HTML with `page.setContent` (helpers in `support/`) and run a rule or lib module against it, asserting both the passing and the violating case. Top-level specs cover audit helpers, health scoring and the entry point's path handling.

## Key Files

| File | Description |
|---|---|
| `audit-helpers.spec.js` | Console filtering/severity scoring and `BROWSER_CONFIGS` |
| `ux-health.spec.js` | Console enrichment and UI health scoring |
| `run-ui-lint.spec.js` | `buildRunPaths` safety and authenticated context options |

## Subdirectories

| Directory | Purpose |
|---|---|
| `accessibility/` | see `accessibility/AGENTS.md` |
| `component/` | see `component/AGENTS.md` |
| `config/` | see `config/AGENTS.md` |
| `entity-layout/` | see `entity-layout/AGENTS.md` |
| `findings/` | see `findings/AGENTS.md` |
| `layout/` | see `layout/AGENTS.md` |
| `mobile/` | see `mobile/AGENTS.md` |
| `orchestration/` | see `orchestration/AGENTS.md` |
| `overflow/` | see `overflow/AGENTS.md` |
| `rules/` | see `rules/AGENTS.md` |
| `runtime/` | see `runtime/AGENTS.md` |
| `support/` | Shared fixtures, see `support/AGENTS.md` |

## For AI Agents

### Working In This Directory

- Specs are `*.spec.js` ES modules importing `@playwright/test`; there is no `playwright.config`, so files are discovered by default patterns.
- Add a spec next to the area it covers; mirror the rule/lib directory name.

### Testing Requirements

- `cd tools/ui-lint && npm test` (all) or `npx playwright test tests/<dir>/<file>.spec.js`. Browsers must be installed (`npm run install:browsers`).

### Common Patterns

- Import rules via default export (`import rule from '../../rules/<cat>/<id>.mjs'`) and run with `runRule`.
- Use `mountContractPage` from `support/contract-fixtures.mjs` for app-like pages.

## Dependencies

### Internal

- `../lib/`, `../rules/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
