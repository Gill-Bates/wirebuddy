<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# view-orchestration

## Purpose

Defines which app views are audited and plans coverage: the catalog of views (and login-failure views), plugin discovery, adaptive coverage expansion and execution graph.

## Key Files

| File | Description |
|---|---|
| `catalog.mjs` | `VIEW_DEFS`, `LOGIN_FAILURE_VIEW_DEFS`, `VIEW_FAMILIES`, `VIEW_RUNTIME_VERSION` (~370 lines) |
| `planner.mjs` | `validateViewDefinition`, `registerViewProvider`, `discoverViews`, `expandCoverage`, `adaptiveCoverageExpansion`, `createViewExecutionGraph`, `buildViewExecutionAnalytics` (~450 lines) |
| `index.mjs` | Exports `VIEWS`, `LOGIN_FAILURE_VIEWS` |

## For AI Agents

### Working In This Directory

- Adding a route to test means adding a view definition in `catalog.mjs`; findings scopes in `../findings/scopes/` may need a matching predicate.

### Testing Requirements

- Covered by `tests/runtime/views-orchestration.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../views.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
