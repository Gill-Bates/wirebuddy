<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# view-orchestration

## Purpose

Defines which app views are audited and plans coverage: the catalog of views (and login-failure views), plugin discovery, adaptive coverage expansion and execution graph.

## Key Files

| File | Description |
|---|---|
| `catalog.mjs` | `VIEW_DEFS`, `LOGIN_FAILURE_VIEW_DEFS`, `VIEW_FAMILIES`, `VIEW_RUNTIME_VERSION` |
| `planner.mjs` | `validateViewDefinition`, `registerViewProvider`, `discoverViews`, `expandCoverage`, `adaptiveCoverageExpansion`, `createViewExecutionGraph`, `buildViewExecutionAnalytics` |
| `index.mjs` | Exports `VIEWS`, `LOGIN_FAILURE_VIEWS` |

## For AI Agents

### Working In This Directory

- Adding a route to test means adding a view definition in `catalog.mjs`; findings scopes in `../findings/scopes/` may need a matching predicate.

### Testing Requirements

- Covered by `tests/runtime/views-orchestration.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../views.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
