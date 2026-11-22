<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# component

## Purpose

Specs for component rules.

## Key Files

| File | Description |
|---|---|
| `changelog-details.spec.js` | Accept valid `<details>`; flag missing details or summary |
| `dashboard-light-surfaces.spec.js` | Light KPI accepted, dark flagged in light theme, dark theme unconstrained |

## For AI Agents

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/component/`; requires installed Playwright browsers.

## Dependencies

### Internal

- `../../rules/component/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
